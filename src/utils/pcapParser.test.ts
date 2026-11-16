import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPcapBuffer,
  dissectEthernetBytes,
  formatHexDump,
  parsePcapBuffer,
  summarizePackets,
} from './pcapParser';

function createSampleEthernetTcpHttpFrame(): Uint8Array {
  const payload = new TextEncoder().encode('GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n');
  const totalLen = 14 + 20 + 20 + payload.length;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);

  // Ethernet header: dst, src, 0x0800 (IPv4)
  buf.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
  buf.set([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb], 6);
  view.setUint16(12, 0x0800, false);

  // IPv4 header
  buf[14] = 0x45; // v4, ihl=5
  view.setUint16(16, 20 + 20 + payload.length, false);
  buf[22] = 64; // TTL
  buf[23] = 6; // TCP
  buf.set([127, 0, 0, 1], 26); // src
  buf.set([127, 0, 0, 1], 30); // dst

  // TCP header
  view.setUint16(34, 54321, false); // src port
  view.setUint16(36, 3000, false); // dst port
  view.setUint32(38, 1001, false); // seq
  view.setUint32(42, 0, false); // ack
  buf[46] = 0x50; // data offset = 5 (20 bytes)
  buf[47] = 0x18; // PSH, ACK
  view.setUint16(48, 65535, false);

  buf.set(payload, 54);
  return buf;
}

test('dissectEthernetBytes extracts real MAC, IPv4, TCP flags, and HTTP payload', () => {
  const frame = createSampleEthernetTcpHttpFrame();
  const pkt = dissectEthernetBytes(frame, 1, Date.UTC(2026, 10, 13, 12, 0, 0));

  assert.equal(pkt.protocol, 'HTTP');
  assert.equal(pkt.srcIp, '127.0.0.1');
  assert.equal(pkt.dstIp, '127.0.0.1');
  assert.equal(pkt.srcPort, 54321);
  assert.equal(pkt.dstPort, 3000);
  assert.equal(pkt.ttl, 64);
  assert.deepEqual(pkt.flags, ['PSH', 'ACK']);
  assert.match(pkt.payloadAscii, /^GET \/index\.html HTTP\/1\.1/);
});

test('buildPcapBuffer and parsePcapBuffer round-trip standard libpcap binary format', () => {
  const frame = createSampleEthernetTcpHttpFrame();
  const original = dissectEthernetBytes(frame, 1, Date.UTC(2026, 10, 13, 12, 0, 0));
  const pcapBytes = buildPcapBuffer([original]);

  // Verify libpcap global magic bytes (little-endian 0xa1b2c3d4)
  const magic = new DataView(pcapBytes.buffer).getUint32(0, true);
  assert.equal(magic, 0xa1b2c3d4);

  const decoded = parsePcapBuffer(pcapBytes);
  assert.equal(decoded.length, 1);
  assert.equal(decoded[0].protocol, 'HTTP');
  assert.equal(decoded[0].srcPort, 54321);
  assert.equal(decoded[0].dstPort, 3000);
  assert.equal(decoded[0].rawHex, original.rawHex);
});

test('parsePcapBuffer rejects invalid magic headers cleanly', () => {
  assert.throws(
    () => parsePcapBuffer(new Uint8Array(32)),
    /Unsupported file signature/
  );
});

test('buildPcapBuffer writes standard Wireshark libpcap global header fields', () => {
  const frame = createSampleEthernetTcpHttpFrame();
  const original = dissectEthernetBytes(frame, 1, Date.UTC(2026, 10, 13, 12, 0, 0));
  const pcapBytes = buildPcapBuffer([original]);
  const view = new DataView(pcapBytes.buffer);

  assert.equal(view.getUint32(0, true), 0xa1b2c3d4);
  assert.equal(view.getUint16(4, true), 2);
  assert.equal(view.getUint16(6, true), 4);
  assert.equal(view.getUint32(16, true), 65535);
  assert.equal(view.getUint32(20, true), 1);
  assert.equal(pcapBytes.length, 24 + 16 + frame.length);
});

test('summarizePackets and formatHexDump compute counts and top source/destination IPs', () => {
  const frame = createSampleEthernetTcpHttpFrame();
  const pkt1 = dissectEthernetBytes(frame, 1);
  const pkt2 = {
    ...pkt1,
    number: 2,
    protocol: 'TCP',
    srcIp: '10.0.0.5',
    dstIp: '10.0.0.2',
  };
  const pkt3 = {
    ...pkt1,
    number: 3,
    protocol: 'UDP',
    srcIp: '10.0.0.5',
    dstIp: '127.0.0.1',
  };

  const stats = summarizePackets([pkt1, pkt2, pkt3]);
  assert.equal(stats.totalPackets, 3);
  assert.equal(stats.totalBytes, frame.length * 3);
  assert.equal(stats.counts.HTTP, 1);
  assert.equal(stats.counts.TCP, 1);
  assert.equal(stats.counts.UDP, 1);
  assert.deepEqual(stats.topSrcIps[0], { ip: '10.0.0.5', count: 2 });
  assert.deepEqual(stats.topDstIps[0], { ip: '127.0.0.1', count: 2 });

  const hex = formatHexDump(new Uint8Array([0x47, 0x45, 0x54]));
  assert.match(hex, /^0000\s+47 45 54/);
  assert.match(hex, /\|GET\|/);
});
