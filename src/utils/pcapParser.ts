import type { IpRankEntry, PacketSummaryStats, RealPacket } from '../types/sniffer';

export function formatHexDump(bytes: Uint8Array, maxBytes = 512): string {
  const slice = bytes.slice(0, maxBytes);
  if (slice.length === 0) return '0000  (empty payload)';

  const lines: string[] = [];
  for (let offset = 0; offset < slice.length; offset += 16) {
    const chunk = slice.slice(offset, offset + 16);
    const hexPart = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ')
      .padEnd(47, ' ');
    const asciiPart = Array.from(chunk)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${offset.toString(16).padStart(4, '0')}  ${hexPart}  |${asciiPart}|`);
  }
  if (bytes.length > maxBytes) {
    lines.push(`... (${bytes.length - maxBytes} more bytes truncated)`);
  }
  return lines.join('\n');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatMac(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':');
}

function formatIpv4(bytes: Uint8Array): string {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

function decodeTcpFlags(flagByte: number): string[] {
  const table: Array<[number, string]> = [
    [0x01, 'FIN'],
    [0x02, 'SYN'],
    [0x04, 'RST'],
    [0x08, 'PSH'],
    [0x10, 'ACK'],
    [0x20, 'URG'],
  ];
  return table.filter(([mask]) => (flagByte & mask) !== 0).map(([, name]) => name);
}

function toAsciiPreview(bytes: Uint8Array, limit = 512): string {
  let out = '';
  const len = Math.min(bytes.length, limit);
  for (let i = 0; i < len; i += 1) {
    const b = bytes[i];
    out += (b >= 32 && b <= 126) || b === 10 || b === 13 ? String.fromCharCode(b) : '.';
  }
  return out;
}

export function dissectEthernetBytes(
  rawFrame: Uint8Array,
  packetNum: number,
  tsMs?: number
): RealPacket {
  const dateObj = tsMs ? new Date(tsMs) : new Date();
  const timestamp = dateObj.toISOString().slice(11, 23);
  const isoTimestamp = dateObj.toISOString();

  if (rawFrame.length < 14) {
    return {
      number: packetNum,
      timestamp,
      isoTimestamp,
      length: rawFrame.length,
      protocol: 'OTHER',
      srcMac: '00:00:00:00:00:00',
      dstMac: '00:00:00:00:00:00',
      etherType: '0x0000',
      srcIp: '-',
      dstIp: '-',
      srcPort: 0,
      dstPort: 0,
      ttl: 0,
      flags: [],
      summary: `Truncated frame (${rawFrame.length} bytes)`,
      payloadAscii: '',
      hexDump: formatHexDump(rawFrame),
      rawHex: bytesToHex(rawFrame),
    };
  }

  const dstMac = formatMac(rawFrame.slice(0, 6));
  const srcMac = formatMac(rawFrame.slice(6, 12));
  const ethType = (rawFrame[12] << 8) | rawFrame[13];
  const ethTypeHex = `0x${ethType.toString(16).padStart(4, '0')}`;
  const ethPayload = rawFrame.slice(14);

  const base: RealPacket = {
    number: packetNum,
    timestamp,
    isoTimestamp,
    length: rawFrame.length,
    protocol: 'OTHER',
    srcMac,
    dstMac,
    etherType: ethTypeHex,
    srcIp: '-',
    dstIp: '-',
    srcPort: 0,
    dstPort: 0,
    ttl: 0,
    flags: [],
    summary: `Ethernet frame EtherType ${ethTypeHex}`,
    payloadAscii: '',
    hexDump: formatHexDump(rawFrame),
    rawHex: bytesToHex(rawFrame),
  };

  if (ethType === 0x0806 && ethPayload.length >= 28) {
    const oper = (ethPayload[6] << 8) | ethPayload[7];
    const spa = formatIpv4(ethPayload.slice(14, 18));
    const tpa = formatIpv4(ethPayload.slice(24, 28));
    return {
      ...base,
      protocol: 'ARP',
      srcIp: spa,
      dstIp: tpa,
      summary: `ARP ${oper === 1 ? 'Request' : oper === 2 ? 'Reply' : `Op=${oper}`}: ${spa} -> ${tpa}`,
    };
  }

  if (ethType === 0x0800 && ethPayload.length >= 20) {
    const view = new DataView(ethPayload.buffer, ethPayload.byteOffset, ethPayload.byteLength);
    const ihl = (ethPayload[0] & 0x0f) * 4;
    const ttl = ethPayload[8];
    const ipProto = ethPayload[9];
    const srcIp = formatIpv4(ethPayload.slice(12, 16));
    const dstIp = formatIpv4(ethPayload.slice(16, 20));
    const ipPayload = ethPayload.slice(ihl);

    if (ipProto === 6 && ipPayload.length >= 20) {
      const tcpView = new DataView(ipPayload.buffer, ipPayload.byteOffset, ipPayload.byteLength);
      const srcPort = tcpView.getUint16(0, false);
      const dstPort = tcpView.getUint16(2, false);
      const seq = tcpView.getUint32(4, false);
      const ack = tcpView.getUint32(8, false);
      const hdrLen = ((ipPayload[12] >> 4) & 0x0f) * 4;
      const flags = decodeTcpFlags(ipPayload[13]);
      const window = tcpView.getUint16(14, false);
      const appPayload = ipPayload.slice(hdrLen);
      const ascii = toAsciiPreview(appPayload);
      const isHttp =
        [80, 8080, 3000].includes(srcPort) || [80, 8080, 3000].includes(dstPort)
          ? /^(GET |POST |PUT |DELETE |HEAD |HTTP\/)/.test(ascii)
          : false;
      const proto = isHttp ? 'HTTP' : srcPort === 53 || dstPort === 53 ? 'DNS' : 'TCP';

      return {
        ...base,
        protocol: proto,
        srcIp,
        dstIp,
        srcPort,
        dstPort,
        ttl,
        ipHeaderLen: ihl,
        ipId: view.getUint16(4, false),
        flags,
        seq,
        ack,
        window,
        summary: `${proto} :${srcPort} -> :${dstPort} [${flags.join(',') || 'NONE'}] seq=${seq}`,
        payloadAscii: ascii,
        hexDump: formatHexDump(appPayload.length > 0 ? appPayload : rawFrame),
      };
    }

    if (ipProto === 17 && ipPayload.length >= 8) {
      const udpView = new DataView(ipPayload.buffer, ipPayload.byteOffset, ipPayload.byteLength);
      const srcPort = udpView.getUint16(0, false);
      const dstPort = udpView.getUint16(2, false);
      const appPayload = ipPayload.slice(8);
      const proto = srcPort === 53 || dstPort === 53 ? 'DNS' : 'UDP';
      return {
        ...base,
        protocol: proto,
        srcIp,
        dstIp,
        srcPort,
        dstPort,
        ttl,
        ipHeaderLen: ihl,
        summary: `${proto} :${srcPort} -> :${dstPort} len=${appPayload.length}B`,
        payloadAscii: toAsciiPreview(appPayload),
        hexDump: formatHexDump(appPayload.length > 0 ? appPayload : rawFrame),
      };
    }

    if (ipProto === 1 && ipPayload.length >= 4) {
      const icmpType = ipPayload[0];
      const icmpCode = ipPayload[1];
      const icmpData = ipPayload.slice(4);
      const typeLabel =
        icmpType === 0 ? 'Echo Reply' : icmpType === 8 ? 'Echo Request' : `Type ${icmpType}`;
      return {
        ...base,
        protocol: 'ICMP',
        srcIp,
        dstIp,
        ttl,
        ipHeaderLen: ihl,
        flags: [typeLabel],
        summary: `ICMP ${typeLabel} (code=${icmpCode}) ${srcIp} -> ${dstIp}`,
        payloadAscii: toAsciiPreview(icmpData),
        hexDump: formatHexDump(icmpData.length > 0 ? icmpData : rawFrame),
      };
    }

    return {
      ...base,
      protocol: `IP(${ipProto})`,
      srcIp,
      dstIp,
      ttl,
      ipHeaderLen: ihl,
      summary: `IPv4 proto=${ipProto} ${srcIp} -> ${dstIp}`,
    };
  }

  return base;
}

/**
 * Encodes a list of RealPackets (using their rawHex Ethernet frames) into a
 * standard Wireshark-compatible libpcap (.pcap) binary buffer.
 */
export function buildPcapBuffer(packets: RealPacket[]): Uint8Array {
  const frames = packets.map((p) => {
    const raw = hexToBytes(p.rawHex);
    const ms = Date.parse(p.isoTimestamp) || Date.now();
    return { raw, ms };
  });

  const totalSize =
    24 + frames.reduce((sum, f) => sum + 16 + f.raw.length, 0);
  const out = new Uint8Array(totalSize);
  const view = new DataView(out.buffer);

  // Global Header (Little Endian 0xa1b2c3d4)
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true); // major
  view.setUint16(6, 4, true); // minor
  view.setInt32(8, 0, true); // thiszone
  view.setUint32(12, 0, true); // sigfigs
  view.setUint32(16, 65535, true); // snaplen
  view.setUint32(20, 1, true); // linktype: Ethernet

  let offset = 24;
  for (const frame of frames) {
    const sec = Math.floor(frame.ms / 1000);
    const usec = (frame.ms % 1000) * 1000;
    view.setUint32(offset, sec, true);
    view.setUint32(offset + 4, usec, true);
    view.setUint32(offset + 8, frame.raw.length, true);
    view.setUint32(offset + 12, frame.raw.length, true);
    out.set(frame.raw, offset + 16);
    offset += 16 + frame.raw.length;
  }

  return out;
}

/**
 * Parses a standard libpcap (.pcap) binary file into RealPacket records.
 * Supports both little-endian (0xa1b2c3d4) and big-endian (0xd4c3b2a1) headers.
 */
export function parsePcapBuffer(buffer: Uint8Array): RealPacket[] {
  if (buffer.length < 24) {
    throw new Error('File is smaller than 24-byte libpcap global header.');
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const magicLE = view.getUint32(0, true);
  let littleEndian = true;

  if (magicLE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d) {
    littleEndian = true;
  } else if (magicLE === 0xd4c3b2a1 || magicLE === 0x4d3cb2a1) {
    littleEndian = false;
  } else {
    throw new Error(
      'Unsupported file signature. Expected standard libpcap (.pcap) format (not pcapng).'
    );
  }

  const linkType = view.getUint32(20, littleEndian);
  if (linkType !== 1) {
    throw new Error(
      `Unsupported link layer type (${linkType}). Expected Ethernet (LINKTYPE_ETHERNET = 1).`
    );
  }

  const packets: RealPacket[] = [];
  let offset = 24;
  let num = 0;

  while (offset + 16 <= buffer.length && packets.length < 1000) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsUsec = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    offset += 16;

    if (inclLen === 0 || offset + inclLen > buffer.length) {
      break;
    }

    num += 1;
    const rawFrame = buffer.slice(offset, offset + inclLen);
    const tsMs = tsSec * 1000 + Math.floor(tsUsec / 1000);
    packets.push(dissectEthernetBytes(rawFrame, num, tsMs));
    offset += inclLen;
  }

  return packets;
}

function rankTopIps(freqMap: Map<string, number>, limit = 3): IpRankEntry[] {
  return Array.from(freqMap.entries())
    .sort((a, b) => (b[1] !== a[1] ? b[1] - a[1] : a[0].localeCompare(b[0])))
    .slice(0, limit)
    .map(([ip, count]) => ({ ip, count }));
}

export function summarizePackets(packets: RealPacket[]): PacketSummaryStats {
  const counts: Record<string, number> = {
    TCP: 0,
    UDP: 0,
    HTTP: 0,
    DNS: 0,
    ICMP: 0,
    ARP: 0,
    OTHER: 0,
  };
  let totalBytes = 0;
  const srcCounts = new Map<string, number>();
  const dstCounts = new Map<string, number>();

  for (const pkt of packets) {
    totalBytes += pkt.length;
    if (pkt.protocol in counts) {
      counts[pkt.protocol] += 1;
    } else {
      counts.OTHER += 1;
    }
    if (pkt.srcIp && pkt.srcIp !== '-') {
      srcCounts.set(pkt.srcIp, (srcCounts.get(pkt.srcIp) ?? 0) + 1);
    }
    if (pkt.dstIp && pkt.dstIp !== '-') {
      dstCounts.set(pkt.dstIp, (dstCounts.get(pkt.dstIp) ?? 0) + 1);
    }
  }

  return {
    totalPackets: packets.length,
    totalBytes,
    counts,
    topSrcIps: rankTopIps(srcCounts),
    topDstIps: rankTopIps(dstCounts),
  };
}
