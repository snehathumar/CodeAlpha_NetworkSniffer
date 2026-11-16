import React from 'react';
import type { RealPacket } from '../types/sniffer';

interface PacketDissectorProps {
  packet: RealPacket | null;
}

export function PacketDissector({ packet }: PacketDissectorProps) {
  return (
    <section
      aria-label="Packet Detail Dissector"
      className="xl:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4"
    >
      {packet ? (
        <>
          <div className="pb-3 border-b border-slate-200">
            <p className="font-mono text-xs text-slate-500 tabular-nums">
              Frame #{packet.number} · {packet.timestamp} · {packet.length} bytes
            </p>
            <h2 className="mt-1 text-sm font-bold text-slate-900 break-words">
              {packet.summary}
            </h2>
          </div>

          {/* Layer 2: Data Link (Ethernet II) */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Layer 2 · Ethernet II Frame
            </h3>
            <dl className="grid grid-cols-2 gap-2 text-xs bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div>
                <dt className="text-slate-500">Source MAC</dt>
                <dd className="font-mono text-slate-900 mt-0.5">{packet.srcMac}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Destination MAC</dt>
                <dd className="font-mono text-slate-900 mt-0.5">{packet.dstMac}</dd>
              </div>
              <div>
                <dt className="text-slate-500">EtherType</dt>
                <dd className="font-mono text-slate-900 mt-0.5">{packet.etherType}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Frame Length</dt>
                <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                  {packet.length} bytes
                </dd>
              </div>
            </dl>
          </div>

          {/* Layer 3: Network Layer (IP / ARP) */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Layer 3 · Network Header
            </h3>
            <dl className="grid grid-cols-2 gap-2 text-xs bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div>
                <dt className="text-slate-500">Source IP</dt>
                <dd className="font-mono font-semibold text-slate-900 mt-0.5 break-all">
                  {packet.srcIp}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Destination IP</dt>
                <dd className="font-mono font-semibold text-slate-900 mt-0.5 break-all">
                  {packet.dstIp}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">TTL / Hop Limit</dt>
                <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                  {packet.ttl}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">IP Header / ID</dt>
                <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                  {packet.ipHeaderLen ? `${packet.ipHeaderLen}B` : '—'}
                  {typeof packet.ipId === 'number' ? ` · id=${packet.ipId}` : ''}
                </dd>
              </div>
            </dl>
          </div>

          {/* Layer 4: Transport & Protocol */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Layer 4 · Transport &amp; Protocol
            </h3>
            <dl className="grid grid-cols-2 gap-2 text-xs bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div>
                <dt className="text-slate-500">Protocol</dt>
                <dd className="font-mono font-semibold text-blue-700 mt-0.5">
                  {packet.protocol}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Ports (Src → Dst)</dt>
                <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                  {packet.srcPort > 0 || packet.dstPort > 0
                    ? `${packet.srcPort} → ${packet.dstPort}`
                    : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Flags / Type</dt>
                <dd className="font-mono text-slate-900 mt-0.5">
                  {packet.flags.length > 0 ? packet.flags.join(', ') : 'None'}
                </dd>
              </div>
              {typeof packet.seq === 'number' ? (
                <div>
                  <dt className="text-slate-500">TCP Window</dt>
                  <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                    {packet.window ?? 0}
                  </dd>
                </div>
              ) : (
                <div>
                  <dt className="text-slate-500">Payload Status</dt>
                  <dd className="font-mono text-slate-900 mt-0.5">
                    {packet.payloadAscii ? 'Present' : 'Header only'}
                  </dd>
                </div>
              )}
              {typeof packet.seq === 'number' && (
                <div className="col-span-2">
                  <dt className="text-slate-500">TCP Sequence / Acknowledgement</dt>
                  <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                    seq={packet.seq} · ack={packet.ack ?? 0}
                  </dd>
                </div>
              )}
            </dl>
          </div>

          {/* Payload ASCII */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Decoded Payload ASCII
            </h3>
            <pre className="mt-1.5 rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-800 whitespace-pre-wrap break-all max-h-36 overflow-y-auto">
              {packet.payloadAscii || '(No printable application payload in this frame)'}
            </pre>
          </div>

          {/* Hex Dump */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Raw Byte Hex &amp; ASCII Dump
            </h3>
            <pre className="mt-1.5 rounded-lg bg-slate-900 text-slate-100 p-3 font-mono text-[11px] overflow-x-auto leading-relaxed max-h-52 overflow-y-auto">
              {packet.hexDump}
            </pre>
          </div>
        </>
      ) : (
        <div className="py-12 text-center space-y-1.5">
          <p className="text-sm font-semibold text-slate-900">
            No Packet Selected
          </p>
          <p className="text-xs text-slate-500">
            Click any captured frame row to dissect Layer 2 (Ethernet), Layer 3 (IP), Layer 4 (TCP/UDP/ICMP), and Hex + ASCII payload.
          </p>
        </div>
      )}
    </section>
  );
}
