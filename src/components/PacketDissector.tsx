import React from 'react';
import type { RealPacket } from '../types/sniffer';

interface PacketDissectorProps {
  packet: RealPacket | null;
}

export function PacketDissector({ packet }: PacketDissectorProps) {
  return (
    <section className="xl:col-span-5 bg-white border border-slate-200 rounded-xl p-5 space-y-4">
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

          {/* Layer 2: Ethernet */}
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

          {/* Layer 3 & 4: IP + Transport */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Layer 3/4 · Network & Transport Headers
            </h3>
            <dl className="grid grid-cols-2 gap-2 text-xs bg-slate-50 border border-slate-200 rounded-lg p-3">
              <div>
                <dt className="text-slate-500">Source Endpoint</dt>
                <dd className="font-mono font-semibold text-slate-900 mt-0.5 break-all">
                  {packet.srcIp}
                  {packet.srcPort > 0 ? `:${packet.srcPort}` : ''}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Destination Endpoint</dt>
                <dd className="font-mono font-semibold text-slate-900 mt-0.5 break-all">
                  {packet.dstIp}
                  {packet.dstPort > 0 ? `:${packet.dstPort}` : ''}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Protocol / TTL</dt>
                <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                  {packet.protocol} · TTL={packet.ttl}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Flags</dt>
                <dd className="font-mono text-slate-900 mt-0.5">
                  {packet.flags.length > 0 ? packet.flags.join(', ') : 'None'}
                </dd>
              </div>
              {typeof packet.seq === 'number' && (
                <>
                  <div>
                    <dt className="text-slate-500">TCP Seq / Ack</dt>
                    <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                      {packet.seq} / {packet.ack ?? 0}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">TCP Window</dt>
                    <dd className="font-mono tabular-nums text-slate-900 mt-0.5">
                      {packet.window ?? 0}
                    </dd>
                  </div>
                </>
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
              Raw Byte Hex & ASCII Dump
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
            Click any captured frame row to dissect its Ethernet, IPv4, TCP/UDP/ICMP, and hex payload layers.
          </p>
        </div>
      )}
    </section>
  );
}
