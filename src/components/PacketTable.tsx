import React, { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import type { ProtocolFilter, RealPacket } from '../types/sniffer';

interface PacketTableProps {
  packets: RealPacket[];
  selectedNumber: number | null;
  onSelectPacket: (pktNumber: number) => void;
}

const FILTER_OPTIONS: ProtocolFilter[] = [
  'ALL',
  'TCP',
  'UDP',
  'HTTP',
  'DNS',
  'ICMP',
  'ARP',
];

export function PacketTable({
  packets,
  selectedNumber,
  onSelectPacket,
}: PacketTableProps) {
  const [protoFilter, setProtoFilter] = useState<ProtocolFilter>('ALL');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return packets.filter((p) => {
      if (protoFilter !== 'ALL' && p.protocol !== protoFilter) return false;
      if (!q) return true;
      return (
        p.srcIp.toLowerCase().includes(q) ||
        p.dstIp.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.summary.toLowerCase().includes(q) ||
        String(p.dstPort).includes(q) ||
        String(p.srcPort).includes(q)
      );
    });
  }, [packets, protoFilter, search]);

  return (
    <section className="xl:col-span-7 bg-white border border-slate-200 rounded-xl overflow-hidden flex flex-col">
      <div className="px-4 py-3 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div
          role="tablist"
          aria-label="Filter captured packets by protocol"
          className="inline-flex flex-wrap items-center gap-1 p-1 bg-slate-100 rounded-lg self-start"
        >
          {FILTER_OPTIONS.map((proto) => (
            <button
              key={proto}
              type="button"
              role="tab"
              aria-selected={protoFilter === proto}
              onClick={() => setProtoFilter(proto)}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                protoFilter === proto
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {proto}
            </button>
          ))}
        </div>

        <div className="relative min-w-[200px]">
          <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <label htmlFor="packet-search" className="sr-only">
            Filter packets by IP, port, or payload
          </label>
          <input
            id="packet-search"
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter IP, port, summary..."
            className="w-full rounded-lg border border-slate-300 bg-white pl-8 pr-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-700 focus:outline-none"
          />
        </div>
      </div>

      {filtered.length === 0 ? (
        <div className="p-10 text-center space-y-1.5">
          <p className="text-sm font-semibold text-slate-900">
            {packets.length === 0
              ? 'No Packets Captured Yet'
              : 'No Packets Match Filter'}
          </p>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            {packets.length === 0
              ? 'Click Start Live Capture to bind the Linux AF_PACKET raw socket, or Upload .pcap to inspect an existing Wireshark capture.'
              : 'Clear the search box or switch the protocol filter back to ALL.'}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto max-h-[540px] overflow-y-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold">
              <tr>
                <th className="py-2.5 px-3">No.</th>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3 text-right">Len</th>
                <th className="py-2.5 px-3">Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 font-mono tabular-nums">
              {filtered.map((pkt) => {
                const isSelected = selectedNumber === pkt.number;
                return (
                  <tr
                    key={`${pkt.number}-${pkt.isoTimestamp}`}
                    onClick={() => onSelectPacket(pkt.number)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-blue-50 text-slate-900'
                        : 'hover:bg-slate-50 text-slate-700'
                    }`}
                  >
                    <td className="py-2 px-3 font-semibold">{pkt.number}</td>
                    <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                      {pkt.timestamp}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      {pkt.srcIp}
                      {pkt.srcPort > 0 ? `:${pkt.srcPort}` : ''}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      {pkt.dstIp}
                      {pkt.dstPort > 0 ? `:${pkt.dstPort}` : ''}
                    </td>
                    <td className="py-2 px-3 font-semibold text-blue-700 whitespace-nowrap">
                      {pkt.protocol}
                    </td>
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      {pkt.length}
                    </td>
                    <td className="py-2 px-3 font-sans text-slate-600 max-w-[240px] truncate">
                      {pkt.summary}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
