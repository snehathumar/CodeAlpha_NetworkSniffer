/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertCircle,
  Code2,
  Download,
  Globe,
  Info,
  Network,
  Play,
  Radio,
  Server,
  Square,
  Trash2,
  Upload,
  Wifi,
} from 'lucide-react';
import { PacketTable } from './components/PacketTable';
import { PacketDissector } from './components/PacketDissector';
import { PythonSourceView } from './components/PythonSourceView';
import type {
  NetworkInterfaceInfo,
  ProtocolFilter,
  RealPacket,
  SnifferStatusResponse,
  TrafficKind,
} from './types/sniffer';
import { summarizePackets } from './utils/pcapParser';

const TRAFFIC_ACTIONS: Array<{
  type: TrafficKind;
  label: string;
  target: string;
  Icon: React.ComponentType<{ className?: string }>;
}> = [
  { type: 'tcp', label: 'TCP Connect', target: '127.0.0.1:3000', Icon: Network },
  { type: 'http', label: 'HTTP GET', target: '/api/health', Icon: Globe },
  { type: 'udp', label: 'UDP Datagram', target: '127.0.0.1:9999', Icon: Radio },
  { type: 'icmp', label: 'ICMP Ping', target: '127.0.0.1', Icon: Wifi },
  { type: 'dns', label: 'DNS Lookup', target: 'A record / resolver', Icon: Server },
];

export default function App() {
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([
    { name: 'all', addresses: ['All Linux Interfaces'] },
  ]);
  const [selectedIface, setSelectedIface] = useState('all');
  const [captureProto, setCaptureProto] = useState<ProtocolFilter>('ALL');

  const [capturing, setCapturing] = useState(false);
  const [packets, setPackets] = useState<RealPacket[]>([]);
  const [selectedNumber, setSelectedNumber] = useState<number | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);
  const [busyTraffic, setBusyTraffic] = useState<TrafficKind | null>(null);

  const [showPython, setShowPython] = useState(false);
  const [pythonSource, setPythonSource] = useState('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/sniffer/status');
      if (!res.ok) return;
      const data = (await res.json()) as SnifferStatusResponse;
      setCapturing(data.capturing);
      setPackets(data.packets);
      if (data.error) setErrorBanner(data.error);
      setSelectedNumber((prev) =>
        prev ?? (data.packets.length > 0 ? data.packets[data.packets.length - 1].number : null)
      );
    } catch {
      // Ignore transient poll errors
    }
  }, []);

  useEffect(() => {
    fetch('/api/sniffer/interfaces')
      .then((r) => (r.ok ? r.json() : null))
      .then((data: { interfaces?: NetworkInterfaceInfo[] } | null) => {
        if (data?.interfaces && data.interfaces.length > 0) {
          setInterfaces(data.interfaces);
        }
      })
      .catch(() => {});

    fetch('/api/sniffer/source')
      .then((r) => (r.ok ? r.json() : null))
      .then((data: { code?: string } | null) => {
        if (data?.code) setPythonSource(data.code);
      })
      .catch(() => {});

    void fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    if (!capturing) return;
    const timer = window.setInterval(() => {
      void fetchStatus();
    }, 900);
    return () => window.clearInterval(timer);
  }, [capturing, fetchStatus]);

  const handleStartCapture = async () => {
    setErrorBanner(null);
    setStatusNotice(null);
    try {
      const res = await fetch('/api/sniffer/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          iface: selectedIface,
          proto: captureProto,
          count: 0,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Raw packet capture needs root on Linux');
      }
      const status = data as SnifferStatusResponse;
      setCapturing(status.capturing);
      setPackets(status.packets);
      if (status.error) {
        setErrorBanner(status.error);
      } else {
        setStatusNotice(`Live AF_PACKET socket bound on interface '${selectedIface}'.`);
      }
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Raw packet capture needs root on Linux');
    }
  };

  const handleStopCapture = async () => {
    setErrorBanner(null);
    try {
      const res = await fetch('/api/sniffer/stop', { method: 'POST' });
      const data = (await res.json()) as SnifferStatusResponse;
      setCapturing(data.capturing);
      setPackets(data.packets);
      setStatusNotice('Live capture stopped.');
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Failed to stop capture.');
    }
  };

  const handleClear = async () => {
    setErrorBanner(null);
    setStatusNotice(null);
    try {
      const res = await fetch('/api/sniffer/clear', { method: 'POST' });
      const data = (await res.json()) as SnifferStatusResponse;
      setPackets(data.packets);
      setSelectedNumber(null);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Failed to clear buffer.');
    }
  };

  const handleGenerateTraffic = async (type: TrafficKind) => {
    setErrorBanner(null);
    setBusyTraffic(type);
    try {
      const res = await fetch('/api/sniffer/traffic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type }),
      });
      const data = (await res.json()) as {
        ok?: boolean;
        skipped?: boolean;
        message?: string;
        error?: string;
      };
      if (!res.ok) {
        throw new Error(data.error || 'Failed to generate local traffic.');
      }
      setStatusNotice(data.message ?? 'Traffic action completed.');
      if (!data.skipped) {
        setTimeout(() => void fetchStatus(), 350);
      }
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Traffic generation failed.');
    } finally {
      setBusyTraffic(null);
    }
  };

  const handleExportPcap = () => {
    setErrorBanner(null);
    if (packets.length === 0) {
      setErrorBanner('Capture at least 1 packet before exporting to .pcap.');
      return;
    }
    window.location.href = '/api/sniffer/export.pcap';
  };

  const handleUploadPcap = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setErrorBanner(null);
    setStatusNotice(null);
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    try {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let binary = '';
      for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);

      const res = await fetch('/api/sniffer/upload-pcap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base64 }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to parse .pcap file.');
      }
      const status = data as SnifferStatusResponse;
      setCapturing(false);
      setPackets(status.packets);
      setSelectedNumber(status.packets[0]?.number ?? null);
      setStatusNotice(`Loaded ${status.packets.length} real packets from ${file.name}.`);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Invalid .pcap file.');
    }
  };

  const stats = useMemo(() => summarizePackets(packets), [packets]);

  const selectedPacket = useMemo(
    () =>
      packets.find((p) => p.number === selectedNumber) ??
      packets[packets.length - 1] ??
      null,
    [packets, selectedNumber]
  );

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      <header className="sticky top-0 z-20 bg-white border-b border-slate-200 px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-900 text-white">
            <Activity className="h-4 w-4" />
          </div>
          <h1 className="font-display text-sm sm:text-base font-bold text-slate-900 truncate">
            PacketLab - Network Packet Sniffer &amp; Protocol Dissector
          </h1>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <a
            href="/api/sniffer/download"
            download="sniffer.py"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 transition-colors whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5 text-blue-700" />
            <span>Download sniffer.py</span>
          </a>
          <button
            type="button"
            onClick={() => setShowPython((prev) => !prev)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors whitespace-nowrap"
          >
            <Code2 className="h-3.5 w-3.5" />
            <span>{showPython ? 'Hide sniffer.py' : 'View sniffer.py'}</span>
          </button>
        </div>
      </header>

      <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto space-y-4">
        {/* Explicit Capture Scope Notice */}
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-xs text-slate-700">
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 text-blue-700 shrink-0" />
            <span className="font-medium">
              Capture source: this server&apos;s network interfaces, not your personal device.
            </span>
          </div>
          <span
            className={`font-mono font-semibold ${
              capturing ? 'text-emerald-700' : 'text-slate-600'
            }`}
          >
            Socket: {capturing ? `Capturing Live (${selectedIface})` : 'Standby'}
          </span>
        </div>

        {/* Summary Bar: Total Packets, Count per Protocol, Top Source & Destination IPs */}
        <section
          aria-label="Packet Summary Bar"
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 bg-white border border-slate-200 rounded-xl divide-y sm:divide-y-0 sm:divide-x divide-slate-200"
        >
          <div className="p-4">
            <p className="text-xs font-medium text-slate-500">Total Captured</p>
            <p className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-900">
              {stats.totalPackets}
            </p>
            <p className="mt-0.5 text-xs font-mono tabular-nums text-slate-500">
              {stats.totalBytes} bytes · {captureProto} filter
            </p>
          </div>

          <div className="p-4">
            <p className="text-xs font-medium text-slate-500">Count per Protocol</p>
            <div className="mt-1.5 grid grid-cols-3 gap-x-2 gap-y-1 text-xs font-mono tabular-nums text-slate-800">
              <span>TCP: {stats.counts.TCP}</span>
              <span>HTTP: {stats.counts.HTTP}</span>
              <span>UDP: {stats.counts.UDP}</span>
              <span>DNS: {stats.counts.DNS}</span>
              <span>ICMP: {stats.counts.ICMP}</span>
              <span>ARP: {stats.counts.ARP}</span>
            </div>
          </div>

          <div className="p-4">
            <p className="text-xs font-medium text-slate-500">Top Source IPs</p>
            {stats.topSrcIps.length === 0 ? (
              <p className="mt-1.5 text-xs text-slate-400 font-mono">No IP traffic yet</p>
            ) : (
              <ul className="mt-1 space-y-0.5 text-xs font-mono tabular-nums text-slate-800">
                {stats.topSrcIps.map((entry) => (
                  <li key={entry.ip} className="flex items-center justify-between gap-2">
                    <span className="truncate">{entry.ip}</span>
                    <span className="text-slate-500 shrink-0">{entry.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="p-4">
            <p className="text-xs font-medium text-slate-500">Top Destination IPs</p>
            {stats.topDstIps.length === 0 ? (
              <p className="mt-1.5 text-xs text-slate-400 font-mono">No IP traffic yet</p>
            ) : (
              <ul className="mt-1 space-y-0.5 text-xs font-mono tabular-nums text-slate-800">
                {stats.topDstIps.map((entry) => (
                  <li key={entry.ip} className="flex items-center justify-between gap-2">
                    <span className="truncate">{entry.ip}</span>
                    <span className="text-slate-500 shrink-0">{entry.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        {/* Capture & PCAP Controls Bar */}
        <section
          aria-label="Capture Controls"
          className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4"
        >
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <label htmlFor="iface-select" className="text-xs font-medium text-slate-600">
                Interface
              </label>
              <select
                id="iface-select"
                disabled={capturing}
                value={selectedIface}
                onChange={(e) => setSelectedIface(e.target.value)}
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs text-slate-900 focus:border-blue-700 focus:outline-none disabled:opacity-60"
              >
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name} ({iface.addresses[0] ?? 'up'})
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <label htmlFor="proto-select" className="text-xs font-medium text-slate-600">
                Socket Filter
              </label>
              <select
                id="proto-select"
                disabled={capturing}
                value={captureProto}
                onChange={(e) => setCaptureProto(e.target.value as ProtocolFilter)}
                className="rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 font-mono text-xs text-slate-900 focus:border-blue-700 focus:outline-none disabled:opacity-60"
              >
                {(['ALL', 'TCP', 'UDP', 'HTTP', 'DNS', 'ICMP', 'ARP'] as const).map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>

            {capturing ? (
              <button
                type="button"
                onClick={() => void handleStopCapture()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-red-700 px-4 py-2 text-xs font-semibold text-white hover:bg-red-800 whitespace-nowrap"
              >
                <Square className="h-3.5 w-3.5" />
                Stop Capture
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void handleStartCapture()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-blue-700 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-800 whitespace-nowrap"
              >
                <Play className="h-3.5 w-3.5" />
                Start Live Capture
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap"
              onChange={(e) => void handleUploadPcap(e)}
              className="hidden"
              aria-label="Upload PCAP file"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
            >
              <Upload className="h-3.5 w-3.5" />
              Upload .pcap
            </button>

            <button
              type="button"
              onClick={handleExportPcap}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
            >
              <Download className="h-3.5 w-3.5" />
              Export .pcap
            </button>

            <button
              type="button"
              onClick={() => void handleClear()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-red-700 hover:bg-red-50 whitespace-nowrap"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear
            </button>
          </div>
        </section>

        {/* Real Local Traffic Generator Panel */}
        <section
          aria-label="Traffic Generator"
          className="bg-white border border-slate-200 rounded-xl p-4 space-y-2.5"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-xs font-bold uppercase tracking-wide text-slate-700">
              Traffic Generator (Real Loopback Packets)
            </h2>
            <span className="text-xs text-slate-500">
              Generates authentic OS socket traffic without requiring internet access
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {TRAFFIC_ACTIONS.map(({ type, label, target, Icon }) => {
              const isBusy = busyTraffic === type;
              return (
                <button
                  key={type}
                  type="button"
                  disabled={busyTraffic !== null}
                  onClick={() => void handleGenerateTraffic(type)}
                  className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 text-xs font-medium text-slate-800 hover:bg-slate-100 disabled:opacity-60 transition-colors whitespace-nowrap"
                >
                  <Icon className="h-3.5 w-3.5 text-blue-700 shrink-0" />
                  <span>{isBusy ? `${label}...` : label}</span>
                  <span className="font-mono text-[11px] text-slate-500">{target}</span>
                </button>
              );
            })}
          </div>
        </section>

        {errorBanner && (
          <div
            role="alert"
            className="flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-xs font-medium text-red-900"
          >
            <AlertCircle className="h-4 w-4 text-red-700 shrink-0" />
            <span>{errorBanner}</span>
          </div>
        )}

        {statusNotice && !errorBanner && (
          <p
            role="status"
            className="rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-xs text-slate-700"
          >
            {statusNotice}
          </p>
        )}

        {showPython && (
          <PythonSourceView
            code={pythonSource}
            onClose={() => setShowPython(false)}
          />
        )}

        {/* Main Split: Live Packet Table + Dissector */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
          <PacketTable
            packets={packets}
            selectedNumber={selectedPacket?.number ?? null}
            onSelectPacket={setSelectedNumber}
          />
          <PacketDissector packet={selectedPacket} />
        </div>
      </main>
    </div>
  );
}
