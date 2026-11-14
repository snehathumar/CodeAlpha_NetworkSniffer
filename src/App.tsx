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
  Play,
  Radio,
  Square,
  Trash2,
  Upload,
} from 'lucide-react';
import { PacketTable } from './components/PacketTable';
import { PacketDissector } from './components/PacketDissector';
import { PythonSourceView } from './components/PythonSourceView';
import type {
  NetworkInterfaceInfo,
  ProtocolFilter,
  RealPacket,
  SnifferStatusResponse,
} from './types/sniffer';
import { summarizePackets } from './utils/pcapParser';

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
        throw new Error(data.error || 'Failed to start kernel capture.');
      }
      const status = data as SnifferStatusResponse;
      setCapturing(status.capturing);
      setPackets(status.packets);
      setStatusNotice(`Live AF_PACKET socket bound on interface '${selectedIface}'.`);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Unable to start capture.');
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

  const handleSendProbe = async () => {
    setErrorBanner(null);
    try {
      const res = await fetch('/api/sniffer/probe', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to send local probe.');
      setStatusNotice(data.message);
      setTimeout(() => void fetchStatus(), 350);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : 'Probe error.');
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
      {/* Top Bar Contract: Single Repo/Project Title on Left, Single Primary Action on Right */}
      <header className="sticky top-0 z-20 bg-white border-b border-slate-200 px-4 sm:px-6 py-3 flex items-center justify-between gap-4 sm:gap-8">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-900 text-white">
            <Activity className="h-4 w-4" />
          </div>
          <div className="flex items-center gap-2 min-w-0 text-sm">
            <span className="hidden sm:inline font-mono font-semibold text-blue-700 whitespace-nowrap">
              CodeAlpha_NetworkSniffer
            </span>
            <span className="hidden sm:inline text-slate-400" aria-hidden="true">
              /
            </span>
            <h1 className="font-display font-bold text-slate-900 truncate">
              Network Packet Sniffer
            </h1>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setShowPython((prev) => !prev)}
          className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
        >
          <Code2 className="h-3.5 w-3.5" />
          <span>{showPython ? 'Hide sniffer.py' : 'View sniffer.py'}</span>
        </button>
      </header>

      <main className="flex-1 p-4 sm:p-6 max-w-7xl w-full mx-auto space-y-5">
        {/* 4-Column Live Capture Telemetry Strip */}
        <section
          aria-label="Live Capture Metrics"
          className="grid grid-cols-2 lg:grid-cols-4 bg-white border border-slate-200 rounded-xl divide-y lg:divide-y-0 lg:divide-x divide-slate-200"
        >
          <div className="p-4 sm:p-5">
            <p className="text-xs font-medium text-slate-500">Captured Packets</p>
            <p className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-900">
              {stats.totalPackets}
            </p>
            <p className="mt-0.5 text-xs text-slate-500">AF_PACKET kernel buffer</p>
          </div>

          <div className="p-4 sm:p-5">
            <p className="text-xs font-medium text-slate-500">Captured Bytes</p>
            <p className="mt-1 text-2xl font-bold font-mono tabular-nums text-slate-900">
              {stats.totalBytes} B
            </p>
            <p className="mt-0.5 text-xs text-slate-500">Raw Ethernet frames</p>
          </div>

          <div className="p-4 sm:p-5">
            <p className="text-xs font-medium text-slate-500">Socket State</p>
            <p
              className={`mt-1 text-lg font-bold font-mono ${
                capturing ? 'text-emerald-700' : 'text-slate-800'
              }`}
            >
              {capturing ? 'Capturing Live' : 'Standby'}
            </p>
            <p className="mt-0.5 text-xs text-slate-500 font-mono">
              iface: {selectedIface} · {captureProto}
            </p>
          </div>

          <div className="p-4 sm:p-5">
            <p className="text-xs font-medium text-slate-500">Protocol Split</p>
            <p className="mt-1 text-sm font-mono font-semibold tabular-nums text-slate-900">
              TCP {stats.counts.TCP} · HTTP {stats.counts.HTTP} · UDP {stats.counts.UDP}
            </p>
            <p className="mt-1 text-xs font-mono tabular-nums text-slate-500">
              DNS {stats.counts.DNS} · ICMP {stats.counts.ICMP} · ARP {stats.counts.ARP}
            </p>
          </div>
        </section>

        {/* Capture Controls Bar */}
        <section className="bg-white border border-slate-200 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
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
                {(['ALL', 'TCP', 'UDP', 'HTTP', 'DNS', 'ICMP', 'ARP'] as const).map(
                  (p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  )
                )}
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
            <button
              type="button"
              onClick={() => void handleSendProbe()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
            >
              <Radio className="h-3.5 w-3.5 text-blue-700" />
              Send Real Probe
            </button>

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
