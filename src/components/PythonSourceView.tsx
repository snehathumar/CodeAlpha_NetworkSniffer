import React, { useState } from 'react';
import { Check, Copy, Download, Terminal, X } from 'lucide-react';

interface PythonSourceViewProps {
  code: string;
  onClose: () => void;
}

export function PythonSourceView({ code, onClose }: PythonSourceViewProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      // Ignore clipboard restriction
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section
      aria-label="Standalone Python Sniffer Source Code"
      className="bg-white border border-slate-200 rounded-xl p-5 space-y-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-200">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Standalone Python CLI Source (sniffer.py)
          </h2>
          <p className="text-xs text-slate-600">
            Pure Python 3 raw-socket sniffer (<code className="font-mono text-slate-800">socket.AF_PACKET</code>) for Linux with Wireshark <code className="font-mono text-slate-800">.pcap</code> export.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void handleCopy()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 whitespace-nowrap"
          >
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-700" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                <span>Copy Code</span>
              </>
            )}
          </button>
          <a
            href="/api/sniffer/download"
            download="sniffer.py"
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-800 whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download sniffer.py</span>
          </a>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close Python source viewer"
            className="rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="rounded-lg bg-slate-50 border border-slate-200 p-3 flex flex-wrap items-center gap-2 text-xs font-mono text-slate-700">
        <Terminal className="h-4 w-4 text-slate-500 shrink-0" />
        <span>sudo python3 sniffer.py --iface all --count 25 --pcap capture.pcap</span>
      </div>

      <pre className="rounded-lg bg-slate-900 text-slate-100 p-4 font-mono text-xs overflow-x-auto max-h-96 overflow-y-auto leading-relaxed">
        {code}
      </pre>
    </section>
  );
}
