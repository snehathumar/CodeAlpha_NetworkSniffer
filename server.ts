import 'dotenv/config';
import express from 'express';
import { execFile, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import dgram from 'node:dgram';
import dns from 'node:dns';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type {
  NetworkInterfaceInfo,
  ProtocolFilter,
  RealPacket,
  TrafficKind,
} from './src/types/sniffer';
import { buildPcapBuffer, parsePcapBuffer } from './src/utils/pcapParser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SNIFFER_SCRIPT = path.join(__dirname, 'sniffer.py');
const MAX_BUFFER_PACKETS = 500;

const StartSchema = z.object({
  iface: z.string().min(1).max(32),
  proto: z.enum(['ALL', 'TCP', 'UDP', 'HTTP', 'DNS', 'ICMP', 'ARP']).default('ALL'),
  count: z.number().int().min(0).max(500).default(0),
});

const UploadPcapSchema = z.object({
  base64: z.string().min(32).max(8_000_000),
});

const TrafficSchema = z.object({
  type: z.enum(['tcp', 'http', 'udp', 'icmp', 'dns']),
});

function formatSnifferError(rawMsg: string): string {
  const lower = rawMsg.toLowerCase();
  if (
    lower.includes('permissionerror') ||
    lower.includes('operation not permitted') ||
    lower.includes('cap_net_raw') ||
    lower.includes('needs root')
  ) {
    return 'Raw packet capture needs root on Linux';
  }
  return rawMsg;
}

function getOsInterfaces(): NetworkInterfaceInfo[] {
  const raw = os.networkInterfaces();
  const list: NetworkInterfaceInfo[] = [{ name: 'all', addresses: ['All Linux Interfaces'] }];
  for (const [name, addrs] of Object.entries(raw)) {
    if (!addrs) continue;
    list.push({
      name,
      addresses: addrs.map((a) => `${a.family}: ${a.address}`),
    });
  }
  return list;
}

class SnifferManager {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private capturing = false;
  private iface = 'all';
  private proto: ProtocolFilter = 'ALL';
  private packets: RealPacket[] = [];
  private totalCaptured = 0;
  private lastError: string | null = null;

  start(iface: string, proto: ProtocolFilter, count: number) {
    this.stop();
    this.lastError = null;
    this.iface = iface;
    this.proto = proto;

    const args = [SNIFFER_SCRIPT, '--iface', iface, '--proto', proto, '--json'];
    if (count > 0) {
      args.push('--count', String(count));
    }

    const child = spawn('python3', args, {
      cwd: __dirname,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    this.proc = child;
    this.capturing = true;

    const rl = readline.createInterface({ input: child.stdout });
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const pkt = JSON.parse(trimmed) as RealPacket;
        this.totalCaptured += 1;
        pkt.number = this.totalCaptured;
        this.packets.push(pkt);
        if (this.packets.length > MAX_BUFFER_PACKETS) {
          this.packets.shift();
        }
      } catch {
        // Ignore malformed partial line
      }
    });

    child.stderr.on('data', (chunk: Buffer) => {
      const msg = chunk.toString('utf8').trim();
      if (msg) {
        this.lastError = formatSnifferError(msg);
      }
    });

    child.on('close', (code) => {
      if (this.proc === child) {
        this.proc = null;
        this.capturing = false;
        if (code !== null && code !== 0 && !this.lastError) {
          this.lastError = `Sniffer process exited with status ${code}.`;
        }
      }
      rl.close();
    });

    child.on('error', (err) => {
      this.lastError = formatSnifferError(err.message);
      this.capturing = false;
      this.proc = null;
    });
  }

  stop() {
    if (this.proc) {
      this.proc.kill('SIGTERM');
      this.proc = null;
    }
    this.capturing = false;
  }

  clear() {
    this.packets = [];
    this.totalCaptured = 0;
    this.lastError = null;
  }

  loadFromPcap(parsedPackets: RealPacket[]) {
    this.stop();
    this.packets = parsedPackets.slice(0, MAX_BUFFER_PACKETS);
    this.totalCaptured = this.packets.length;
    this.lastError = null;
  }

  getStatus() {
    return {
      capturing: this.capturing,
      iface: this.iface,
      proto: this.proto,
      totalCaptured: this.totalCaptured,
      packets: this.packets,
      error: this.lastError,
    };
  }

  getPackets(): RealPacket[] {
    return this.packets;
  }
}

async function runRealLocalTraffic(
  type: TrafficKind,
  port: number
): Promise<{ ok: boolean; skipped?: boolean; message: string }> {
  if (type === 'tcp') {
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
        socket.end();
        resolve();
      });
      socket.setTimeout(1500, () => {
        socket.destroy();
        reject(new Error(`TCP connect to 127.0.0.1:${port} timed out.`));
      });
      socket.on('error', (err) => reject(err));
    });
    return { ok: true, message: `Executed real TCP handshake to 127.0.0.1:${port}.` };
  }

  if (type === 'http') {
    await new Promise<void>((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${port}/api/health`, (resp) => {
        resp.resume();
        resp.on('end', () => resolve());
      });
      req.on('error', (err) => reject(err));
      req.setTimeout(1500, () => {
        req.destroy();
        reject(new Error(`HTTP GET to 127.0.0.1:${port}/api/health timed out.`));
      });
    });
    return { ok: true, message: `Sent real HTTP GET to 127.0.0.1:${port}/api/health.` };
  }

  if (type === 'udp') {
    await new Promise<void>((resolve, reject) => {
      const udp = dgram.createSocket('udp4');
      const msg = Buffer.from('PacketLab_Real_Local_UDP_Probe');
      udp.on('error', (err) => {
        udp.close();
        reject(err);
      });
      udp.send(msg, 9999, '127.0.0.1', (err) => {
        udp.close();
        if (err) reject(err);
        else resolve();
      });
    });
    return { ok: true, message: 'Sent real UDP datagram to 127.0.0.1:9999.' };
  }

  if (type === 'icmp') {
    return new Promise((resolve) => {
      execFile(
        'ping',
        ['-c', '1', '-W', '1', '127.0.0.1'],
        { timeout: 2000 },
        (err, _stdout, stderr) => {
          if (err) {
            const detail = (stderr || err.message || '').trim();
            resolve({
              ok: false,
              skipped: true,
              message: `ICMP ping skipped: not permitted or unavailable in this environment${detail ? ` (${detail.split('\n')[0]})` : ''}.`,
            });
            return;
          }
          resolve({ ok: true, message: 'Sent real ICMP Echo Request to 127.0.0.1.' });
        }
      );
    });
  }

  // DNS lookup (gracefully skipped if external/local DNS resolver is unreachable)
  return new Promise((resolve) => {
    const resolver = new dns.Resolver({ timeout: 1200, tries: 1 });
    resolver.resolve4('example.com', (err, addresses) => {
      if (err) {
        // Fallback to OS resolver for localhost if UDP/53 resolver is unreachable
        dns.lookup('localhost', (lookupErr, addr) => {
          if (lookupErr) {
            resolve({
              ok: false,
              skipped: true,
              message: `DNS lookup skipped: DNS resolver unreachable in offline sandbox (${err.code || err.message}).`,
            });
            return;
          }
          resolve({
            ok: false,
            skipped: true,
            message: `DNS UDP/53 query skipped (${err.code || 'offline'}); OS hosts lookup resolved localhost -> ${addr}.`,
          });
        });
        return;
      }
      resolve({
        ok: true,
        message: `Executed real DNS A-record query for example.com -> ${addresses[0] ?? 'resolved'}.`,
      });
    });
  });
}

async function startServer() {
  const app = express();
  const sniffer = new SnifferManager();
  const port = Number(process.env.PORT || 3000);

  // Top-level JSON deserialization mounted before all route handlers
  app.use(express.json({ limit: '10mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'packetlab-network-sniffer' });
  });

  app.get('/api/sniffer/interfaces', (_req, res) => {
    res.json({ interfaces: getOsInterfaces() });
  });

  app.get('/api/sniffer/status', (_req, res) => {
    res.json(sniffer.getStatus());
  });

  app.post('/api/sniffer/start', (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const parsed = StartSchema.safeParse(body);
    if (!parsed.success) {
      res.status(400).json({
        error: parsed.error.issues[0]?.message ?? 'Invalid capture parameters.',
      });
      return;
    }

    const allowedIfaces = new Set(getOsInterfaces().map((i) => i.name));
    if (!allowedIfaces.has(parsed.data.iface)) {
      res.status(400).json({
        error: `Interface '${parsed.data.iface}' was not found on this host.`,
      });
      return;
    }

    sniffer.start(parsed.data.iface, parsed.data.proto, parsed.data.count);
    res.json(sniffer.getStatus());
  });

  app.post('/api/sniffer/stop', (_req, res) => {
    sniffer.stop();
    res.json(sniffer.getStatus());
  });

  app.post('/api/sniffer/clear', (_req, res) => {
    sniffer.clear();
    res.json(sniffer.getStatus());
  });

  app.post('/api/sniffer/traffic', async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const parsed = TrafficSchema.safeParse(body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid traffic generator action.' });
      return;
    }

    try {
      const result = await runRealLocalTraffic(parsed.data.type, port);
      res.json(result);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Traffic generation failed.',
      });
    }
  });

  app.get('/api/sniffer/export.pcap', (_req, res) => {
    const packets = sniffer.getPackets();
    if (packets.length === 0) {
      res.status(400).json({ error: 'No captured packets to export.' });
      return;
    }
    const pcapBytes = buildPcapBuffer(packets);
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="packetlab_capture.pcap"'
    );
    res.send(Buffer.from(pcapBytes));
  });

  app.post('/api/sniffer/upload-pcap', (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const parsed = UploadPcapSchema.safeParse(body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Provide a valid base64-encoded .pcap file.' });
      return;
    }

    try {
      const rawBuf = Buffer.from(parsed.data.base64, 'base64');
      const packets = parsePcapBuffer(new Uint8Array(rawBuf));
      if (packets.length === 0) {
        res.status(400).json({ error: 'No valid Ethernet packets found in .pcap file.' });
        return;
      }
      sniffer.loadFromPcap(packets);
      res.json(sniffer.getStatus());
    } catch (error) {
      res.status(400).json({
        error: error instanceof Error ? error.message : 'Failed to parse .pcap file.',
      });
    }
  });

  app.get('/api/sniffer/source', async (_req, res) => {
    try {
      const code = await fs.readFile(SNIFFER_SCRIPT, 'utf8');
      res.json({ filename: 'sniffer.py', code });
    } catch {
      res.status(404).json({ error: 'sniffer.py not found on server.' });
    }
  });

  app.get('/api/sniffer/download', async (_req, res) => {
    try {
      const code = await fs.readFile(SNIFFER_SCRIPT, 'utf8');
      res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="sniffer.py"');
      res.send(code);
    } catch {
      res.status(404).json({ error: 'sniffer.py not found on server.' });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.join(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`PacketLab running on http://0.0.0.0:${port}`);
  });

  const cleanup = () => {
    sniffer.stop();
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
