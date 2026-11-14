# CodeAlpha_NetworkSniffer

A real Linux raw-socket **Network Packet Sniffer & Protocol Dissector** built in Python (`AF_PACKET` + `struct`) with an interactive full-stack TypeScript/React live packet inspector and Wireshark-compatible `.pcap` export/import.

---

## Features

- **Real Kernel Packet Capture (`sniffer.py`)**: Uses pure Python 3 standard library (`socket.AF_PACKET`, `socket.SOCK_RAW`, `struct`) with zero external pip dependencies.
- **Full Layer 2 / 3 / 4 Dissection**: Parses Ethernet II MACs & EtherType, ARP, IPv4 (TTL, IHL, IP ID, addresses), IPv6, TCP (ports, sequence/ack numbers, window, `SYN/ACK/PSH/FIN/RST` flags), UDP, ICMP, DNS, and HTTP payloads.
- **Wireshark `.pcap` Support**: Writes and reads standard `libpcap` (`0xa1b2c3d4`) binary capture files (`--pcap capture.pcap` in CLI or **Export .pcap** / **Upload .pcap** in the web UI).
- **Live Web Workbench**: Select host interfaces (`all`, `lo`, `eth*`), filter by protocol (`TCP`, `UDP`, `HTTP`, `DNS`, `ICMP`, `ARP`), send real local socket probes, and inspect full Hex + ASCII payload dumps.

---

## CLI Usage (Python)

Run directly on Linux with root privileges or `CAP_NET_RAW`:

```bash
# Capture 25 packets across all interfaces
sudo python3 sniffer.py --iface all --count 25

# Capture TCP traffic on loopback and save to Wireshark .pcap
sudo python3 sniffer.py --iface lo --proto TCP --pcap capture.pcap

# Emit structured JSON lines
sudo python3 sniffer.py --iface all --json
```

---

## Web Application Usage

```bash
npm install
npm run dev
```

Open `http://localhost:3000` to start live packet capture, inspect frames, or upload/download `.pcap` files.

### Verification

```bash
npx --yes tsx --test src/utils/pcapParser.test.ts
npm run lint
npm run build
```
