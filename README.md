# CodeAlpha_NetworkSniffer

**PacketLab - Network Packet Sniffer & Protocol Dissector** — a real Linux raw-socket packet sniffer built in pure Python 3 (`socket.AF_PACKET` + `struct`) paired with a TypeScript/React live capture workbench, loopback traffic generator, Layer 2/3/4 frame dissector, and Wireshark-compatible `.pcap` exporter/importer.

---

## Key Features

- **100% Real Kernel Capture (`sniffer.py`)**: Binds Linux `AF_PACKET` / `SOCK_RAW` sockets using only Python 3 standard library modules (`socket`, `struct`, `json`, `argparse`) with zero third-party `pip` dependencies.
- **Layer 2 / 3 / 4 Protocol Dissection**: Decodes Ethernet II MACs & EtherType (`0x0800`, `0x0806`, `0x86DD`), ARP, IPv4 (IHL, IP ID, TTL, source/destination IPs), IPv6, TCP (ports, flags, `seq`, `ack`, `window`), UDP, ICMP, DNS, and HTTP payloads with full Hex + ASCII dumps.
- **Traffic Generator Panel (Loopback-First)**: Triggers real local TCP connects, local HTTP `GET` requests, localhost UDP datagrams, plus conditional ICMP pings and DNS lookups without requiring internet connectivity.
- **Wireshark `.pcap` Interop**: Writes and reads standard little/big-endian `libpcap` (`0xa1b2c3d4`) Ethernet capture files (`--pcap capture.pcap` in CLI or **Export .pcap** / **Upload .pcap** in the web UI).

---

## Run on Linux

Raw packet capture requires root privileges (`sudo`) or `CAP_NET_RAW` capability on Linux.

1. **Clone or download `sniffer.py`** (or click **Download sniffer.py** directly inside the PacketLab web UI).
2. **Capture 25 live packets across all interfaces:**
   ```bash
   sudo python3 sniffer.py --iface all --count 25
   ```
3. **Capture 25 packets and save to a `.pcap` file:**
   ```bash
   sudo python3 sniffer.py --iface all --count 25 --pcap capture.pcap
   ```
   *(Optional protocol or interface filter examples: `sudo python3 sniffer.py --iface lo --proto TCP --pcap capture.pcap` or `sudo python3 sniffer.py --iface all --json`)*
4. **Open `capture.pcap` in Wireshark:**
   - **From terminal:**
     ```bash
     wireshark capture.pcap
     ```
   - **From Wireshark GUI:** Open Wireshark -> click **File** -> **Open...** -> select `capture.pcap`.
   - Useful Wireshark display filters: `http`, `tcp`, `udp.port == 9999`, `icmp`, or `ip.addr == 127.0.0.1`.

---

## Demo

Follow these 5 steps to verify live packet capture and protocol analysis in the web workbench:

1. **Start Capture**: Open the PacketLab workbench, keep interface set to `all` (or select `lo`), and click **Start Live Capture** to bind the host's `AF_PACKET` raw socket.
2. **Generate Real Local Traffic**: In the **Traffic Generator** panel, click **TCP Connect**, **HTTP GET**, **UDP Datagram**, **ICMP Ping**, or **DNS Lookup** to emit real loopback packets on the server.
3. **Inspect Summary & Filters**: Watch the **Summary Bar** update live with total packets, protocol counts (`TCP`, `HTTP`, `UDP`, `DNS`, `ICMP`, `ARP`), and top source/destination IPs; filter rows using the protocol tabs or search box.
4. **Dissect Layer 2 / 3 / 4 & Payload**: Click any captured frame in the packet table to inspect its Ethernet MAC headers (Layer 2), IPv4 headers (Layer 3), TCP/UDP/ICMP headers (Layer 4), decoded ASCII text, and raw Hex + ASCII byte dump.
5. **Export & Verify in Wireshark**: Click **Export .pcap** to download a valid `libpcap` capture file (open it in Wireshark or re-load it anytime with **Upload .pcap**), or click **Download sniffer.py** to run the standalone Python script locally on Linux.

---

## Local Development & Verification

```bash
npm install
npm run dev
```

Run tests, type-check, and production build:

```bash
npx --yes tsx --test src/utils/pcapParser.test.ts
npm run lint
npm run build
```
