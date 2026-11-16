#!/usr/bin/env python3
"""
PacketLab - Network Packet Sniffer & Protocol Dissector
Standalone Linux Raw-Socket Packet Capture CLI (CodeAlpha_NetworkSniffer)

Captures live network packets from Linux network interfaces using raw AF_PACKET
sockets (pure Python standard library, no external dependencies required),
dissects Ethernet, IPv4, TCP, UDP, ICMP, DNS, ARP, and HTTP headers, and
optionally exports captures to standard Wireshark-compatible .pcap files.

Usage:
  sudo python3 sniffer.py --iface all --count 25
  sudo python3 sniffer.py --iface all --count 25 --pcap capture.pcap
  sudo python3 sniffer.py --iface lo --proto TCP --json
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

ETH_HEADER_LEN = 14
PCAP_GLOBAL_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1


def format_mac(raw_mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_mac)


def format_hex_dump(data: bytes, max_bytes: int = 512) -> str:
    clipped = data[:max_bytes]
    if not clipped:
        return "0000  (empty payload)"
    lines: List[str] = []
    for offset in range(0, len(clipped), 16):
        chunk = clipped[offset : offset + 16]
        hex_cols = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_cols = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_cols}  |{ascii_cols}|")
    if len(data) > max_bytes:
        lines.append(f"... ({len(data) - max_bytes} more bytes truncated)")
    return "\n".join(lines)


def decode_tcp_flags(flags_byte: int) -> List[str]:
    flag_names = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    return [name for mask, name in flag_names if flags_byte & mask]


def detect_app_protocol(
    transport_proto: str, src_port: int, dst_port: int, payload: bytes
) -> str:
    ports = {src_port, dst_port}
    if 53 in ports:
        return "DNS"
    if 80 in ports or 8080 in ports or 3000 in ports:
        head = payload[:24].decode("ascii", errors="ignore")
        if any(
            head.startswith(m)
            for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")
        ):
            return "HTTP"
    return transport_proto


def dissect_ethernet_frame(raw_frame: bytes, packet_num: int) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    time_short = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if len(raw_frame) < ETH_HEADER_LEN:
        return {
            "number": packet_num,
            "timestamp": time_short,
            "isoTimestamp": now_iso,
            "length": len(raw_frame),
            "protocol": "OTHER",
            "srcMac": "00:00:00:00:00:00",
            "dstMac": "00:00:00:00:00:00",
            "etherType": "0x0000",
            "srcIp": "unknown",
            "dstIp": "unknown",
            "srcPort": 0,
            "dstPort": 0,
            "ttl": 0,
            "flags": [],
            "summary": f"Truncated frame ({len(raw_frame)} bytes)",
            "payloadAscii": "",
            "hexDump": format_hex_dump(raw_frame),
            "rawHex": raw_frame.hex(),
        }

    dst_mac, src_mac, eth_proto = struct.unpack("! 6s 6s H", raw_frame[:ETH_HEADER_LEN])
    eth_payload = raw_frame[ETH_HEADER_LEN:]

    result: Dict[str, Any] = {
        "number": packet_num,
        "timestamp": time_short,
        "isoTimestamp": now_iso,
        "length": len(raw_frame),
        "protocol": "OTHER",
        "srcMac": format_mac(src_mac),
        "dstMac": format_mac(dst_mac),
        "etherType": f"0x{eth_proto:04x}",
        "srcIp": "-",
        "dstIp": "-",
        "srcPort": 0,
        "dstPort": 0,
        "ttl": 0,
        "flags": [],
        "summary": f"Ethernet frame EtherType 0x{eth_proto:04x}",
        "payloadAscii": "",
        "hexDump": format_hex_dump(raw_frame),
        "rawHex": raw_frame.hex(),
    }

    # ARP (0x0806)
    if eth_proto == 0x0806 and len(eth_payload) >= 28:
        htype, ptype, hlen, plen, oper = struct.unpack("! HHBBH", eth_payload[:8])
        sha = format_mac(eth_payload[8:14])
        spa = socket.inet_ntoa(eth_payload[14:18])
        tha = format_mac(eth_payload[18:24])
        tpa = socket.inet_ntoa(eth_payload[24:28])
        op_label = "Request" if oper == 1 else "Reply" if oper == 2 else f"Op={oper}"
        result.update(
            {
                "protocol": "ARP",
                "srcIp": spa,
                "dstIp": tpa,
                "summary": f"ARP {op_label}: Who has {tpa}? Tell {spa} ({sha} -> {tha})",
            }
        )
        return result

    # IPv4 (0x0800)
    if eth_proto == 0x0800 and len(eth_payload) >= 20:
        ver_ihl, tos, total_len, ident, frag_off, ttl, ip_proto, checksum, src_b, dst_b = struct.unpack(
            "! BBHHHBBH4s4s", eth_payload[:20]
        )
        ihl = (ver_ihl & 0x0F) * 4
        src_ip = socket.inet_ntoa(src_b)
        dst_ip = socket.inet_ntoa(dst_b)
        ip_payload = eth_payload[ihl:]

        result.update(
            {
                "srcIp": src_ip,
                "dstIp": dst_ip,
                "ttl": ttl,
                "ipHeaderLen": ihl,
                "ipId": ident,
            }
        )

        # TCP (6)
        if ip_proto == 6 and len(ip_payload) >= 20:
            src_port, dst_port, seq, ack, offset_reserved_flags, window, tcp_sum, urg = struct.unpack(
                "! HHLLHHHH", ip_payload[:20]
            )
            tcp_hdr_len = ((offset_reserved_flags >> 12) & 0x0F) * 4
            flags = decode_tcp_flags(offset_reserved_flags & 0xFF)
            app_payload = ip_payload[tcp_hdr_len:]
            proto_label = detect_app_protocol("TCP", src_port, dst_port, app_payload)
            ascii_preview = "".join(
                chr(b) if 32 <= b <= 126 or b in (10, 13) else "."
                for b in app_payload[:1024]
            )
            first_line = ascii_preview.splitlines()[0][:90] if ascii_preview.strip() else ""
            summary = (
                f"{proto_label} :{src_port} -> :{dst_port} [{','.join(flags) or 'NONE'}] seq={seq}"
            )
            if first_line and proto_label == "HTTP":
                summary = f"HTTP {first_line}"

            result.update(
                {
                    "protocol": proto_label,
                    "srcPort": src_port,
                    "dstPort": dst_port,
                    "flags": flags,
                    "seq": seq,
                    "ack": ack,
                    "window": window,
                    "summary": summary,
                    "payloadAscii": ascii_preview,
                    "hexDump": format_hex_dump(app_payload if app_payload else raw_frame),
                }
            )
            return result

        # UDP (17)
        if ip_proto == 17 and len(ip_payload) >= 8:
            src_port, dst_port, udp_len, udp_sum = struct.unpack("! HHHH", ip_payload[:8])
            app_payload = ip_payload[8:]
            proto_label = detect_app_protocol("UDP", src_port, dst_port, app_payload)
            ascii_preview = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in app_payload[:512]
            )
            result.update(
                {
                    "protocol": proto_label,
                    "srcPort": src_port,
                    "dstPort": dst_port,
                    "summary": f"{proto_label} :{src_port} -> :{dst_port} len={len(app_payload)}B",
                    "payloadAscii": ascii_preview,
                    "hexDump": format_hex_dump(app_payload if app_payload else raw_frame),
                }
            )
            return result

        # ICMP (1)
        if ip_proto == 1 and len(ip_payload) >= 4:
            icmp_type, icmp_code, icmp_sum = struct.unpack("! BBH", ip_payload[:4])
            icmp_data = ip_payload[4:]
            type_label = (
                "Echo Reply"
                if icmp_type == 0
                else "Echo Request"
                if icmp_type == 8
                else f"Type {icmp_type}"
            )
            ascii_preview = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in icmp_data[:256]
            )
            result.update(
                {
                    "protocol": "ICMP",
                    "flags": [type_label],
                    "summary": f"ICMP {type_label} (code={icmp_code}) {src_ip} -> {dst_ip}",
                    "payloadAscii": ascii_preview,
                    "hexDump": format_hex_dump(icmp_data if icmp_data else raw_frame),
                }
            )
            return result

        result["protocol"] = f"IP({ip_proto})"
        result["summary"] = f"IPv4 proto={ip_proto} {src_ip} -> {dst_ip}"
        return result

    # IPv6 (0x86DD)
    if eth_proto == 0x86DD and len(eth_payload) >= 40:
        src_v6 = socket.inet_ntop(socket.AF_INET6, eth_payload[8:24])
        dst_v6 = socket.inet_ntop(socket.AF_INET6, eth_payload[24:40])
        next_hdr = eth_payload[6]
        hop_limit = eth_payload[7]
        proto_name = "TCP" if next_hdr == 6 else "UDP" if next_hdr == 17 else "ICMPv6" if next_hdr == 58 else f"IPv6({next_hdr})"
        src_port, dst_port = 0, 0
        app_payload = eth_payload[40:]
        if next_hdr in (6, 17) and len(app_payload) >= 4:
            src_port, dst_port = struct.unpack("! HH", app_payload[:4])
        result.update(
            {
                "protocol": proto_name if proto_name in ("TCP", "UDP") else "OTHER",
                "srcIp": src_v6,
                "dstIp": dst_v6,
                "srcPort": src_port,
                "dstPort": dst_port,
                "ttl": hop_limit,
                "summary": f"IPv6 {proto_name} {src_v6} -> {dst_v6}",
            }
        )
        return result

    return result


class PcapWriter:
    def __init__(self, filepath: str) -> None:
        self.fp = open(filepath, "wb")
        header = struct.pack(
            "<IHHIIII",
            PCAP_GLOBAL_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            65535,
            PCAP_LINKTYPE_ETHERNET,
        )
        self.fp.write(header)
        self.fp.flush()

    def write_packet(self, raw_frame: bytes) -> None:
        now = time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1_000_000)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(raw_frame), len(raw_frame))
        self.fp.write(pkt_hdr + raw_frame)
        self.fp.flush()

    def close(self) -> None:
        self.fp.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PacketLab - Real Linux Raw-Socket Network Packet Sniffer"
    )
    parser.add_argument(
        "--iface",
        default="all",
        help="Network interface name (e.g., lo, eth1, eth2) or 'all' (default: all)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture before exiting (0 = continuous)",
    )
    parser.add_argument(
        "--proto",
        default="ALL",
        choices=["ALL", "TCP", "UDP", "ICMP", "HTTP", "DNS", "ARP"],
        help="Optional protocol filter (default: ALL)",
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="Optional output .pcap file path (Wireshark compatible)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit newline-delimited JSON records to stdout",
    )
    args = parser.parse_args()

    running = True

    def handle_stop(_signum: int, _frame: Any) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if args.iface != "all":
            sock.bind((args.iface, 0))
        sock.settimeout(0.5)
    except PermissionError:
        print(
            "Raw packet capture needs root on Linux",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        print(f"Error binding interface '{args.iface}': {exc}", file=sys.stderr)
        sys.exit(1)

    pcap_writer: Optional[PcapWriter] = PcapWriter(args.pcap) if args.pcap else None
    captured_count = 0

    if not args.json:
        print(
            f"[*] Listening on interface='{args.iface}' proto='{args.proto}' (Ctrl+C to stop)..."
        )

    try:
        while running:
            if args.count > 0 and captured_count >= args.count:
                break
            try:
                raw_frame, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue

            dissected = dissect_ethernet_frame(raw_frame, captured_count + 1)
            if args.proto != "ALL" and dissected["protocol"] != args.proto:
                continue

            captured_count += 1
            dissected["number"] = captured_count

            if pcap_writer:
                pcap_writer.write_packet(raw_frame)

            if args.json:
                sys.stdout.write(json.dumps(dissected) + "\n")
                sys.stdout.flush()
            else:
                print(
                    f"[{dissected['timestamp']}] #{captured_count:<4} "
                    f"{dissected['protocol']:<5} {dissected['srcIp']}:{dissected['srcPort']} -> "
                    f"{dissected['dstIp']}:{dissected['dstPort']} | {dissected['summary']}"
                )
    finally:
        sock.close()
        if pcap_writer:
            pcap_writer.close()


if __name__ == "__main__":
    main()
