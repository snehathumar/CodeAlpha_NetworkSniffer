export type ProtocolFilter = 'ALL' | 'TCP' | 'UDP' | 'HTTP' | 'DNS' | 'ICMP' | 'ARP';

export type TrafficKind = 'tcp' | 'http' | 'udp' | 'icmp' | 'dns';

export interface RealPacket {
  number: number;
  timestamp: string;
  isoTimestamp: string;
  length: number;
  protocol: string;
  srcMac: string;
  dstMac: string;
  etherType: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  ttl: number;
  flags: string[];
  seq?: number;
  ack?: number;
  window?: number;
  ipHeaderLen?: number;
  ipId?: number;
  summary: string;
  payloadAscii: string;
  hexDump: string;
  rawHex: string;
}

export interface NetworkInterfaceInfo {
  name: string;
  addresses: string[];
}

export interface SnifferStatusResponse {
  capturing: boolean;
  iface: string;
  proto: ProtocolFilter;
  totalCaptured: number;
  packets: RealPacket[];
  error: string | null;
}

export interface IpRankEntry {
  ip: string;
  count: number;
}

export interface PacketSummaryStats {
  totalPackets: number;
  totalBytes: number;
  counts: Record<string, number>;
  topSrcIps: IpRankEntry[];
  topDstIps: IpRankEntry[];
}
