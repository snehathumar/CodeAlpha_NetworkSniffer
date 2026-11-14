export type ProtocolFilter = 'ALL' | 'TCP' | 'UDP' | 'HTTP' | 'DNS' | 'ICMP' | 'ARP';

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
