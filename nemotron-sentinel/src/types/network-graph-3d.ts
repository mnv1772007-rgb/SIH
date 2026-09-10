export type NodeStatus = "normal" | "alert" | "active" | "cold" | "critical";

export interface NodeMetadata {
  ip?: string;
  domain?: string;
  country?: string;
  riskScore?: number;
  packetsPerSec?: number;
  protocol?: string;
  timestamp?: string;
  threatType?: string;
  description?: string;
  asn?: string;
  [key: string]: any;
}

export interface NetworkNode {
  id: string;
  name: string;
  group: string | number;
  status?: NodeStatus;
  value?: number;
  metadata?: NodeMetadata;
  // 3D physics coordinates
  x?: number;
  y?: number;
  z?: number;
  vx?: number;
  vy?: number;
  vz?: number;
}

export interface NetworkLink {
  source: string | NetworkNode;
  target: string | NetworkNode;
  value?: number;
  label?: string;
  activeFlow?: boolean;
}

export interface NetworkGraphData {
  nodes: NetworkNode[];
  links: NetworkLink[];
}

export interface NetworkGraphProps {
  data?: NetworkGraphData;
  apiEndpoint?: string;
  autoRefreshIntervalMs?: number;
  onNodeSelect?: (node: NetworkNode | null) => void;
  className?: string;
}
