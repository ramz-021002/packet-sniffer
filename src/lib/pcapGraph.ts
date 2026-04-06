import { parsePcapFile, type AnalysisResult, type L4Protocol } from './pcap'

/**
 * Capture-level stats plus graph dimensions. Safe to JSON.stringify for tools / exports.
 */
export interface PcapGraphSummary {
  totalPackets: number
  ipv4Packets: number
  processedPackets: number
  skippedPackets: number
  bytes: number
  nodeCount: number
  edgeCount: number
}

/**
 * One host in the communication graph. `id` equals `ip` (IPv4 string).
 */
export interface GraphNode {
  id: string
  ip: string
  incomingPackets: number
  outgoingPackets: number
  incomingBytes: number
  outgoingBytes: number
  totalPackets: number
  totalBytes: number
}

/**
 * Directed flow A → B (aggregated IPv4 conversations).
 */
export interface GraphEdge {
  id: string
  source: string
  target: string
  packets: number
  bytes: number
  protocols: L4Protocol[]
}

/**
 * Graph structure for visualization, statistics, or downstream analysis (JSON, graph DB, etc.).
 */
export interface CommunicationGraph {
  summary: PcapGraphSummary
  nodes: GraphNode[]
  edges: GraphEdge[]
}

function edgeId(source: string, target: string): string {
  return `${source}>${target}`
}

/**
 * Build a {@link CommunicationGraph} from a full parse result.
 */
export function analysisToGraph(analysis: AnalysisResult): CommunicationGraph {
  const nodes: GraphNode[] = analysis.nodes.map((host) => {
    const totalPackets = host.incomingPackets + host.outgoingPackets
    const totalBytes = host.incomingBytes + host.outgoingBytes
    return {
      id: host.ip,
      ip: host.ip,
      incomingPackets: host.incomingPackets,
      outgoingPackets: host.outgoingPackets,
      incomingBytes: host.incomingBytes,
      outgoingBytes: host.outgoingBytes,
      totalPackets,
      totalBytes,
    }
  })

  const edges: GraphEdge[] = analysis.conversations.map((flow) => ({
    id: edgeId(flow.source, flow.target),
    source: flow.source,
    target: flow.target,
    packets: flow.packets,
    bytes: flow.bytes,
    protocols: [...flow.protocols],
  }))

  return {
    summary: {
      totalPackets: analysis.totalPackets,
      ipv4Packets: analysis.ipv4Packets,
      processedPackets: analysis.processedPackets,
      skippedPackets: analysis.skippedPackets,
      bytes: analysis.bytes,
      nodeCount: nodes.length,
      edgeCount: edges.length,
    },
    nodes,
    edges,
  }
}

/**
 * Parse a classic Ethernet IPv4 PCAP and return a {@link CommunicationGraph}.
 */
export function parsePcapFileToGraph(buffer: ArrayBuffer): CommunicationGraph {
  return analysisToGraph(parsePcapFile(buffer))
}
