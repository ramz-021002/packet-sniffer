import type { CommunicationGraph, GraphEdge, GraphNode } from './pcapGraph'
import { isPrivateOrReservedIp } from './geo'

export function isPublicIpv4(ip: string): boolean {
  return !isPrivateOrReservedIp(ip)
}

function csvEscape(value: string | number): string {
  const s = String(value)
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`
  }
  return s
}

/** Nodes whose IPv4 address is not private/reserved (RFC-style heuristic). */
export function getPublicGraphNodes(graph: CommunicationGraph): GraphNode[] {
  return graph.nodes.filter((n) => isPublicIpv4(n.ip))
}

/**
 * One row per public IP with traffic totals (RFC1918 / link-local / multicast excluded).
 */
export function buildPublicIpsCsv(graph: CommunicationGraph): string {
  const rows: string[][] = [
    [
      'ip',
      'total_bytes',
      'total_packets',
      'outgoing_bytes',
      'incoming_bytes',
      'outgoing_packets',
      'incoming_packets',
    ],
  ]

  const publicNodes = [...getPublicGraphNodes(graph)].sort((a, b) => b.totalBytes - a.totalBytes)

  for (const n of publicNodes) {
    rows.push([
      n.ip,
      String(n.totalBytes),
      String(n.totalPackets),
      String(n.outgoingBytes),
      String(n.incomingBytes),
      String(n.outgoingPackets),
      String(n.incomingPackets),
    ])
  }

  return rows.map((line) => line.map(csvEscape).join(',')).join('\n')
}

/** Directed flows as CSV (all endpoints). */
export function buildFlowsCsv(graph: CommunicationGraph): string {
  const rows: string[][] = [
    ['source_ip', 'target_ip', 'packets', 'bytes', 'protocols'],
  ]

  for (const e of graph.edges) {
    rows.push([
      e.source,
      e.target,
      String(e.packets),
      String(e.bytes),
      e.protocols.join('|'),
    ])
  }

  return rows.map((line) => line.map(csvEscape).join(',')).join('\n')
}

export interface GraphJsonExport {
  exportedAt: string
  format: 'pcap-atlas-communication-graph'
  version: 1
  summary: CommunicationGraph['summary']
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export function buildGraphJson(graph: CommunicationGraph): string {
  const payload: GraphJsonExport = {
    exportedAt: new Date().toISOString(),
    format: 'pcap-atlas-communication-graph',
    version: 1,
    summary: graph.summary,
    nodes: graph.nodes,
    edges: graph.edges,
  }
  return `${JSON.stringify(payload, null, 2)}\n`
}

export function downloadTextFile(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export function downloadDataUrl(filename: string, dataUrl: string): void {
  const a = document.createElement('a')
  a.href = dataUrl
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
}
