import type { CommunicationGraph } from './pcapGraph'
import { isPrivateOrReservedIp } from './geo'

export type FlagSeverity = 'high' | 'medium' | 'low'

export interface Flag {
  rule: string
  severity: FlagSeverity
  detail: string
}

/** Plain-language explanation of what each rule means and why it matters. */
export const RULE_DESCRIPTIONS: Record<string, string> = {
  'TCP Null Scan':
    'A TCP packet with no flags set. Port scanners (e.g. nmap -sN) use this to probe for open ports while evading some firewalls and logging.',
  'TCP FIN Scan':
    'A TCP packet with only the FIN flag set. A stealth scan technique that can slip past stateless packet filters.',
  'TCP Xmas Scan':
    'FIN, PSH and URG set together — the packet is "lit up like a Christmas tree". A stealth port-scan technique.',
  'Invalid TCP Flags':
    'SYN and RST set simultaneously, an impossible combination in a normal TCP exchange. Indicates crafted or malicious packets.',
  'IP Fragment':
    'A fragmented IP packet. Fragmentation can be abused to split an attack across packets and evade inspection systems that do not reassemble.',
  'Oversized ICMP':
    'An unusually large ICMP packet. Can indicate an ICMP tunnel used to smuggle data, or an ICMP flood.',
  'Oversized DNS':
    'A DNS packet larger than typical. Often a sign of DNS tunneling — encoding data inside DNS queries to exfiltrate it over port 53.',
  'Suspicious Port':
    'Traffic on a port associated with malware, remote-access trojans, or insecure cleartext protocols.',
  'Suspicious Port Usage':
    'A host communicated on a port linked to known malware, backdoors, or insecure protocols.',
  'Port Scan':
    'One host contacted many different ports on a single target — classic port-scanning behaviour used to enumerate open services.',
  'Host Sweep':
    'One host probed the same port across many internal hosts — used to find a specific service across a local network. Fan-out to public servers (e.g. normal web browsing) is excluded to avoid false positives.',
  'High Outbound Volume':
    'A host sent far more data than it received. A large outbound/inbound asymmetry can indicate data exfiltration.',
}

export interface FlagSummary {
  high: number
  medium: number
  low: number
  rules: Array<{ rule: string; severity: FlagSeverity; count: number }>
}

export interface FlagResult {
  packetFlags: Map<number, Flag[]>
  nodeFlags: Map<string, Flag[]>
  summary: FlagSummary
}

// TCP flag bitmasks (byte 13 of TCP header)
const TCP_FIN = 0x01
const TCP_SYN = 0x02
const TCP_RST = 0x04
const TCP_PSH = 0x08
const TCP_URG = 0x20

// Ports associated with known malware/RATs
const RISKY_PORTS = new Map<number, { desc: string; severity: FlagSeverity }>([
  [4444,  { desc: 'Metasploit default shell', severity: 'high' }],
  [6667,  { desc: 'IRC/botnet C2', severity: 'high' }],
  [6668,  { desc: 'IRC/botnet C2', severity: 'high' }],
  [6669,  { desc: 'IRC/botnet C2', severity: 'high' }],
  [31337, { desc: 'Back Orifice', severity: 'high' }],
  [12345, { desc: 'NetBus trojan', severity: 'high' }],
  [12346, { desc: 'NetBus trojan', severity: 'high' }],
  [27374, { desc: 'Sub7 trojan', severity: 'high' }],
  [54321, { desc: 'Back Orifice 2K', severity: 'high' }],
  [1337,  { desc: 'Common backdoor port', severity: 'medium' }],
  [23,    { desc: 'Telnet (cleartext)', severity: 'low' }],
])

const PORT_SCAN_THRESHOLD = 15   // unique dst ports to one host
const HOST_SWEEP_THRESHOLD = 10  // unique dst hosts on one port
const EXFIL_BYTES_MIN = 5 * 1024 * 1024  // 5 MB
const EXFIL_RATIO = 8

export function computeFlags(graph: CommunicationGraph): FlagResult {
  const packetFlags = new Map<number, Flag[]>()
  const nodeFlags = new Map<string, Flag[]>()

  function addPacket(index: number, flag: Flag) {
    const list = packetFlags.get(index) ?? []
    list.push(flag)
    packetFlags.set(index, list)
  }

  function addNode(ip: string, flag: Flag) {
    const existing = nodeFlags.get(ip) ?? []
    // Deduplicate by rule name
    if (!existing.some(f => f.rule === flag.rule)) {
      existing.push(flag)
    }
    nodeFlags.set(ip, existing)
  }

  // ── Per-packet rules ──────────────────────────────────────────────────────
  // Track risky-port edges so we don't emit one flag per packet per edge
  const seenRiskyEdge = new Set<string>()

  for (const pkt of graph.packets) {
    // TCP scan patterns
    if (pkt.protocol === 'TCP' && pkt.tcpFlags != null) {
      const f = pkt.tcpFlags
      if (f === 0) {
        addPacket(pkt.index, { rule: 'TCP Null Scan', severity: 'high',
          detail: 'No TCP flags set — stealth scan technique' })
      } else if (f === TCP_FIN) {
        addPacket(pkt.index, { rule: 'TCP FIN Scan', severity: 'high',
          detail: 'Only FIN flag set — stealth scan technique' })
      } else if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) === (TCP_FIN | TCP_PSH | TCP_URG)) {
        addPacket(pkt.index, { rule: 'TCP Xmas Scan', severity: 'high',
          detail: 'FIN + PSH + URG set — Xmas tree scan technique' })
      } else if ((f & (TCP_SYN | TCP_RST)) === (TCP_SYN | TCP_RST)) {
        addPacket(pkt.index, { rule: 'Invalid TCP Flags', severity: 'high',
          detail: 'SYN + RST simultaneously set — malformed or crafted packet' })
      }
    }

    // IP fragments
    if (pkt.isFragment) {
      addPacket(pkt.index, { rule: 'IP Fragment', severity: 'low',
        detail: 'Fragmented IP packet — can be used to evade deep-packet inspection' })
    }

    // Oversized ICMP (potential tunnel or flood)
    if (pkt.protocol === 'ICMP' && pkt.ipLength > 1000) {
      addPacket(pkt.index, { rule: 'Oversized ICMP', severity: 'medium',
        detail: `${pkt.ipLength}-byte ICMP packet — possible ICMP tunnel or amplification` })
    }

    // Oversized DNS (potential tunneling)
    if (pkt.protocol === 'UDP' && (pkt.srcPort === 53 || pkt.dstPort === 53) && pkt.ipLength > 512) {
      addPacket(pkt.index, { rule: 'Oversized DNS', severity: 'medium',
        detail: `${pkt.ipLength}-byte DNS packet — possible DNS tunneling` })
    }

    // Known malicious/suspicious port
    const dstInfo = pkt.dstPort != null ? RISKY_PORTS.get(pkt.dstPort) : undefined
    const srcInfo = pkt.srcPort != null ? RISKY_PORTS.get(pkt.srcPort) : undefined
    const portInfo = dstInfo ?? srcInfo
    if (portInfo != null) {
      const port = dstInfo ? pkt.dstPort! : pkt.srcPort!
      addPacket(pkt.index, { rule: 'Suspicious Port', severity: portInfo.severity,
        detail: `Port ${port} — ${portInfo.desc}` })

      // Also flag the edge once (deduplicated)
      const edgeKey = `${pkt.src}>${pkt.dst}`
      if (!seenRiskyEdge.has(edgeKey)) {
        seenRiskyEdge.add(edgeKey)
        addNode(pkt.src, { rule: 'Suspicious Port Usage', severity: portInfo.severity,
          detail: `Communicated on port ${port} (${portInfo.desc})` })
      }
    }
  }

  // ── Flow-level rules ──────────────────────────────────────────────────────
  // src → dst → Set<dstPort>  (port scan: one host, many ports)
  const srcDstPorts = new Map<string, Map<string, Set<number>>>()
  // src → dstPort → Set<dstIp>  (host sweep: one port, many hosts)
  const srcPortHosts = new Map<string, Map<number, Set<string>>>()

  for (const pkt of graph.packets) {
    if (pkt.dstPort == null) continue

    // Port scan tracking
    const byDst = srcDstPorts.get(pkt.src) ?? new Map<string, Set<number>>()
    const ports = byDst.get(pkt.dst) ?? new Set<number>()
    ports.add(pkt.dstPort)
    byDst.set(pkt.dst, ports)
    srcDstPorts.set(pkt.src, byDst)

    // Host sweep tracking — only internal targets. A host legitimately fans out
    // to many public servers on one port (e.g. web browsing on 443), so counting
    // public destinations produces false positives on ordinary capture machines.
    if (isPrivateOrReservedIp(pkt.dst)) {
      const byPort = srcPortHosts.get(pkt.src) ?? new Map<number, Set<string>>()
      const hosts = byPort.get(pkt.dstPort) ?? new Set<string>()
      hosts.add(pkt.dst)
      byPort.set(pkt.dstPort, hosts)
      srcPortHosts.set(pkt.src, byPort)
    }
  }

  for (const [src, byDst] of srcDstPorts) {
    for (const [dst, ports] of byDst) {
      if (ports.size >= PORT_SCAN_THRESHOLD) {
        addNode(src, { rule: 'Port Scan', severity: 'high',
          detail: `Contacted ${ports.size} different ports on ${dst}` })
      }
    }
  }

  for (const [src, byPort] of srcPortHosts) {
    for (const [port, hosts] of byPort) {
      if (hosts.size >= HOST_SWEEP_THRESHOLD) {
        addNode(src, { rule: 'Host Sweep', severity: 'high',
          detail: `Probed ${hosts.size} internal hosts on port ${port} — possible network sweep` })
      }
    }
  }

  // ── Per-node rules ────────────────────────────────────────────────────────
  for (const node of graph.nodes) {
    if (isPrivateOrReservedIp(node.ip)) continue  // exfil only relevant for internal hosts

    if (
      node.outgoingBytes >= EXFIL_BYTES_MIN &&
      node.incomingBytes > 0 &&
      node.outgoingBytes / node.incomingBytes >= EXFIL_RATIO
    ) {
      addNode(node.ip, { rule: 'High Outbound Volume', severity: 'medium',
        detail: `Sent ${fmtMB(node.outgoingBytes)} vs received ${fmtMB(node.incomingBytes)} — ${Math.round(node.outgoingBytes / node.incomingBytes)}× asymmetry` })
    }
  }

  // ── Build summary ─────────────────────────────────────────────────────────
  const allFlags = [
    ...[...packetFlags.values()].flat(),
    ...[...nodeFlags.values()].flat(),
  ]

  const ruleCounts = new Map<string, { severity: FlagSeverity; count: number }>()
  for (const flag of allFlags) {
    const entry = ruleCounts.get(flag.rule)
    if (entry) {
      entry.count++
    } else {
      ruleCounts.set(flag.rule, { severity: flag.severity, count: 1 })
    }
  }

  const sevOrder: Record<FlagSeverity, number> = { high: 0, medium: 1, low: 2 }
  const rules = [...ruleCounts.entries()]
    .map(([rule, { severity, count }]) => ({ rule, severity, count }))
    .sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || b.count - a.count)

  const summary: FlagSummary = {
    high: allFlags.filter(f => f.severity === 'high').length,
    medium: allFlags.filter(f => f.severity === 'medium').length,
    low: allFlags.filter(f => f.severity === 'low').length,
    rules,
  }

  return { packetFlags, nodeFlags, summary }
}

function fmtMB(bytes: number): string {
  return `${(bytes / 1_048_576).toFixed(1)} MB`
}
