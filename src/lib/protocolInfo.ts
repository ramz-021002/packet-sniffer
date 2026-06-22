import type { PacketRecord } from './pcap'

const ICMP_TYPES: Record<number, string> = {
  0: 'Echo Reply',
  3: 'Dest Unreachable',
  5: 'Redirect',
  8: 'Echo Request',
  11: 'Time Exceeded',
  12: 'Parameter Problem',
  13: 'Timestamp',
  14: 'Timestamp Reply',
}

// Well-known port → service name
const SERVICES: Record<number, string> = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  135: 'MSRPC',
  137: 'NetBIOS',
  138: 'NetBIOS',
  139: 'NetBIOS',
  143: 'IMAP',
  161: 'SNMP',
  179: 'BGP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'Syslog',
  587: 'SMTP',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  1900: 'SSDP',
  3306: 'MySQL',
  3389: 'RDP',
  5060: 'SIP',
  5353: 'mDNS',
  5432: 'Postgres',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-alt',
  8443: 'HTTPS-alt',
}

// TCP flag bit → short name, ordered for readable display
const TCP_FLAG_BITS: Array<[number, string]> = [
  [0x02, 'SYN'],
  [0x10, 'ACK'],
  [0x01, 'FIN'],
  [0x04, 'RST'],
  [0x08, 'PSH'],
  [0x20, 'URG'],
  [0x40, 'ECE'],
  [0x80, 'CWR'],
]

const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/']

/** Service name for a flow, preferring the lower (well-known) of the two ports. */
function serviceName(srcPort: number | null, dstPort: number | null): string | null {
  if (dstPort != null && SERVICES[dstPort]) return SERVICES[dstPort]
  if (srcPort != null && SERVICES[srcPort]) return SERVICES[srcPort]
  return null
}

function tcpFlagNames(flags: number): string {
  const names = TCP_FLAG_BITS.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name)
  return names.length ? names.join(', ') : 'none'
}

export function getPacketInfo(record: PacketRecord): string {
  const { payload, protocol } = record
  const ihl = payload.length >= 1 ? (payload[0] & 0x0f) * 4 : 0
  const hasL4 = payload.length > ihl

  if (protocol === 'ICMP') {
    if (hasL4) {
      const type = payload[ihl]
      return ICMP_TYPES[type] ? `ICMP ${ICMP_TYPES[type]}` : `ICMP type ${type}`
    }
    return 'ICMP'
  }

  const service = serviceName(record.srcPort, record.dstPort)

  if (protocol === 'UDP') {
    if ((record.srcPort === 53 || record.dstPort === 53) && hasL4) {
      return parseDnsInfo(payload, ihl)
    }
    return service ? `${service} (UDP)` : 'UDP'
  }

  if (protocol === 'TCP') {
    if (hasL4) {
      // Plaintext HTTP request/response line, if present
      const http = parseHttpInfo(payload, ihl)
      if (http) return http

      // TLS ClientHello → server name (SNI), readable even though the session is encrypted
      const sni = parseTlsSni(payload, ihl)
      if (sni) {
        const label = record.srcPort === 443 || record.dstPort === 443 ? 'HTTPS' : 'TLS'
        return `${label} → ${sni}`
      }
    }

    const flagPart = record.tcpFlags != null ? `[${tcpFlagNames(record.tcpFlags)}]` : ''
    if (service) {
      return flagPart ? `${service} ${flagPart}` : service
    }
    return flagPart || 'TCP'
  }

  return protocol === 'OTHER' ? 'Other L4' : ''
}

function parseDnsInfo(payload: Uint8Array, ihl: number): string {
  const dnsStart = ihl + 8
  if (payload.length < dnsStart + 12) return 'DNS'

  const flags = (payload[dnsStart + 2] << 8) | payload[dnsStart + 3]
  const isResponse = (flags & 0x8000) !== 0
  const qdCount = (payload[dnsStart + 4] << 8) | payload[dnsStart + 5]

  const label = isResponse ? 'DNS Response' : 'DNS Query'
  if (qdCount === 0) return label

  const name = readDnsName(payload, dnsStart + 12)
  return name ? `${label}: ${name}` : label
}

function readDnsName(data: Uint8Array, start: number): string {
  const labels: string[] = []
  let pos = start
  let jumps = 0

  while (pos < data.length) {
    if (jumps > 5) break
    const len = data[pos]
    if (len === 0) break

    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= data.length) break
      pos = ((len & 0x3f) << 8) | data[pos + 1]
      jumps++
      continue
    }

    pos++
    if (pos + len > data.length) break

    let label = ''
    for (let i = 0; i < len; i++) {
      const c = data[pos + i]
      label += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '?'
    }
    labels.push(label)
    pos += len
  }

  return labels.join('.')
}

/**
 * Extract the SNI host name from a TLS ClientHello. The hostname is sent in
 * cleartext before encryption begins, so it is readable from the raw bytes.
 * Returns null if this isn't a ClientHello or the SNI lies beyond the captured
 * payload preview. Best-effort with strict bounds checking.
 */
function parseTlsSni(payload: Uint8Array, ihl: number): string | null {
  if (payload.length < ihl + 13) return null
  const tcpHeaderLen = (payload[ihl + 12] >> 4) * 4
  const start = ihl + tcpHeaderLen
  const len = payload.length

  // TLS record: handshake (0x16), then handshake type ClientHello (0x01)
  if (start + 6 > len || payload[start] !== 0x16 || payload[start + 5] !== 0x01) {
    return null
  }

  // Skip record header (5) + handshake header (4) + client version (2) + random (32)
  let pos = start + 5 + 4 + 2 + 32
  if (pos + 1 > len) return null

  // Session ID
  pos += 1 + payload[pos]
  if (pos + 2 > len) return null

  // Cipher suites
  pos += 2 + ((payload[pos] << 8) | payload[pos + 1])
  if (pos + 1 > len) return null

  // Compression methods
  pos += 1 + payload[pos]
  if (pos + 2 > len) return null

  // Extensions block length, then iterate extensions
  pos += 2
  while (pos + 4 <= len) {
    const extType = (payload[pos] << 8) | payload[pos + 1]
    const extLen = (payload[pos + 2] << 8) | payload[pos + 3]
    pos += 4

    if (extType === 0x0000) {
      // server_name extension: list len (2) + name type (1) + name len (2) + host
      if (pos + 5 > len) return null
      const nameLen = (payload[pos + 3] << 8) | payload[pos + 4]
      const nameStart = pos + 5
      if (nameStart + nameLen > len) return null

      let host = ''
      for (let i = 0; i < nameLen; i++) {
        const c = payload[nameStart + i]
        if (c < 0x20 || c >= 0x7f) return null // not a clean hostname
        host += String.fromCharCode(c)
      }
      return host || null
    }

    pos += extLen
  }

  return null
}

function parseHttpInfo(payload: Uint8Array, ihl: number): string {
  if (payload.length < ihl + 13) return ''
  const tcpHeaderLen = (payload[ihl + 12] >> 4) * 4
  const httpStart = ihl + tcpHeaderLen

  if (payload.length <= httpStart + 4) return ''

  const limit = Math.min(httpStart + 128, payload.length)
  let lineEnd = limit
  for (let i = httpStart; i < limit - 1; i++) {
    if (payload[i] === 0x0d && payload[i + 1] === 0x0a) { lineEnd = i; break }
    if (payload[i] === 0x0a) { lineEnd = i; break }
  }

  let line = ''
  for (let i = httpStart; i < lineEnd; i++) {
    line += String.fromCharCode(payload[i])
  }

  for (const prefix of HTTP_METHODS) {
    if (line.startsWith(prefix)) {
      return line.length > 80 ? `${line.slice(0, 80)}…` : line
    }
  }

  return ''
}
