export type L4Protocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER'

export interface Conversation {
  source: string
  target: string
  packets: number
  bytes: number
  protocols: L4Protocol[]
}

export interface HostTraffic {
  ip: string
  incomingPackets: number
  outgoingPackets: number
  incomingBytes: number
  outgoingBytes: number
}

export interface AnalysisResult {
  totalPackets: number
  ipv4Packets: number
  processedPackets: number
  skippedPackets: number
  bytes: number
  conversations: Conversation[]
  nodes: HostTraffic[]
}

type Endian = 'little' | 'big'

const LINKTYPE_ETHERNET = 1
const ETHERTYPE_IPV4 = 0x0800

export function parsePcapFile(buffer: ArrayBuffer): AnalysisResult {
  const view = new DataView(buffer)

  if (view.byteLength < 24) {
    throw new Error('Invalid pcap file: too small to contain a global header.')
  }

  const endian = detectEndianness(view)
  const littleEndian = endian === 'little'
  const linkType = view.getUint32(20, littleEndian)

  if (linkType !== LINKTYPE_ETHERNET) {
    throw new Error(
      `Unsupported link type ${linkType}. This analyzer currently supports Ethernet captures only.`,
    )
  }

  let offset = 24
  let totalPackets = 0
  let ipv4Packets = 0
  let processedPackets = 0
  let bytes = 0

  const conversations = new Map<string, {
    source: string
    target: string
    packets: number
    bytes: number
    protocols: Set<L4Protocol>
  }>()

  const hosts = new Map<string, HostTraffic>()

  while (offset + 16 <= view.byteLength) {
    const includedLength = view.getUint32(offset + 8, littleEndian)
    const packetStart = offset + 16
    const packetEnd = packetStart + includedLength
    totalPackets += 1

    if (packetEnd > view.byteLength) {
      break
    }

    if (includedLength < 14) {
      offset = packetEnd
      continue
    }

    const etherType = view.getUint16(packetStart + 12, false)
    if (etherType !== ETHERTYPE_IPV4) {
      offset = packetEnd
      continue
    }

    ipv4Packets += 1

    const ipStart = packetStart + 14
    if (packetEnd < ipStart + 20) {
      offset = packetEnd
      continue
    }

    const firstIpByte = view.getUint8(ipStart)
    const ipVersion = firstIpByte >> 4
    const ihl = (firstIpByte & 0x0f) * 4

    if (ipVersion !== 4 || ihl < 20 || packetEnd < ipStart + ihl) {
      offset = packetEnd
      continue
    }

    const totalLength = view.getUint16(ipStart + 2, false)
    const protocolByte = view.getUint8(ipStart + 9)
    const source = readIpv4Address(view, ipStart + 12)
    const target = readIpv4Address(view, ipStart + 16)
    const protocol = toL4Protocol(protocolByte)

    const packetBytes = totalLength > 0 ? totalLength : packetEnd - ipStart

    processedPackets += 1
    bytes += packetBytes

    const conversationKey = `${source}>${target}`
    const existingConversation = conversations.get(conversationKey)

    if (!existingConversation) {
      conversations.set(conversationKey, {
        source,
        target,
        packets: 1,
        bytes: packetBytes,
        protocols: new Set<L4Protocol>([protocol]),
      })
    } else {
      existingConversation.packets += 1
      existingConversation.bytes += packetBytes
      existingConversation.protocols.add(protocol)
    }

    incrementHostTraffic(hosts, source, packetBytes, true)
    incrementHostTraffic(hosts, target, packetBytes, false)

    offset = packetEnd
  }

  return {
    totalPackets,
    ipv4Packets,
    processedPackets,
    skippedPackets: totalPackets - processedPackets,
    bytes,
    conversations: [...conversations.values()].map((flow) => ({
      source: flow.source,
      target: flow.target,
      packets: flow.packets,
      bytes: flow.bytes,
      protocols: [...flow.protocols],
    })),
    nodes: [...hosts.values()],
  }
}

function detectEndianness(view: DataView): Endian {
  const magicNumber = view.getUint32(0, false)

  if (magicNumber === 0xa1b2c3d4 || magicNumber === 0xa1b23c4d) {
    return 'big'
  }

  if (magicNumber === 0xd4c3b2a1 || magicNumber === 0x4d3cb2a1) {
    return 'little'
  }

  throw new Error('Unsupported file format. Provide a classic .pcap file (not pcapng).')
}

function readIpv4Address(view: DataView, startOffset: number): string {
  return [
    view.getUint8(startOffset),
    view.getUint8(startOffset + 1),
    view.getUint8(startOffset + 2),
    view.getUint8(startOffset + 3),
  ].join('.')
}

function toL4Protocol(protocolByte: number): L4Protocol {
  if (protocolByte === 6) {
    return 'TCP'
  }

  if (protocolByte === 17) {
    return 'UDP'
  }

  if (protocolByte === 1) {
    return 'ICMP'
  }

  return 'OTHER'
}

function incrementHostTraffic(
  hosts: Map<string, HostTraffic>,
  ip: string,
  bytes: number,
  isOutgoing: boolean,
): void {
  const current = hosts.get(ip) ?? {
    ip,
    incomingPackets: 0,
    outgoingPackets: 0,
    incomingBytes: 0,
    outgoingBytes: 0,
  }

  if (isOutgoing) {
    current.outgoingPackets += 1
    current.outgoingBytes += bytes
  } else {
    current.incomingPackets += 1
    current.incomingBytes += bytes
  }

  hosts.set(ip, current)
}
