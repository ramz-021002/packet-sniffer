import type { JSX } from 'react'
import type { PacketRecord } from '../lib/pcap'
import type { Flag } from '../lib/flags'
import { getPacketInfo } from '../lib/protocolInfo'

const BYTES_PER_ROW = 16

function toAscii(b: number): string {
  return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'
}

interface Props {
  record: PacketRecord
  baseSec: number
  baseUsec: number
  flags?: Flag[]
}

export function HexDump({ record, baseSec, baseUsec, flags }: Props) {
  const { payload } = record
  const dSec = record.timestampSec - baseSec
  const dUsec = record.timestampUsec - baseUsec
  const relTime = (dSec + dUsec / 1_000_000).toFixed(6)
  const info = getPacketInfo(record)
  const src = record.srcPort != null ? `${record.src}:${record.srcPort}` : record.src
  const dst = record.dstPort != null ? `${record.dst}:${record.dstPort}` : record.dst
  const proto = record.protocol.toLowerCase()

  const rows: JSX.Element[] = []
  for (let i = 0; i < payload.length; i += BYTES_PER_ROW) {
    const slice = payload.slice(i, i + BYTES_PER_ROW)
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, '0').toUpperCase())
    const asc = Array.from(slice, toAscii)

    while (hex.length < BYTES_PER_ROW) hex.push('  ')
    while (asc.length < BYTES_PER_ROW) asc.push(' ')

    const hexStr = `${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}`

    rows.push(
      <div key={i} className="hex-row">
        <span className="hex-col hex-offset">{i.toString(16).padStart(4, '0').toUpperCase()}</span>
        <span className="hex-col hex-bytes">{hexStr}</span>
        <span className="hex-col hex-ascii">{asc.join('')}</span>
      </div>,
    )
  }

  return (
    <div className="hex-dump-panel">
      <div className="hex-dump-meta">
        <span className="hex-meta-chip">#{record.index}</span>
        <span className="hex-meta-chip">+{relTime}s</span>
        <span className="hex-meta-addr">{src} → {dst}</span>
        <span className={`proto-badge proto-badge--${proto}`}>{record.protocol}</span>
        <span className="hex-meta-chip">{record.ipLength} B</span>
        {info && <span className="hex-meta-info">{info}</span>}
      </div>
      {flags && flags.length > 0 && (
        <ul className="hex-flags">
          {flags.map((flag, i) => (
            <li key={i} className={`hex-flag hex-flag--${flag.severity}`}>
              <span className={`flag-sev-dot flag-sev-dot--${flag.severity}`} aria-hidden="true" />
              <strong>{flag.rule}</strong>
              <span className="hex-flag-detail">{flag.detail}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="hex-dump-body">
        <div className="hex-row hex-row--header">
          <span className="hex-col hex-offset">Offset</span>
          <span className="hex-col hex-bytes">{'00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F'}</span>
          <span className="hex-col hex-ascii">ASCII</span>
        </div>
        {rows}
      </div>
      {payload.length < record.ipLength && (
        <p className="hex-dump-truncated">
          Showing first {payload.length} of {record.ipLength} bytes.
        </p>
      )}
    </div>
  )
}
