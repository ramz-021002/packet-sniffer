import { useEffect, useMemo, useRef, useState } from 'react'
import type { PacketRecord } from '../lib/pcap'
import type { Flag } from '../lib/flags'
import { getPacketInfo } from '../lib/protocolInfo'

const ROW_HEIGHT = 28
const OVERSCAN = 10

interface DerivedRow {
  pkt: PacketRecord
  info: string
  relTime: string
  src: string
  dst: string
  haystack: string
}

interface Props {
  packets: PacketRecord[]
  selectedIndex: number | null
  packetFlags: Map<number, Flag[]>
  onSelect: (record: PacketRecord) => void
}

export function PacketTable({ packets, selectedIndex, packetFlags, onSelect }: Props) {
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [filterText, setFilterText] = useState('')
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportH, setViewportH] = useState(420)

  const scrollRef = useRef<HTMLDivElement>(null)

  // Precompute per-packet display strings once (info parsing is non-trivial)
  const rows = useMemo<DerivedRow[]>(() => {
    const baseSec = packets[0]?.timestampSec ?? 0
    const baseUsec = packets[0]?.timestampUsec ?? 0
    return packets.map((pkt) => {
      const relTime = ((pkt.timestampSec - baseSec) + (pkt.timestampUsec - baseUsec) / 1_000_000).toFixed(6)
      const src = pkt.srcPort != null ? `${pkt.src}:${pkt.srcPort}` : pkt.src
      const dst = pkt.dstPort != null ? `${pkt.dst}:${pkt.dstPort}` : pkt.dst
      const info = getPacketInfo(pkt)
      const haystack = `${src} ${dst} ${pkt.protocol} ${info}`.toLowerCase()
      return { pkt, info, relTime, src, dst, haystack }
    })
  }, [packets])

  const terms = useMemo(
    () => filterText.trim().toLowerCase().split(/\s+/).filter(Boolean),
    [filterText],
  )

  const displayed = useMemo(() => {
    if (!flaggedOnly && terms.length === 0) return rows
    return rows.filter((r) => {
      if (flaggedOnly && !(packetFlags.get(r.pkt.index)?.length)) return false
      if (terms.length && !terms.every((t) => r.haystack.includes(t))) return false
      return true
    })
  }, [rows, flaggedOnly, terms, packetFlags])

  const flaggedCount = useMemo(
    () => rows.reduce((n, r) => n + ((packetFlags.get(r.pkt.index)?.length ?? 0) > 0 ? 1 : 0), 0),
    [rows, packetFlags],
  )

  // Track the scroll viewport height for virtualization
  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const update = () => setViewportH(el.clientHeight)
    update()
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Jump back to the top whenever the visible set changes
  function resetScroll() {
    scrollRef.current?.scrollTo({ top: 0 })
    setScrollTop(0)
  }

  const total = displayed.length
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const endIndex = Math.min(total, Math.ceil((scrollTop + viewportH) / ROW_HEIGHT) + OVERSCAN)
  const topPad = startIndex * ROW_HEIGHT
  const bottomPad = Math.max(0, (total - endIndex) * ROW_HEIGHT)
  const slice = displayed.slice(startIndex, endIndex)

  return (
    <div className="packet-table-outer">
      <div className="packet-table-toolbar">
        <input
          type="text"
          className="packet-filter"
          placeholder="Filter — e.g. tcp, 443, 10.0.0.5, dns"
          value={filterText}
          onChange={(e) => { setFilterText(e.target.value); resetScroll() }}
          spellCheck={false}
        />
        <span className="packet-table-stat">
          {total.toLocaleString()}
          {total !== rows.length && ` of ${rows.length.toLocaleString()}`}
          {flaggedCount > 0 && <> · <span className="stat-flagged">{flaggedCount.toLocaleString()} flagged</span></>}
        </span>
        {flaggedCount > 0 && (
          <button
            type="button"
            className={`pkt-filter-btn${flaggedOnly ? ' pkt-filter-btn--active' : ''}`}
            onClick={() => { setFlaggedOnly((v) => !v); resetScroll() }}
          >
            {flaggedOnly ? 'Show all' : 'Flagged only'}
          </button>
        )}
      </div>

      <div
        className="packet-table-wrap"
        ref={scrollRef}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <table className="packet-table">
          <thead>
            <tr>
              <th className="col-num">#</th>
              <th className="col-time">Time</th>
              <th className="col-addr">Source</th>
              <th className="col-addr">Destination</th>
              <th className="col-proto">Proto</th>
              <th className="col-len">Len</th>
              <th className="col-flags-dots"></th>
              <th className="col-info">Info</th>
            </tr>
          </thead>
          <tbody>
            {topPad > 0 && <tr className="packet-spacer" style={{ height: topPad }}><td colSpan={8} /></tr>}
            {slice.map((row) => {
              const pkt = row.pkt
              const proto = pkt.protocol.toLowerCase()
              const isSelected = selectedIndex === pkt.index
              const rowFlags = packetFlags.get(pkt.index)
              const topSev = rowFlags?.some((f) => f.severity === 'high') ? 'high'
                : rowFlags?.some((f) => f.severity === 'medium') ? 'medium'
                : rowFlags?.length ? 'low' : null

              return (
                <tr
                  key={pkt.index}
                  className={`packet-row packet-row--${proto}${isSelected ? ' packet-row--selected' : ''}${topSev ? ` packet-row--flagged-${topSev}` : ''}`}
                  onClick={() => onSelect(pkt)}
                >
                  <td>{pkt.index}</td>
                  <td className="packet-time">{row.relTime}</td>
                  <td className="packet-addr" title={row.src}>{row.src}</td>
                  <td className="packet-addr" title={row.dst}>{row.dst}</td>
                  <td>
                    <span className={`proto-badge proto-badge--${proto}`}>{pkt.protocol}</span>
                  </td>
                  <td>{pkt.ipLength}</td>
                  <td className="packet-flags-dots">
                    {rowFlags?.map((flag, i) => (
                      <span
                        key={i}
                        className={`flag-dot flag-dot--${flag.severity}`}
                        title={`${flag.rule}: ${flag.detail}`}
                      />
                    ))}
                  </td>
                  <td className="packet-info" title={row.info}>{row.info}</td>
                </tr>
              )
            })}
            {bottomPad > 0 && <tr className="packet-spacer" style={{ height: bottomPad }}><td colSpan={8} /></tr>}
          </tbody>
        </table>
      </div>

      {total === 0 && (
        <p className="packet-table-notice">
          {rows.length === 0 ? 'No packets in this capture.' : 'No packets match the current filter.'}
        </p>
      )}
    </div>
  )
}
