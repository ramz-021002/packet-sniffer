import { useMemo, useState } from 'react'
import type { PacketRecord } from '../lib/pcap'
import { RULE_DESCRIPTIONS, type Flag, type FlagResult } from '../lib/flags'

const SEV_LABEL: Record<string, string> = { high: 'High', medium: 'Medium', low: 'Low' }
const MAX_PACKET_ENTRIES = 60

interface PacketEntry {
  record: PacketRecord
  flag: Flag
}

interface NodeEntry {
  ip: string
  flag: Flag
}

interface RuleEntries {
  packets: PacketEntry[]
  nodes: NodeEntry[]
}

interface Props {
  flags: FlagResult
  packets: PacketRecord[]
  selectedPacketIndex?: number | null
  onSelectPacket: (record: PacketRecord) => void
  onSelectNode?: (ip: string) => void
}

export function FlagsSummary({ flags, packets, selectedPacketIndex, onSelectPacket, onSelectNode }: Props) {
  const { summary } = flags
  const total = summary.high + summary.medium + summary.low
  const [expandedRule, setExpandedRule] = useState<string | null>(null)

  // Group every flag occurrence by rule name once, resolving packet indices to records.
  const byRule = useMemo(() => {
    const recordByIndex = new Map(packets.map((p) => [p.index, p]))
    const map = new Map<string, RuleEntries>()
    const ensure = (rule: string) => {
      let entry = map.get(rule)
      if (!entry) {
        entry = { packets: [], nodes: [] }
        map.set(rule, entry)
      }
      return entry
    }

    for (const [index, fls] of flags.packetFlags) {
      const record = recordByIndex.get(index)
      if (!record) continue
      for (const flag of fls) ensure(flag.rule).packets.push({ record, flag })
    }
    for (const [ip, fls] of flags.nodeFlags) {
      for (const flag of fls) ensure(flag.rule).nodes.push({ ip, flag })
    }
    return map
  }, [flags, packets])

  function addr(record: PacketRecord): string {
    const src = record.srcPort != null ? `${record.src}:${record.srcPort}` : record.src
    const dst = record.dstPort != null ? `${record.dst}:${record.dstPort}` : record.dst
    return `${src} → ${dst}`
  }

  return (
    <section className="card flags-card" aria-label="Security flags">
      <div className="flags-header">
        <div>
          <h2>Security Flags</h2>
          <p className="flags-lead">
            Heuristic rules — review in context before drawing conclusions. Click a rule to see what triggered it.
          </p>
        </div>
        <div className="flags-counts">
          {total === 0 ? (
            <span className="flags-clear">No suspicious patterns detected</span>
          ) : (
            <>
              {summary.high > 0 && (
                <span className="flag-count flag-count--high">{summary.high} High</span>
              )}
              {summary.medium > 0 && (
                <span className="flag-count flag-count--medium">{summary.medium} Medium</span>
              )}
              {summary.low > 0 && (
                <span className="flag-count flag-count--low">{summary.low} Low</span>
              )}
            </>
          )}
        </div>
      </div>

      {total > 0 && (
        <ul className="flags-rule-list">
          {summary.rules.map((r) => {
            const entries = byRule.get(r.rule) ?? { packets: [], nodes: [] }
            const isExpanded = expandedRule === r.rule
            const shownPackets = entries.packets.slice(0, MAX_PACKET_ENTRIES)
            const hiddenCount = entries.packets.length - shownPackets.length

            return (
              <li key={r.rule} className={`flag-rule flag-rule--${r.severity}`}>
                <button
                  type="button"
                  className="flag-rule-head"
                  aria-expanded={isExpanded}
                  onClick={() => setExpandedRule((cur) => (cur === r.rule ? null : r.rule))}
                >
                  <span className={`flag-sev-dot flag-sev-dot--${r.severity}`} aria-hidden="true" />
                  <span className="flag-rule-name">{r.rule}</span>
                  <span className="flag-rule-sev">{SEV_LABEL[r.severity]}</span>
                  <span className="flag-rule-count">{r.count}×</span>
                  <span className={`flag-rule-chevron${isExpanded ? ' is-open' : ''}`} aria-hidden="true">▾</span>
                </button>

                {isExpanded && (
                  <div className="flag-rule-detail">
                    {RULE_DESCRIPTIONS[r.rule] && (
                      <p className="flag-rule-desc">{RULE_DESCRIPTIONS[r.rule]}</p>
                    )}

                    {entries.nodes.length > 0 && (
                      <div className="flag-detail-group">
                        <h4 className="flag-detail-heading">
                          Host{entries.nodes.length > 1 ? 's' : ''} ({entries.nodes.length})
                        </h4>
                        <ul className="flag-entry-list">
                          {entries.nodes.map((n, i) => (
                            <li key={i}>
                              <button
                                type="button"
                                className="flag-entry flag-entry--node"
                                onClick={() => onSelectNode?.(n.ip)}
                                disabled={!onSelectNode}
                              >
                                <span className="flag-entry-ip">{n.ip}</span>
                                <span className="flag-entry-detail">{n.flag.detail}</span>
                              </button>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {entries.packets.length > 0 && (
                      <div className="flag-detail-group">
                        <h4 className="flag-detail-heading">
                          Packet{entries.packets.length > 1 ? 's' : ''} ({entries.packets.length})
                        </h4>
                        <ul className="flag-entry-list">
                          {shownPackets.map(({ record, flag }) => {
                            const proto = record.protocol.toLowerCase()
                            const active = selectedPacketIndex === record.index
                            return (
                              <li key={record.index}>
                                <button
                                  type="button"
                                  className={`flag-entry flag-entry--packet${active ? ' is-active' : ''}`}
                                  onClick={() => onSelectPacket(record)}
                                >
                                  <span className="flag-entry-num">#{record.index}</span>
                                  <span className={`proto-badge proto-badge--${proto}`}>{record.protocol}</span>
                                  <span className="flag-entry-addr">{addr(record)}</span>
                                  <span className="flag-entry-detail">{flag.detail}</span>
                                </button>
                              </li>
                            )
                          })}
                        </ul>
                        {hiddenCount > 0 && (
                          <p className="flag-entry-more">+{hiddenCount.toLocaleString()} more packet{hiddenCount > 1 ? 's' : ''} — use the packet filter below to see them all.</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
