import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import { parsePcapFile, type AnalysisResult } from './lib/pcap'
import { fetchGeoDetails, formatGeoDetails, type GeoDetails } from './lib/geo'
import './App.css'

function App() {
  const graphContainerRef = useRef<HTMLDivElement | null>(null)
  const graphRef = useRef<Core | null>(null)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [selectedFileName, setSelectedFileName] = useState('')
  const [error, setError] = useState('')
  const [isParsing, setIsParsing] = useState(false)
  const [selectedNodeIp, setSelectedNodeIp] = useState<string | null>(null)
  const [geoDetails, setGeoDetails] = useState<GeoDetails | null>(null)
  const [isFetchingGeo, setIsFetchingGeo] = useState(false)

  const denseGraphMode = useMemo(() => {
    if (!analysis) {
      return false
    }

    return analysis.nodes.length > 8 || analysis.conversations.length > 14
  }, [analysis])

  useEffect(() => {
    if (!graphContainerRef.current || !analysis) {
      return
    }

    graphRef.current?.destroy()

    const elements: ElementDefinition[] = []

    for (const node of analysis.nodes) {
      const traffic =
        node.incomingPackets + node.outgoingPackets || node.incomingBytes + node.outgoingBytes
      elements.push({
        data: {
          id: node.ip,
          label: node.ip,
          traffic,
          incomingPackets: node.incomingPackets,
          outgoingPackets: node.outgoingPackets,
          incomingBytes: node.incomingBytes,
          outgoingBytes: node.outgoingBytes,
        },
      })
    }

    for (const flow of analysis.conversations) {
      elements.push({
        data: {
          id: `${flow.source}>${flow.target}`,
          source: flow.source,
          target: flow.target,
          label: `${flow.packets} pkts`,
          packets: flow.packets,
          bytes: flow.bytes,
          protocols: flow.protocols.join(', '),
        },
      })
    }

    graphRef.current = cytoscape({
      container: graphContainerRef.current,
      elements,
      wheelSensitivity: 0.15,
      style: [
        {
          selector: 'node',
          style: {
            label: denseGraphMode ? '' : 'data(label)',
            'font-family': '"Space Grotesk", sans-serif',
            'font-size': 13,
            'font-weight': 700,
            color: '#0f172a',
            'text-wrap': 'none',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 16,
            'text-background-color': '#f8fafc',
            'text-background-opacity': 0.95,
            'text-background-shape': 'roundrectangle',
            'text-background-padding': '4px',
            'background-color': '#0f766e',
            'border-width': 2,
            'border-color': '#f1f5f9',
            width: 'mapData(traffic, 1, 3000, 24, 70)',
            height: 'mapData(traffic, 1, 3000, 24, 70)',
          },
        },
        {
          selector: 'edge',
          style: {
            label: denseGraphMode ? '' : 'data(label)',
            'font-family': '"IBM Plex Mono", monospace',
            'font-size': 10,
            color: '#0f172a',
            width: 'mapData(packets, 1, 200, 1, 8)',
            'line-color': '#0ea5a0',
            'target-arrow-color': '#0ea5a0',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.85,
            'text-background-padding': '2px',
          },
        },
        {
          selector: 'node.reveal-label, node:selected',
          style: {
            label: 'data(label)',
          },
        },
        {
          selector: 'edge.reveal-label, edge:selected',
          style: {
            label: 'data(label)',
            'text-background-opacity': 0.95,
          },
        },
        {
          selector: ':selected',
          style: {
            'overlay-opacity': 0,
            'border-color': '#f97316',
            'line-color': '#f97316',
            'target-arrow-color': '#f97316',
          },
        },
      ],
      layout: {
        name: 'cose',
        fit: true,
        animate: false,
        idealEdgeLength: denseGraphMode ? 240 : 170,
        nodeRepulsion: denseGraphMode ? 300000 : 160000,
        gravity: 0.4,
        componentSpacing: denseGraphMode ? 120 : 60,
        padding: denseGraphMode ? 44 : 24,
      },
    })

    if (graphRef.current) {
      const cy = graphRef.current

      cy.on('tap', 'node', (event) => {
        const nodeIp = event.target.data('id') as string
        if (denseGraphMode) {
          event.target.toggleClass('reveal-label')
        }
        setSelectedNodeIp(nodeIp)
        setGeoDetails(null)
        setIsFetchingGeo(true)
        void fetchGeoDetails(nodeIp).then((details) => {
          setGeoDetails(details)
          setIsFetchingGeo(false)
        })
      })

      cy.on('tap', 'edge', (event) => {
        cy.edges().removeClass('reveal-label')
        event.target.addClass('reveal-label')
      })

      cy.on('tap', (event) => {
        if (event.target === cy) {
          cy.nodes().removeClass('reveal-label')
          cy.edges().removeClass('reveal-label')
          setSelectedNodeIp(null)
          setGeoDetails(null)
        }
      })
    }

    return () => {
      graphRef.current?.destroy()
      graphRef.current = null
    }
  }, [analysis, denseGraphMode])

  const topTalkers = useMemo(() => {
    if (!analysis) {
      return []
    }

    return [...analysis.nodes]
      .sort((a, b) => {
        const aTraffic = a.incomingBytes + a.outgoingBytes
        const bTraffic = b.incomingBytes + b.outgoingBytes
        return bTraffic - aTraffic
      })
      .slice(0, 5)
  }, [analysis])

  async function handleFileChange(file: File | null) {
    if (!file) {
      return
    }

    setIsParsing(true)
    setError('')
    setSelectedFileName(file.name)

    try {
      const arrayBuffer = await file.arrayBuffer()
      const result = parsePcapFile(arrayBuffer)
      setAnalysis(result)
    } catch (caughtError) {
      const message =
        caughtError instanceof Error ? caughtError.message : 'Unknown parsing error occurred.'
      setAnalysis(null)
      setError(message)
    } finally {
      setIsParsing(false)
    }
  }

  return (
    <main className="page-shell">
      <header className="hero-banner">
        <p className="eyebrow">Client-side Packet Intelligence</p>
        <h1>PCAP Communication Atlas</h1>
        <p className="intro">
          Upload a classic <strong>.pcap</strong> file, decode Ethernet + IPv4 traffic directly in
          your browser, and inspect how hosts communicate.
        </p>
      </header>

      <section className="control-panel" aria-label="Upload controls">
        <label className="upload-button" htmlFor="pcap-input">
          Select PCAP File
        </label>
        <input
          id="pcap-input"
          className="file-input"
          type="file"
          accept=".pcap,application/vnd.tcpdump.pcap"
          onChange={(event) => {
            const file = event.target.files?.[0] ?? null
            void handleFileChange(file)
          }}
        />
        <p className="file-caption">{selectedFileName || 'No file selected yet.'}</p>
        <p className="hint">Current parser supports classic PCAP with Ethernet link type.</p>
      </section>

      {isParsing && <p className="status">Parsing capture...</p>}
      {error && <p className="status error">{error}</p>}

      {analysis && (
        <>
          <section className="metrics" aria-label="Capture metrics">
            <article>
              <h2>Packets In File</h2>
              <p>{analysis.totalPackets}</p>
            </article>
            <article>
              <h2>IPv4 Packets Seen</h2>
              <p>{analysis.ipv4Packets}</p>
            </article>
            <article>
              <h2>Graphable Packets</h2>
              <p>{analysis.processedPackets}</p>
            </article>
            <article>
              <h2>Conversations</h2>
              <p>{analysis.conversations.length}</p>
            </article>
            <article>
              <h2>Unique Hosts</h2>
              <p>{analysis.nodes.length}</p>
            </article>
            <article>
              <h2>Traffic Volume</h2>
              <p>{formatBytes(analysis.bytes)}</p>
            </article>
          </section>

          <section className="grid-layout">
            <article className="card graph-card">
              <h2>Communication Graph</h2>
              <p>Nodes are IP addresses. Directed edges represent source-to-destination flows.</p>
              <p className="dense-tip">
                {denseGraphMode
                  ? 'Dense mode: Click a node to reveal its IP label (and look up ISP details). Click an edge to show packet count.'
                  : 'Click a node to look up ISP, domain, and location details.'}
              </p>
              <div ref={graphContainerRef} className="graph-canvas" />
              {selectedNodeIp && (
                <article className="geo-detail-panel">
                  <h3>{selectedNodeIp}</h3>
                  {isFetchingGeo ? (
                    <p className="geo-loading">Fetching ISP details...</p>
                  ) : geoDetails ? (
                    <pre className="geo-info">{formatGeoDetails(geoDetails)}</pre>
                  ) : null}
                </article>
              )}
            </article>

            <article className="card">
              <h2>Top Talkers</h2>
              <ol className="talker-list">
                {topTalkers.map((node) => {
                  const bytes = node.incomingBytes + node.outgoingBytes
                  return (
                    <li key={node.ip}>
                      <div>
                        <strong>{node.ip}</strong>
                        <span>{formatBytes(bytes)}</span>
                      </div>
                      <small>
                        {node.outgoingPackets} out / {node.incomingPackets} in packets
                      </small>
                    </li>
                  )
                })}
              </ol>
            </article>
          </section>
        </>
      )}
    </main>
  )
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`
  }

  const units = ['KB', 'MB', 'GB']
  let current = value / 1024
  let unitIndex = 0

  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024
    unitIndex += 1
  }

  return `${current.toFixed(2)} ${units[unitIndex]}`
}

export default App
