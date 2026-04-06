import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition, type LayoutOptions } from 'cytoscape'
import type { CommunicationGraph } from './lib/pcapGraph'
import { parsePcapFileToGraph } from './lib/pcapGraph'
import { buildCytoscapeStyles } from './lib/cyTheme'
import { fetchGeoDetails, formatGeoDetails, type GeoDetails } from './lib/geo'
import { applyThemeToDocument, getInitialTheme, type UiTheme } from './theme'
import {
  buildFlowsCsv,
  buildGraphJson,
  buildPublicIpsCsv,
  downloadDataUrl,
  downloadTextFile,
  getPublicGraphNodes,
} from './lib/exportCapture'
import './App.css'

function GitHubMark() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="github-link__icon">
      <path d="M12 2C6.48 2 2 6.58 2 12.25c0 4.53 2.87 8.38 6.84 9.73.5.09.68-.22.68-.48v-1.67c-2.78.62-3.37-1.37-3.37-1.37-.46-1.2-1.13-1.52-1.13-1.52-.92-.65.07-.64.07-.64 1.02.08 1.56 1.07 1.56 1.07.91 1.57 2.4 1.12 2.98.86.09-.68.35-1.12.63-1.38-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.25-.45-1.28.1-2.66 0 0 .84-.28 2.75 1.05a9.18 9.18 0 0 1 5 0c1.9-1.33 2.74-1.05 2.74-1.05.56 1.38.21 2.41.11 2.66.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.81-4.57 5.06.36.32.69.95.69 1.92v2.84c0 .26.18.57.69.47C19.13 20.63 22 16.78 22 12.25 22 6.58 17.52 2 12 2Z" />
    </svg>
  )
}

function coseLayoutOptions(denseGraphMode: boolean, edgeCount: number): LayoutOptions {
  const veryDense = edgeCount > 120 || denseGraphMode
  return {
    name: 'cose',
    fit: true,
    animate: false,
    idealEdgeLength: veryDense ? 290 : denseGraphMode ? 240 : 170,
    nodeRepulsion: veryDense ? 480000 : denseGraphMode ? 320000 : 160000,
    gravity: veryDense ? 0.22 : 0.4,
    componentSpacing: veryDense ? 160 : denseGraphMode ? 120 : 60,
    padding: veryDense ? 56 : denseGraphMode ? 44 : 24,
    nestingFactor: 0.8,
    numIter: veryDense ? 2200 : 1800,
  }
}

function App() {
  const graphContainerRef = useRef<HTMLDivElement | null>(null)
  const graphRef = useRef<Core | null>(null)
  const cyRef = useRef<Core | null>(null)
  const [graph, setGraph] = useState<CommunicationGraph | null>(null)
  const [selectedFileName, setSelectedFileName] = useState('')
  const [error, setError] = useState('')
  const [isParsing, setIsParsing] = useState(false)
  const [selectedNodeIp, setSelectedNodeIp] = useState<string | null>(null)
  const [geoDetails, setGeoDetails] = useState<GeoDetails | null>(null)
  const [isFetchingGeo, setIsFetchingGeo] = useState(false)
  const [theme, setTheme] = useState<UiTheme>(() => getInitialTheme())

  function setUiTheme(next: UiTheme) {
    setTheme(next)
    applyThemeToDocument(next)
  }

  const denseGraphMode = useMemo(() => {
    if (!graph) {
      return false
    }

    return graph.nodes.length > 8 || graph.edges.length > 14
  }, [graph])

  const layoutOpts = useMemo(() => {
    if (!graph) {
      return null
    }
    return coseLayoutOptions(denseGraphMode, graph.edges.length)
  }, [graph, denseGraphMode])

  const runRelayout = useCallback(() => {
    const cy = cyRef.current
    const opts = layoutOpts
    if (!cy || !opts) {
      return
    }
    cy.layout(opts).run()
  }, [layoutOpts])

  const graphZoomIn = useCallback(() => {
    const cy = cyRef.current
    if (!cy) {
      return
    }
    const z = cy.zoom()
    cy.zoom({ level: Math.min(z * 1.25, cy.maxZoom()), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
  }, [])

  const graphZoomOut = useCallback(() => {
    const cy = cyRef.current
    if (!cy) {
      return
    }
    const z = cy.zoom()
    cy.zoom({ level: Math.max(z / 1.25, cy.minZoom()), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
  }, [])

  const graphFit = useCallback(() => {
    cyRef.current?.fit(undefined, 48)
  }, [])

  const focusNodeOnGraph = useCallback((ip: string) => {
    const cy = cyRef.current
    if (!cy) {
      return
    }
    const node = cy.getElementById(ip)
    if (node.empty()) {
      return
    }
    cy.batch(() => {
      cy.nodes().unselect()
      cy.edges().removeClass('reveal-label')
      node.select()
      if (denseGraphMode) {
        node.addClass('reveal-label')
      }
    })
    cy.animate({ fit: { eles: node, padding: 72 }, duration: 220, easing: 'ease-out-cubic' })
  }, [denseGraphMode])

  useEffect(() => {
    if (!graphContainerRef.current || !graph || !layoutOpts) {
      return
    }

    graphRef.current?.destroy()
    cyRef.current = null

    const elements: ElementDefinition[] = []

    for (const node of graph.nodes) {
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

    for (const flow of graph.edges) {
      elements.push({
        data: {
          id: flow.id,
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
      style: buildCytoscapeStyles(theme, denseGraphMode),
      layout: layoutOpts,
      minZoom: 0.12,
      maxZoom: 3.2,
      wheelSensitivity: 0.18,
    })

    if (graphRef.current) {
      const cy = graphRef.current
      cyRef.current = cy

      cy.on('tap', 'node', (event) => {
        const node = event.target
        const nodeIp = node.data('id') as string
        if (denseGraphMode) {
          node.addClass('reveal-label')
        }
        setSelectedNodeIp(nodeIp)
        setGeoDetails(null)
        setIsFetchingGeo(true)
        cy.animate({ fit: { eles: node, padding: 72 }, duration: 220, easing: 'ease-out-cubic' })
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
      cyRef.current = null
      graphRef.current?.destroy()
      graphRef.current = null
    }
  }, [graph, denseGraphMode, layoutOpts, theme])

  const topTalkers = useMemo(() => {
    if (!graph) {
      return []
    }

    return [...graph.nodes]
      .sort((a, b) => b.totalBytes - a.totalBytes)
      .slice(0, 12)
  }, [graph])

  const exportBase = useMemo(() => {
    const stem = selectedFileName.replace(/\.[^.]+$/i, '').trim() || 'capture'
    const safe = stem.replace(/[^\w\s.-]/g, '_').replace(/\s+/g, '_').slice(0, 96)
    return safe || 'capture'
  }, [selectedFileName])

  const publicIpCount = useMemo(() => {
    if (!graph) {
      return 0
    }
    return getPublicGraphNodes(graph).length
  }, [graph])

  const downloadPublicIpsCsv = useCallback(() => {
    if (!graph) {
      return
    }
    downloadTextFile(
      `${exportBase}_public_ips.csv`,
      buildPublicIpsCsv(graph),
      'text/csv;charset=utf-8',
    )
  }, [graph, exportBase])

  const downloadFlowsCsv = useCallback(() => {
    if (!graph) {
      return
    }
    downloadTextFile(
      `${exportBase}_flows.csv`,
      buildFlowsCsv(graph),
      'text/csv;charset=utf-8',
    )
  }, [graph, exportBase])

  const downloadGraphJson = useCallback(() => {
    if (!graph) {
      return
    }
    downloadTextFile(
      `${exportBase}_graph.json`,
      buildGraphJson(graph),
      'application/json;charset=utf-8',
    )
  }, [graph, exportBase])

  const downloadGraphPng = useCallback(() => {
    const cy = cyRef.current
    if (!cy) {
      return
    }
    const bg = theme === 'dark' ? '#000000' : '#f2f2f6'
    const dataUrl = cy.png({ full: true, scale: 2, bg })
    downloadDataUrl(`${exportBase}_graph.png`, dataUrl)
  }, [exportBase, theme])

  function handleTalkerActivate(ip: string) {
    focusNodeOnGraph(ip)
    setSelectedNodeIp(ip)
    setGeoDetails(null)
    setIsFetchingGeo(true)
    void fetchGeoDetails(ip).then((details) => {
      setGeoDetails(details)
      setIsFetchingGeo(false)
    })
  }

  async function handleFileChange(file: File | null) {
    if (!file) {
      return
    }

    setIsParsing(true)
    setError('')
    setSelectedFileName(file.name)

    try {
      const arrayBuffer = await file.arrayBuffer()
      const result = parsePcapFileToGraph(arrayBuffer)
      setGraph(result)
    } catch (caughtError) {
      const message =
        caughtError instanceof Error ? caughtError.message : 'Unknown parsing error occurred.'
      setGraph(null)
      setError(message)
    } finally {
      setIsParsing(false)
    }
  }

  return (
    <main className="page-shell">
      <header className="hero-banner">
        <div className="hero-top">
          <p className="eyebrow">Analyze Network Traffic</p>
          <div className="hero-actions">
            <div className="theme-switch" role="group" aria-label="Color theme">
              <button
                type="button"
                className={theme === 'light' ? 'is-active' : ''}
                aria-pressed={theme === 'light'}
                onClick={() => setUiTheme('light')}
              >
                Light
              </button>
              <button
                type="button"
                className={theme === 'dark' ? 'is-active' : ''}
                aria-pressed={theme === 'dark'}
                onClick={() => setUiTheme('dark')}
              >
                Dark
              </button>
            </div>

            <a
              className="github-link"
              href="https://github.com/ramz-021002/packet-sniffer"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="View packet-sniffer repository on GitHub"
            >
              <GitHubMark />
              <span className="github-link__content">
                <span className="github-link__label">View on GitHub</span>
                <span className="github-link__repo">github.com/ramz-021002/packet-sniffer</span>
              </span>
            </a>
          </div>
        </div>
        <h1>Network Packet Analyzer</h1>
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

      {graph && (
        <>
          <section className="metrics" aria-label="Capture metrics">
            <article>
              <h2>Packets In File</h2>
              <p>{graph.summary.totalPackets}</p>
            </article>
            <article>
              <h2>IPv4 Packets Seen</h2>
              <p>{graph.summary.ipv4Packets}</p>
            </article>
            <article>
              <h2>Graphable Packets</h2>
              <p>{graph.summary.processedPackets}</p>
            </article>
            <article>
              <h2>Conversations</h2>
              <p>{graph.summary.edgeCount}</p>
            </article>
            <article>
              <h2>Unique Hosts</h2>
              <p>{graph.summary.nodeCount}</p>
            </article>
            <article>
              <h2>Traffic Volume</h2>
              <p>{formatBytes(graph.summary.bytes)}</p>
            </article>
          </section>

          <section className="card export-card" aria-label="Export downloads">
            <h2>Exports</h2>
            <p className="export-lead">
              CSV and JSON use UTF-8. Public IPs exclude private, loopback, link-local, and multicast
              ranges ({publicIpCount} in this capture).
            </p>
            <div className="export-actions">
              <button type="button" className="export-btn" onClick={downloadPublicIpsCsv}>
                Public IPs (CSV)
              </button>
              <button type="button" className="export-btn" onClick={downloadFlowsCsv}>
                All flows (CSV)
              </button>
              <button type="button" className="export-btn" onClick={downloadGraphJson}>
                Graph (JSON)
              </button>
              <button type="button" className="export-btn" onClick={downloadGraphPng}>
                Graph image (PNG)
              </button>
            </div>
          </section>

          <section className="grid-layout">
            <article className="card graph-card">
              <div className="graph-card-header">
                <div>
                  <h2>Communication Graph</h2>
                  <p className="graph-card-lead">
                    Nodes are IPs; arrows follow packet direction. Scroll to zoom, drag the background
                    to pan.
                  </p>
                </div>
              </div>
              <p className="dense-tip">
                {denseGraphMode
                  ? 'Dense capture: edges are faded until you select one. Pick a host in the inspector or Top Talkers to zoom in.'
                  : 'Select a host to see ISP and location in the inspector.'}
              </p>
              <div className="graph-workspace">
                <div className="graph-frame">
                  <div className="graph-toolbar" role="toolbar" aria-label="Graph view controls">
                    <button type="button" className="graph-tool-btn" onClick={graphFit} title="Fit all">
                      Fit
                    </button>
                    <button type="button" className="graph-tool-btn" onClick={graphZoomOut} title="Zoom out">
                      −
                    </button>
                    <button type="button" className="graph-tool-btn" onClick={graphZoomIn} title="Zoom in">
                      +
                    </button>
                    <button type="button" className="graph-tool-btn graph-tool-btn--accent" onClick={runRelayout} title="Re-run layout">
                      Re-layout
                    </button>
                    <button
                      type="button"
                      className="graph-tool-btn"
                      onClick={downloadGraphPng}
                      title="Download graph as PNG"
                    >
                      PNG
                    </button>
                  </div>
                  <div ref={graphContainerRef} className="graph-canvas" />
                </div>
                <aside className="graph-inspector" aria-label="Host inspector">
                  <h3 className="inspector-title">Inspector</h3>
                  {!selectedNodeIp ? (
                    <p className="inspector-placeholder">
                      Click a node on the graph or an entry in <strong>Top Talkers</strong> to load ISP
                      and location details.
                    </p>
                  ) : (
                    <>
                      <p className="inspector-ip">{selectedNodeIp}</p>
                      {isFetchingGeo ? (
                        <p className="geo-loading">Fetching ISP details…</p>
                      ) : geoDetails ? (
                        <pre className="geo-info">{formatGeoDetails(geoDetails)}</pre>
                      ) : null}
                    </>
                  )}
                </aside>
              </div>
            </article>

            <article className="card talkers-card">
              <h2>Top Talkers</h2>
              <p className="talkers-lead">By total bytes. Click to focus on the graph.</p>
              <ol className="talker-list">
                {topTalkers.map((node) => {
                  const active = selectedNodeIp === node.ip
                  return (
                    <li key={node.ip}>
                      <button
                        type="button"
                        className={`talker-row${active ? ' talker-row--active' : ''}`}
                        onClick={() => handleTalkerActivate(node.ip)}
                      >
                        <span className="talker-row-main">
                          <strong>{node.ip}</strong>
                          <span className="talker-bytes">{formatBytes(node.totalBytes)}</span>
                        </span>
                        <small>
                          {node.outgoingPackets} out / {node.incomingPackets} in packets
                        </small>
                      </button>
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
