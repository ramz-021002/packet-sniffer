import type cytoscape from 'cytoscape'
import type { UiTheme } from '../theme'

export function buildCytoscapeStyles(
  theme: UiTheme,
  denseGraphMode: boolean,
): cytoscape.CytoscapeOptions['style'] {
  const isDark = theme === 'dark'

  const nodeLabelColor = isDark ? '#f5f5f5' : '#18181b'
  const nodeLabelBg = isDark ? '#171717' : '#ffffff'
  const nodeFill = isDark ? '#525252' : '#6366f1'
  const nodeBorder = isDark ? '#a3a3a3' : '#818cf8'

  const edgeLabelColor = isDark ? '#c4c4c4' : '#3f3f46'
  const edgeLine = isDark ? '#404040' : '#a1a1aa'
  const edgeArrow = isDark ? '#5c5c5c' : '#737373'
  const edgeLabelBg = isDark ? '#0a0a0a' : '#fafafa'
  const denseOpacity = denseGraphMode ? (isDark ? 0.38 : 0.42) : isDark ? 0.72 : 0.78
  const normalOpacity = isDark ? 0.72 : 0.88

  return [
    {
      selector: 'node',
      style: {
        label: denseGraphMode ? '' : 'data(label)',
        'font-family': '"DM Sans", sans-serif',
        'font-size': 11,
        'font-weight': 600,
        color: nodeLabelColor,
        'text-wrap': 'none' as const,
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 14,
        'text-background-color': nodeLabelBg,
        'text-background-opacity': isDark ? 0.92 : 0.94,
        'text-background-shape': 'roundrectangle',
        'text-background-padding': '3px',
        'background-color': nodeFill,
        'border-width': 2,
        'border-color': nodeBorder,
        width: 'mapData(traffic, 1, 3000, 22, 64)',
        height: 'mapData(traffic, 1, 3000, 22, 64)',
      },
    },
    {
      selector: 'edge',
      style: {
        label: denseGraphMode ? '' : 'data(label)',
        'font-family': '"JetBrains Mono", monospace',
        'font-size': 9,
        color: edgeLabelColor,
        width: 'mapData(packets, 1, 200, 1, 6)',
        'line-color': edgeLine,
        'target-arrow-color': edgeArrow,
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 0.75,
        'line-opacity': denseGraphMode ? denseOpacity : normalOpacity,
        'text-background-color': edgeLabelBg,
        'text-background-opacity': isDark ? 0.88 : 0.92,
        'text-background-padding': '2px',
      },
    },
    {
      selector: 'edge:selected',
      style: {
        'overlay-opacity': 0,
        'line-opacity': 1,
        width: 'mapData(packets, 1, 200, 2, 9)',
        'line-color': '#f59e0b',
        'target-arrow-color': '#f59e0b',
        color: isDark ? '#fef3c7' : '#78350f',
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
      selector: 'node:selected',
      style: {
        'overlay-opacity': 0,
        'border-color': '#f59e0b',
        'border-width': 3,
        'background-color': isDark ? '#737373' : '#818cf8',
      },
    },
  ]
}
