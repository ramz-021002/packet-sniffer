# PCAP Communication Atlas

Browser-first packet analysis UI for classic `.pcap` files.

Upload a packet capture and the app will:

- Parse packet records in-browser (no server needed)
- Decode Ethernet + IPv4 traffic
- Aggregate directional host-to-host communication flows
- Render an interactive IP communication graph
- Show capture metrics and top talkers

## Tech Stack

- React + TypeScript + Vite
- Cytoscape.js for network graph visualization
- Pure TypeScript parser for classic PCAP files

## Quick Start

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

## Deployment Options

### 1) GitHub Pages (Automatic via GitHub Actions)

This repository includes [`.github/workflows/deploy-github-pages.yml`](.github/workflows/deploy-github-pages.yml).

Setup:

1. Push to `main`.
2. In GitHub repo settings, enable Pages and select `GitHub Actions` as source.
3. The workflow builds and deploys `dist/` automatically.

The workflow dynamically sets Vite `base` to `/<repo-name>/`.

## Parser Scope

Current parser support:

- Classic `.pcap` format
- Ethernet link type (`LINKTYPE_ETHERNET`)
- IPv4 frames
- Protocol identification: TCP, UDP, ICMP, OTHER

Not yet supported:

- `.pcapng`
- Non-Ethernet captures
- Deep protocol dissection beyond IPv4 source/destination flow mapping

## Useful Scripts

- `npm run dev`: start local development server
- `npm run build`: production build
- `npm run build:gh`: GitHub Pages-oriented build (uses `VITE_BASE_PATH`)
- `npm run preview`: preview production build locally
