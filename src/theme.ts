export type UiTheme = 'light' | 'dark'

const STORAGE_KEY = 'pcap-atlas-theme'

export function getInitialTheme(): UiTheme {
  if (typeof window === 'undefined') {
    return 'light'
  }
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored === 'dark' || stored === 'light') {
    return stored
  }
  if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    return 'dark'
  }
  return 'light'
}

export function applyThemeToDocument(theme: UiTheme): void {
  document.documentElement.dataset.theme = theme
  localStorage.setItem(STORAGE_KEY, theme)
}
