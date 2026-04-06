export interface GeoDetails {
  ip: string
  isp?: string
  org?: string
  domain?: string
  country?: string
  city?: string
  region?: string
  timezone?: string
  status?: 'success' | 'fail' | 'loading'
}

const geoCache = new Map<string, GeoDetails>()

export function isPrivateOrReservedIp(ip: string): boolean {
  if (ip === '::1' || ip === '0.0.0.0') {
    return true
  }

  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) {
    return true
  }

  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) {
    return true
  }

  if (
    ip.startsWith('169.254.') ||
    ip.startsWith('100.64.') ||
    ip.startsWith('224.') ||
    ip.startsWith('255.')
  ) {
    return true
  }

  if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) {
    return true
  }

  return false
}

async function fetchFromIpApiCo(ip: string): Promise<GeoDetails | null> {
  const response = await fetch(`https://ipapi.co/${ip}/json/`, {
    signal: AbortSignal.timeout(5000),
  })

  if (!response.ok) {
    throw new Error(`ipapi.co HTTP ${response.status}`)
  }

  const data = (await response.json()) as {
    ip?: string
    isp?: string
    org?: string
    domain?: string
    asn?: string
    country_name?: string
    city?: string
    region?: string
    timezone?: string
    error?: boolean
    reason?: string
  }

  if (data.error) {
    throw new Error(data.reason || 'ipapi.co lookup failed')
  }

  return {
    ip: data.ip || ip,
    isp: data.isp || data.org || data.asn || 'Unknown ISP',
    org: data.org,
    domain: data.domain,
    country: data.country_name,
    city: data.city,
    region: data.region,
    timezone: data.timezone,
    status: 'success',
  }
}

async function fetchFromIpWhoIs(ip: string): Promise<GeoDetails | null> {
  const response = await fetch(`https://ipwho.is/${ip}`, {
    signal: AbortSignal.timeout(5000),
  })

  if (!response.ok) {
    throw new Error(`ipwho.is HTTP ${response.status}`)
  }

  const data = (await response.json()) as {
    success?: boolean
    ip?: string
    connection?: {
      isp?: string
      org?: string
      domain?: string
      asn?: number
    }
    country?: string
    city?: string
    region?: string
    timezone?: {
      id?: string
    }
    message?: string
  }

  if (data.success === false) {
    throw new Error(data.message || 'ipwho.is lookup failed')
  }

  return {
    ip: data.ip || ip,
    isp: data.connection?.isp || data.connection?.org || 'Unknown ISP',
    org: data.connection?.org,
    domain: data.connection?.domain,
    country: data.country,
    city: data.city,
    region: data.region,
    timezone: data.timezone?.id,
    status: 'success',
  }
}

async function fetchFromIpInfo(ip: string): Promise<GeoDetails | null> {
  const response = await fetch(`https://ipinfo.io/${ip}/json`, {
    signal: AbortSignal.timeout(5000),
  })

  if (!response.ok) {
    throw new Error(`ipinfo.io HTTP ${response.status}`)
  }

  const data = (await response.json()) as {
    ip?: string
    city?: string
    region?: string
    country?: string
    org?: string
    timezone?: string
    hostname?: string
    bogon?: boolean
  }

  if (data.bogon) {
    throw new Error('ipinfo.io reported bogon address')
  }

  return {
    ip: data.ip || ip,
    isp: data.org || 'Unknown ISP',
    org: data.org,
    domain: data.hostname,
    country: data.country,
    city: data.city,
    region: data.region,
    timezone: data.timezone,
    status: 'success',
  }
}

export async function fetchGeoDetails(ip: string): Promise<GeoDetails> {
  const normalizedIp = ip.trim()

  if (isPrivateOrReservedIp(normalizedIp)) {
    return {
      ip: normalizedIp,
      status: 'fail',
      isp: 'Private/Local Network',
    }
  }

  if (geoCache.has(normalizedIp)) {
    const cached = geoCache.get(normalizedIp)
    return cached as GeoDetails
  }

  const result: GeoDetails = {
    ip: normalizedIp,
    status: 'loading',
  }

  const providers: Array<(address: string) => Promise<GeoDetails | null>> = [
    fetchFromIpApiCo,
    fetchFromIpWhoIs,
    fetchFromIpInfo,
  ]
  const providerErrors: string[] = []

  try {
    for (const provider of providers) {
      try {
        const providerResult = await provider(normalizedIp)
        if (providerResult?.status === 'success') {
          geoCache.set(normalizedIp, providerResult)
          return providerResult
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown provider error'
        providerErrors.push(message)
        // Try next provider.
      }
    }

    result.status = 'fail'
    result.isp =
      providerErrors.length > 0
        ? `Lookup failed for all providers (${providerErrors[0]})`
        : 'Lookup failed for all providers'
  } catch (error) {
    result.status = 'fail'
    result.isp = 'Lookup failed'
    if (error instanceof Error && error.name === 'TimeoutError') {
      result.isp = 'Lookup timed out'
    }
  }

  return result
}

export function formatGeoDetails(geo: GeoDetails): string {
  const parts = []

  if (geo.isp) {
    parts.push(`ISP: ${geo.isp}`)
  }

  if (geo.domain) {
    parts.push(`Domain: ${geo.domain}`)
  }

  if (geo.country) {
    const location = [geo.city, geo.region, geo.country].filter(Boolean).join(', ')
    if (location) {
      parts.push(`Location: ${location}`)
    }
  }

  if (geo.timezone) {
    parts.push(`Timezone: ${geo.timezone}`)
  }

  return parts.length > 0 ? parts.join('\n') : 'No details available'
}
