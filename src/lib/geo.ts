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

export async function fetchGeoDetails(ip: string): Promise<GeoDetails> {
  if (ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return {
      ip,
      status: 'fail',
      isp: 'Private/Local Network',
    }
  }

  if (geoCache.has(ip)) {
    const cached = geoCache.get(ip)
    return cached as GeoDetails
  }

  const result: GeoDetails = {
    ip,
    status: 'loading',
  }

  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
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
    }

    result.ip = data.ip || ip
    result.isp = data.isp || data.org || 'Unknown ISP'
    result.org = data.org
    result.domain = data.domain
    result.country = data.country_name
    result.city = data.city
    result.region = data.region
    result.timezone = data.timezone
    result.status = 'success'
  } catch (error) {
    result.status = 'fail'
    result.isp = 'Lookup failed'
    if (error instanceof TypeError && error.message.includes('AbortSignal')) {
      result.isp = 'Lookup timed out'
    }
  }

  geoCache.set(ip, result)
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
