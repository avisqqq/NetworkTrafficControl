function url(type) {
  return type === 'black' ? '/blacklist' : '/whitelist'
}

export async function fetchList(type) {
  const res = await fetch(url(type))
  return res.ok ? res.json() : []
}

export async function addIP(type, ip) {
  const res = await fetch(url(type), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  })
  if (!res.ok) throw new Error(await res.text())
}

export async function removeIP(type, ip) {
  const res = await fetch(`${url(type)}?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(await res.text())
}

export async function fetchNetworkDevices() {
  const res = await fetch('/network/devices')
  return res.ok ? res.json() : []
}
