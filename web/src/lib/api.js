function url(type) {
  return type === 'black' ? '/blacklist' : '/whitelist'
}

export async function fetchList(type) {
  const res = await fetch(url(type))
  return res.ok ? res.json() : []
}

export async function addIP(type, ip) {
  await fetch(url(type), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  })
}

export async function removeIP(type, ip) {
  await fetch(`${url(type)}?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' })
}