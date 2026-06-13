function url(type) {
  if (type === "black") return "/blacklist";
  if (type === "white") return "/whitelist";
  if (type === "local") return "/onlylocal";
  return "/blacklist";
}

export async function fetchList(type) {
  const res = await fetch(url(type));
  return res.ok ? res.json() : [];
}

export async function addIP(type, ip) {
  const res = await fetch(url(type), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function removeIP(type, ip) {
  const res = await fetch(`${url(type)}?ip=${encodeURIComponent(ip)}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function fetchNetworkDevices() {
  const res = await fetch("/network/devices");
  return res.ok ? res.json() : [];
}

export async function fetchLocalNets() {
  const [v4, v6] = await Promise.all([
    fetch("/network/localnets/v4"),
    fetch("/network/localnets/v6"),
  ]);

  return {
    v4: v4.ok ? (await v4.json()) || [] : [],
    v6: v6.ok ? (await v6.json()) || [] : [],
  };
}

export async function fetchRuntimeState() {
  const res = await fetch("/runtime/state");
  return res.ok ? res.json() : { mockMode: false };
}

export async function fetchMetricsText() {
  const res = await fetch("/metrics");
  return res.ok ? res.text() : "";
}

export async function fetchAppLogs(limit = 200) {
  const res = await fetch(`/app/logs?limit=${encodeURIComponent(limit)}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function inspectPacket(packet) {
  const res = await fetch("/packet/inspect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(packet),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchAnalysisSummary(limit = 50) {
  const res = await fetch(`/analysis/summary?limit=${encodeURIComponent(limit)}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchHostAnalysis(ip, limit = 50) {
  const res = await fetch(`/analysis/host?ip=${encodeURIComponent(ip)}&limit=${encodeURIComponent(limit)}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchKnownHosts() {
  const res = await fetch("/analysis/hosts");
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function generateAnalysisReport({ ip = "", limit = 5 } = {}) {
  const res = await fetch("/analysis/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, limit }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
