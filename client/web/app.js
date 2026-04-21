const statusEl = document.getElementById('status');
const filterEl = document.getElementById('filter');
const toggleBtn = document.getElementById('toggle');
const clearBtn = document.getElementById('clear');
const capEl = document.getElementById('cap');
const countEl = document.getElementById('count');
const rowsEl = document.getElementById('rows');
const listTypeEl = document.getElementById('listType');
const ipInputEl = document.getElementById('ipInput');
const addBtn = document.getElementById('addBtn');
const removeBtn = document.getElementById('removeBtn');
const refreshBtn = document.getElementById('refreshBtn');
const listEl = document.getElementById('listEntries');

function currentList() {
	return listTypeEl.value;
}

let paused = false;
let cap = 300;
let shown = 0;
const t0 = performance.now();

function baseUrl() {
	return currentList() === 'black' ? '/blacklist' : '/whitelist';
}

async function loadList() {
	const res = await fetch((baseUrl()));
	const data = await res.json();
	renderList(data);
}
loadList();
addBtn.onclick = async () => {
	const ip = ipInputEl.value.trim();
	if (!ip) return;

	await fetch(baseUrl(), {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ ip })
	});

	ipInputEl.value = '';
	loadList();

}

removeBtn.onclick = async () => {
	const ip = ipInputEl.value.trim();
	if (!ip) return;

	await fetch(`${baseUrl()}?ip=${encodeURIComponent(ip)}`, {
		method: 'DELETE'
	});

	ipInputEl.value = '';
	loadList();
}
refreshBtn.onclick = loadList();
listTypeEl.onchange = loadList();

function renderList(data) {
	if (data == null) {
		return
	}
	listEl.innerHTML = '';

	for (const ip of data) {
		const li = document.createElement('li');
		li.textContent = ip;

		li.onclick = () => {
			ipInputEl.value = ip;
		};

		listEl.appendChild(li);
	}
}

function setStatus(ok) {
	statusEl.className = 'pill ' + (ok ? 'ok' : 'bad')
	statusEl.textContent = ok ? 'Connected' : 'Disconnected'
}


function matchesFilter(e) {
	const q = (filterEl.value || '').trim().toLowerCase();
	if (!q) return true;
	return (
		String(e.seq).includes(q) ||
		String(e.proto).includes(q) ||
		(e.src || '').toLowerCase().includes(q) ||
		(e.dst || '').toLowerCase().includes(q)
	);
}

function addRow(e) {
	if (paused) return;
	if (!matchesFilter(e)) return;

	const protoCls = e.proto.toLowerCase();
	const protoLabel = e.proto;

	const actionCls = e.action.toLowerCase();
	const actionLabel = e.action;

	const ageMs = Math.max(0, Math.round(performance.now() - t0));
	const tr = document.createElement('tr');
	tr.innerHTML =
		`
		<td class="right"> ${e.seq}</td>
		<td><span class="proto ${protoCls}">${protoLabel}</span></td>
		<td><span class="action ${actionCls}">${actionLabel}</span></td>
		<td>${e.src}</td>
		<td>${e.dst}</td>
		<td class="right">${ageMs}ms</td>
	`;

	rowsEl.prepend(tr);
	shown++;
	countEl.textContent = shown;

	while (rowsEl.children.length > cap) rowsEl.removeChild(rowsEl.lastChild);
}
toggleBtn.addEventListener('click', () => {
	paused = !paused;
	toggleBtn.textContent = paused ? "Resume" : "Pause";
	toggleBtn.classList.toggle('btn-ghost', paused);
});

clearBtn.addEventListener('click', () => {
	rowsEl.innerHTML = '';
	shown = 0;
	countEl.textContent = '0';
});

capEl.addEventListener('change', () => {
	const n = parseInt(capEl.value, 10);
	if (!Number.isFinite(n) || n < 10 || n > 5000) {
		capEl.value = String(cap);
		return
	}
	cap = n;
	while (rowsEl.children.length > cap) rowsEl.removeChild(rowsEl.lastChild);
});

filterEl.addEventListener('input', () => {
	rowsEl.innerHTML = '';
	shown = 0;
	countEl.textContent = '0';
})

const es = new EventSource('http://192.168.0.143:8086/events');
es.onopen = () => setStatus(true)
es.onerror = () => setStatus(false)
es.onmessage = (msg) => {
	try { addRow(JSON.parse(msg.data)); } catch (_) { }
};

