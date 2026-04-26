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
const events = [];

function baseUrl() {
	return currentList() === 'black' ? '/blacklist' : '/whitelist';
}

async function loadList() {
	const res = await fetch(baseUrl());
	if (!res.ok) return;
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
	await loadList();

}

removeBtn.onclick = async () => {
	const ip = ipInputEl.value.trim();
	if (!ip) return;

	await fetch(`${baseUrl()}?ip=${encodeURIComponent(ip)}`, {
		method: 'DELETE'
	});

	ipInputEl.value = '';
	await loadList();
}
refreshBtn.onclick = loadList;
listTypeEl.onchange = loadList;

function renderList(data) {
	if (data == null) {
		return
	}
	listEl.innerHTML = '';

	for (const ip of data) {
		const li = document.createElement('li');
		const button = document.createElement('button');
		button.type = 'button';
		button.textContent = ip.ip;
		li.appendChild(button);

		li.onclick = () => {
			ipInputEl.value = ip.ip;
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
		String(e.iface).toLowerCase().includes(q) ||
		String(e.direction).toLowerCase().includes(q) ||
		String(e.proto).includes(q) ||
		String(e.action).toLowerCase().includes(q) ||
		(e.src || '').toLowerCase().includes(q) ||
		(e.dst || '').toLowerCase().includes(q) ||
		String(e.src_port || '').includes(q) ||
		String(e.dst_port || '').includes(q)
	);
}

function renderRows() {
	rowsEl.innerHTML = '';
	shown = 0;

	for (let i = events.length - 1; i >= 0; i--) {
		const e = events[i];
		if (matchesFilter(e)) appendRow(e);
		if (shown >= cap) break;
	}

	countEl.textContent = shown;
}

function appendRow(e) {
	if (!matchesFilter(e)) return;

	const protoCls = e.proto.toLowerCase();
	const protoLabel = e.proto;

	const actionCls = e.action.toLowerCase();
	const actionLabel = e.action;
	const directionCls = e.direction.toLowerCase();
	const srcPort = e.src_port ? e.src_port : '-';
	const dstPort = e.dst_port ? e.dst_port : '-';

	const tr = document.createElement('tr');
	tr.innerHTML =
		`
		<td class="right"> ${e.seq}</td>
		<td>${e.iface || e.ifindex || ''}</td>
		<td><span class="direction ${directionCls}">${e.direction}</span></td>
		<td><span class="proto ${protoCls}">${protoLabel}</span></td>
		<td><span class="action ${actionCls}">${actionLabel}</span></td>
		<td>${e.src}</td>
		<td class="right">${srcPort}</td>
		<td>${e.dst}</td>
		<td class="right">${dstPort}</td>
		<td class="right">${e.time}</td>
	`;

	rowsEl.prepend(tr);
	shown++;
	countEl.textContent = shown;

	while (rowsEl.children.length > cap) rowsEl.removeChild(rowsEl.lastChild);
}

function addRow(e) {
	if (paused) return;
	events.unshift(e);
	while (events.length > cap * 3) events.pop();
	renderRows();
}
toggleBtn.addEventListener('click', () => {
	paused = !paused;
	toggleBtn.textContent = paused ? "Resume" : "Pause";
	toggleBtn.classList.toggle('btn-ghost', paused);
});

clearBtn.addEventListener('click', () => {
	rowsEl.innerHTML = '';
	events.length = 0;
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
	renderRows();
});

filterEl.addEventListener('input', () => {
	renderRows();
})

const es = new EventSource(`${window.location.origin}/events`);
es.onopen = () => setStatus(true)
es.onerror = () => setStatus(false)
es.onmessage = (msg) => {
	try { addRow(JSON.parse(msg.data)); } catch (_) { }
};
