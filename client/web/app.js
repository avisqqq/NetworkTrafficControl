const statusEl = document.getElementById('status');
const filterEl = document.getElementById('filter');
const toggleBtn = document.getElementById('toggle');
const clearBtn = document.getElementById('clear');
const capEl = document.getElementById('cap');
const countEl = document.getElementById('count');
const rowsEl = document.getElementById('rows');

let paused = false;
let cap = 300;
let shown = 0;
const t0 = performance.now();


function setStatus(ok) {
	statusEl.className = 'pill ' + (ok ? 'ok' : 'bad')
	statusEl.textContent = ok ? 'Connected' : 'Disconnected'
}

function protoLable(p) {
	if (p === 6) return ['tcp', 'TCP'];
	if (p === 17) return ['udp', 'UDP'];
	if (p === 1) return ['icmp', 'ICMP'];
	return ['', 'P' + p];
}

function matchesFilter(e) {
	const q = (filterEl.value || '').trim().toLowerCase();
	if (!q) return true;
	return (
		String(e.seq).includes(q) ||
		String(e.proto).includes(q) ||
		(e.src || '').toLowerCase.includes(q) ||
		(e.dst || '').toLowerCase.includes(q)
	);
}

function addRow(e) {
	if (paused) return;
	if (!matchesFilter(e)) return;

	const [cls, label] = protoLable(e.proto)
	const ageMs = Math.max(0, Math.round(performance.now() - t0));
	const tr = document.createElement('tr');
	tr.innerHTML =
		`
		<td class="right"> ${e.seq}</td>
		<td><span class="proto ${cls}">${label}</span></td>
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

const es = new EventSource('/events');
es.onopen = () => setStatus(true)
es.onerror = () => setStatus(false)
es.onmessage = (msg) => {
	try { addRow(JSON.parse(msg.data)); } catch (_) { }
};

