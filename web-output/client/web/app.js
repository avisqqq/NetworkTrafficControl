const statusEl = document.getElementById('status');
const filterEl = document.getElementById('filter');
const toogleBtn = document.getElementById('toggle');
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

	const [cls, label] = protoLable()
}
