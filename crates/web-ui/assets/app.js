// Q-EVM gas lab: every number on the page comes from the node's API.
const $ = (id) => document.getElementById(id);
const fmt = (n) => Math.round(n).toLocaleString('en-US');

function countUp(el, to, { decimals = 0, suffix = '' } = {}) {
  const from = Number(el.dataset.v || 0);
  el.dataset.v = to;
  if (from === to && el.textContent !== '—') return;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / 1100);
    const v = from + (to - from) * (1 - Math.pow(1 - t, 4));
    el.textContent = (decimals ? v.toFixed(decimals) : fmt(v)) + suffix;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  el.classList.remove('flash');
  void el.offsetWidth;
  el.classList.add('flash');
}

const setText = (id, text) => ($(id).textContent = text);
const width = (id, pct) => ($(id).style.width = Math.max(0.6, Math.min(100, pct)) + '%');

function render(a) {
  const p = a.paper;
  setText('p-native', fmt(p.native_gas));
  setText('p-onchain', fmt(p.groth16_gas));
  setText('p-red', p.reduction_percent.toFixed(1) + '%');
  setText('p-saved', fmt(p.native_gas - p.groth16_gas));
  setText('p-batch', fmt(p.batched_gas_per_tx));
  setText('st-samples', a.samples);
  if (!a.measured) return;

  countUp($('native-avg'), a.native_avg);
  countUp($('onchain-avg'), a.onchain_avg);
  countUp($('reduction'), a.reduction_percent, { decimals: 1, suffix: '%' });
  setText('saved', `${fmt(a.gas_saved_avg)} gas saved per op`);

  width('bar-native', 100);
  width('bar-onchain', (a.onchain_avg / a.native_avg) * 100);
  setText('bar-native-val', fmt(a.native_avg) + ' gas');
  setText('bar-onchain-val', fmt(a.onchain_avg) + ' gas');

  countUp($('ops-native'), a.native_ops_per_block);
  countUp($('ops-onchain'), a.zkvm_ops_per_block);
  countUp($('prove-ms'), a.prove_time_ms_avg, { decimals: 1, suffix: ' ms' });
  setText('minmax', `${fmt(a.onchain_min)} / ${fmt(a.onchain_max)}`);

  setText('c-native', fmt(a.native_avg));
  setText('c-onchain', fmt(a.onchain_avg));
  setText('c-red', a.reduction_percent.toFixed(1) + '%');
  setText('c-saved', fmt(a.gas_saved_avg));

  const b = a.last_batch;
  if (b) {
    countUp($('b-size'), b.size);
    countUp($('b-gas'), b.onchain_gas.total);
    countUp($('b-per-op'), b.amortized_gas_per_op);
    setText('b-vs', `${(a.onchain_avg / b.amortized_gas_per_op).toFixed(1)}× cheaper`);
    width('bar-batch', (b.amortized_gas_per_op / a.native_avg) * 100);
    setText('bar-batch-val', `${fmt(b.amortized_gas_per_op)} gas/op ×${b.size}`);
    setText('c-batch', `${fmt(b.amortized_gas_per_op)} (×${b.size})`);
  }
}

async function refreshGas() {
  try {
    const res = await fetch('/api/gas-analysis');
    if (res.ok) render(await res.json());
  } catch (_) { /* node offline: keep last values */ }
}

async function refreshStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const s = await res.json();
    setText('st-mempool', s.mempool_len);
    setText('st-batch', s.last_batch_size ? `${s.last_batch_size} ops` : '—');
  } catch (_) { /* ignore */ }
}

function feedRow(cls, cells) {
  const feed = $('feed');
  feed.querySelector('.empty')?.remove();
  const li = document.createElement('li');
  li.className = cls;
  li.innerHTML = cells.map((c, i) => `<span${i === 1 ? ' class="hash"' : ''}>${c}</span>`).join('');
  feed.prepend(li);
  while (feed.children.length > 60) feed.lastChild.remove();
}

let gasTimer = null;
function connectEvents() {
  const source = new EventSource('/api/events');
  source.onopen = () => {
    $('live').classList.add('on');
    setText('live-text', 'live');
  };
  source.onerror = () => {
    $('live').classList.remove('on');
    setText('live-text', 'reconnecting');
  };
  source.onmessage = (msg) => {
    const e = JSON.parse(msg.data);
    const time = new Date().toLocaleTimeString('en-GB');
    if (e.type === 'accepted') {
      feedRow('', [time, e.op_hash, fmt(e.native_gas), fmt(e.onchain_gas), e.prove_time_ms.toFixed(1) + ' ms']);
    } else if (e.type === 'rejected') {
      feedRow('rejected', [time, e.op_hash, '—', '—', e.reason]);
    } else if (e.type === 'batch' && e.gas) {
      const g = e.gas;
      feedRow('batch', [time, `batch ×${e.size}`, '—', fmt(g.amortized_gas_per_op) + '/op', g.prove_time_ms.toFixed(1) + ' ms']);
    }
    clearTimeout(gasTimer);
    gasTimer = setTimeout(refreshGas, 250);
    refreshStatus();
  };
}

const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
$('demo-btn').addEventListener('click', async () => {
  const btn = $('demo-btn');
  const count = Number($('demo-count').value);
  btn.disabled = true;
  let i = 0;
  const spin = setInterval(() => (btn.textContent = `${spinner[i++ % spinner.length]} proving ${count}`), 80);
  try {
    const res = await fetch('/api/demo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ count }),
    });
    if (!res.ok) throw new Error(await res.text());
    const out = await res.json();
    render(out.analysis);
    setText('demo-hint', `${out.accepted}/${out.submitted} ops proven and verified on the EVM.`);
  } catch (err) {
    setText('demo-hint', 'Demo failed: ' + err.message);
  } finally {
    clearInterval(spin);
    btn.textContent = 'Run demo';
    btn.disabled = false;
    refreshStatus();
  }
});

const io = new IntersectionObserver((entries) => {
  entries.forEach((en) => en.isIntersecting && en.target.classList.add('in'));
}, { threshold: 0.08 });
document.querySelectorAll('.reveal').forEach((el) => io.observe(el));

refreshGas();
refreshStatus();
connectEvents();
setInterval(refreshStatus, 3000);
setInterval(refreshGas, 5000);
