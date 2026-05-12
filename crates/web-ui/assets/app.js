const statusPill = document.getElementById('status-pill');
const statusList = document.getElementById('status-list');
const mempoolEl = document.getElementById('mempool');
const eventsEl = document.getElementById('events');

const chartCtx = document.getElementById('metrics-chart');
let metricsChart;

function setStatus(status) {
  statusPill.textContent = status;
}

async function fetchStatus() {
  try {
    const response = await fetch('/api/status');
    if (!response.ok) throw new Error('status unavailable');
    const data = await response.json();
    setStatus('Node Online');
    statusList.innerHTML = '';
    const entries = {
      'Mempool size': data.mempool_len,
      'Last batch id': data.last_batch_id ?? '—',
      'Last batch size': data.last_batch_size,
    };
    Object.entries(entries).forEach(([label, value]) => {
      const item = document.createElement('li');
      item.textContent = `${label}: ${value}`;
      statusList.appendChild(item);
    });
    updateChart(data);
  } catch (err) {
    setStatus('Disconnected');
  }
}

async function fetchMempool() {
  try {
    const response = await fetch('/api/mempool');
    if (!response.ok) throw new Error('mempool unavailable');
    const data = await response.json();
    mempoolEl.innerHTML = '';
    if (data.length === 0) {
      mempoolEl.innerHTML = '<div class="mempool-item">Mempool empty</div>';
      return;
    }
    data.slice(0, 5).forEach((op) => {
      const item = document.createElement('div');
      item.className = 'mempool-item';
      item.textContent = `${op.sender} • nonce ${op.nonce}`;
      mempoolEl.appendChild(item);
    });
  } catch (err) {
    mempoolEl.innerHTML = '<div class="mempool-item">Mempool unavailable</div>';
  }
}

function updateChart(status) {
  const labels = metricsChart?.data.labels ?? [];
  const values = metricsChart?.data.datasets[0]?.data ?? [];
  labels.push(new Date().toLocaleTimeString());
  values.push(status.mempool_len);
  if (labels.length > 12) {
    labels.shift();
    values.shift();
  }
  if (!metricsChart) {
    metricsChart = new Chart(chartCtx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Mempool size',
            data: values,
            borderColor: '#38bdf8',
            backgroundColor: 'rgba(56, 189, 248, 0.2)',
            tension: 0.3,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
        },
        scales: {
          x: { ticks: { color: '#94a3b8' } },
          y: { ticks: { color: '#94a3b8' }, beginAtZero: true },
        },
      },
    });
  } else {
    metricsChart.update();
  }
}

function addEvent(message) {
  const entry = document.createElement('div');
  entry.className = 'event';
  entry.textContent = message;
  eventsEl.prepend(entry);
  const items = eventsEl.querySelectorAll('.event');
  if (items.length > 20) {
    items[items.length - 1].remove();
  }
}

function startEventStream() {
  const source = new EventSource('/api/events');
  source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'accepted') {
      addEvent(`Accepted op ${data.op_hash}`);
    } else if (data.type === 'rejected') {
      addEvent(`Rejected op ${data.op_hash}: ${data.reason}`);
    } else if (data.type === 'batch') {
      addEvent(`Batch ${data.batch_id} created (${data.size} ops)`);
    }
  };
  source.onerror = () => {
    source.close();
    setTimeout(startEventStream, 3000);
  };
}

fetchStatus();
fetchMempool();
setInterval(fetchStatus, 2000);
setInterval(fetchMempool, 3000);
startEventStream();
