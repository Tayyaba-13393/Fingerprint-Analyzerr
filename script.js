/*
  script.js — Snoopy Net Sniffer
  FR-1 : URL Validation
  FR-6 : Comparison mode
  FR-7 : Chart.js Visualizations (Pie, Histogram, Timeline)
*/
 
'use strict';
 
// ── Chart instances ──────────────────────────────────────────────
let protocolChartInst  = null;
let protocolChartBInst = null;   // Site B pie — compare mode only
let sizeChartInst      = null;
let timelineChartInst  = null;
 
// ── Current mode ('single' | 'compare') ─────────────────────────
let currentMode = 'single';
 
// ── Chart.js palette ─────────────────────────────────────────────
const PALETTE = ['#D93025','#1A2744','#FFD84D','#4CAF50','#87CEEB','#F4A130'];
 
 
// ═══════════════════════════════════════════════════════════════
//  FR-1  URL Validation
// ═══════════════════════════════════════════════════════════════
function validateUrl(url) {
  const regex = /^https?:\/\/([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,})(:[0-9]{1,5})?(\/.*)?$/i;
  return regex.test(url.trim());
}
 
 
// ═══════════════════════════════════════════════════════════════
//  Mode switcher (Analyze / Compare tabs)
// ═══════════════════════════════════════════════════════════════
function switchMode(mode) {
  currentMode = mode;
  document.getElementById('panel-single').style.display  = mode === 'single'  ? '' : 'none';
  document.getElementById('panel-compare').style.display = mode === 'compare' ? '' : 'none';
  document.getElementById('tab-single').classList.toggle('active',  mode === 'single');
  document.getElementById('tab-compare').classList.toggle('active', mode === 'compare');
  hideStatus();
  document.getElementById('results-section').classList.remove('show');
}
 
 
// ═══════════════════════════════════════════════════════════════
//  Status helpers
// ═══════════════════════════════════════════════════════════════
function showStatus(msg, isError = false) {
  const el = document.getElementById('statusBubble');
  el.classList.add('show');
  el.classList.toggle('error', isError);
  document.getElementById('statusSpinner').style.display = isError ? 'none' : '';
  document.getElementById('statusText').textContent = msg;
}
 
function hideStatus() {
  document.getElementById('statusBubble').classList.remove('show');
}
 
function setBtn(disabled) {
  document.getElementById('analyzeBtn').disabled = disabled;
}
 
 
// ═══════════════════════════════════════════════════════════════
//  FR-1 + FR-2→FR-5  Single-site analysis
// ═══════════════════════════════════════════════════════════════
async function startAnalysis() {
  const url = document.getElementById('urlInput').value.trim();
 
  if (!url) {
    showStatus('Good grief! Enter a URL first! 🐾', true); return;
  }
  if (!validateUrl(url)) {
    showStatus('That URL looks ruff… try https://example.com 🐶', true); return;
  }
 
  setBtn(true);
  showStatus('Snoopy is sniffing the network… this takes ~10 seconds 🐾');
  document.getElementById('results-section').classList.remove('show');
  document.getElementById('compareCard').style.display = 'none';
 
  try {
    const res  = await fetch('/api/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });
    const data = await res.json();
 
    if (!res.ok || data.error) {
      showStatus('Woof! Error: ' + (data.error || 'Server error'), true);
      return;
    }
 
    hideStatus();
    renderFingerprint(data);
    renderCharts(data);
    document.getElementById('results-section').classList.add('show');
 
  } catch (err) {
    showStatus('Network error: ' + err.message, true);
  } finally {
    setBtn(false);
  }
}
 
 
// ═══════════════════════════════════════════════════════════════
//  FR-6  Two-site comparison
// ═══════════════════════════════════════════════════════════════
async function startCompare() {
  const urlA = document.getElementById('urlA').value.trim();
  const urlB = document.getElementById('urlB').value.trim();
 
  if (!urlA || !urlB) {
    showStatus('Enter both URLs, Charlie Brown! 🐾', true); return;
  }
  if (!validateUrl(urlA) || !validateUrl(urlB)) {
    showStatus('One or both URLs look invalid! 🐶', true); return;
  }
 
  showStatus('Snoopy is sniffing BOTH sites… ~20 seconds ⏱');
  document.getElementById('results-section').classList.remove('show');
 
  try {
    const res  = await fetch('/api/compare', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ urlA, urlB }),
    });
    const data = await res.json();
 
    if (!res.ok || data.error) {
      showStatus('Error: ' + (data.error || 'Server error'), true); return;
    }
 
    hideStatus();
 
    // Show fingerprint of site A first
    renderFingerprint(data.siteA);
    // Pass BOTH fingerprints so timeline shows two lines (FR-7 compare mode)
    renderCharts(data.siteA, data.siteB);
 
    // Show comparison table
    renderCompareTable(data.siteA, data.siteB, data.diff);
 
    document.getElementById('results-section').classList.add('show');
 
  } catch (err) {
    showStatus('Network error: ' + err.message, true);
  }
}
 
 
// ═══════════════════════════════════════════════════════════════
//  Render fingerprint card
// ═══════════════════════════════════════════════════════════════
function renderFingerprint(fp) {
  document.getElementById('siteLabel').textContent     = fp.site_url || '—';
  document.getElementById('behaviorLabel').textContent = fp.behavior_label || '—';
  document.getElementById('confidenceLabel').textContent = (fp.confidence || 0) + '%';
 
  // Stats grid
  const stats = [
    { icon: '📦', value: (fp.total_packets  || 0).toLocaleString(), label: 'Packets'     },
    { icon: '💾', value: fmtBytes(fp.total_bytes),                   label: 'Total Data'  },
    { icon: '📏', value: (fp.mean_packet_size || 0) + ' B',          label: 'Avg Size'    },
    { icon: '⬆️',  value: (fp.max_packet_size  || 0) + ' B',          label: 'Max Size'    },
    { icon: '🌐', value: (fp.unique_ips || 0).toString(),             label: 'Unique IPs'  },
    { icon: '📡', value: fp.top_protocol || '—',                      label: 'Top Protocol'},
  ];
 
  document.getElementById('fpGrid').innerHTML = stats.map(s => `
    <div class="fp-stat">
      <div class="fp-icon">${s.icon}</div>
      <span class="fp-value">${s.value}</span>
      <div class="fp-label">${s.label}</div>
    </div>`).join('');
 
  // IP pills
  const ips = fp.ip_list || [];
  document.getElementById('ipList').innerHTML = ips.length
    ? ips.map(ip => `<span class="ip-pill">🔵 ${escHtml(ip)}</span>`).join('')
    : '<span style="color:#999;font-weight:700">No IPs captured</span>';
 
  // DNS tags
  const dns = fp.dns_queries || [];
  document.getElementById('dnsList').innerHTML = dns.length
    ? dns.map(d => `<span class="dns-tag">${escHtml(d)}</span>`).join('')
    : '<span style="color:#999;font-weight:700">No DNS queries captured</span>';
}
 
 
// ═══════════════════════════════════════════════════════════════
//  FR-7  Charts  (fpB optional — passed in compare mode for dual-line)
// ═══════════════════════════════════════════════════════════════
function renderCharts(fp, fpB = null) {
  destroyCharts();
 
  const isCompare = fpB !== null;
 
  // Show/hide Site B pie canvas
  document.getElementById('pieCardB').style.display = isCompare ? '' : 'none';
  document.getElementById('pieLabelA').textContent  = isCompare ? '— ' + fp.site_url  + ' (A)' : '';
  document.getElementById('pieLabelB').textContent  = isCompare ? '— ' + fpB.site_url + ' (B)' : '';
 
  // 1a. Pie — Site A Protocol Mix
  const proto = fp.protocol_distribution || [];
  if (proto.length) {
    protocolChartInst = new Chart(
      document.getElementById('protocolChart').getContext('2d'),
      {
        type: 'doughnut',
        data: {
          labels:   proto.map(p => p.name),
          datasets: [{ data: proto.map(p => p.value), backgroundColor: PALETTE, borderColor: '#1A2744', borderWidth: 2 }],
        },
        options: {
          cutout: '55%',
          plugins: { legend: { labels: { font: { family: "'Nunito', sans-serif", weight: '700' }, color: '#1A2744' } } },
        },
      }
    );
  }
 
  // 1b. Pie — Site B Protocol Mix (compare mode only)
  if (isCompare) {
    const protoB = fpB.protocol_distribution || [];
    if (protoB.length) {
      protocolChartBInst = new Chart(
        document.getElementById('protocolChartB').getContext('2d'),
        {
          type: 'doughnut',
          data: {
            labels:   protoB.map(p => p.name),
            datasets: [{ data: protoB.map(p => p.value), backgroundColor: PALETTE, borderColor: '#1A2744', borderWidth: 2 }],
          },
          options: {
            cutout: '55%',
            plugins: { legend: { labels: { font: { family: "'Nunito', sans-serif", weight: '700' }, color: '#1A2744' } } },
          },
        }
      );
    }
  }
 
  // 2. Bar — Packet Size Histogram  (Site A always shown)
  const sizeDist   = fp.size_distribution || [0,0,0,0];
  const sizeLabels = ['0–100 B','101–500 B','501–1000 B','1001–1500 B'];
 
  // In compare mode show both sites as grouped bars
  const barDatasets = isCompare
    ? [
        { label: fp.site_url  + ' (A)', data: sizeDist,                              backgroundColor: '#D93025', borderColor: '#1A2744', borderWidth: 2 },
        { label: fpB.site_url + ' (B)', data: fpB.size_distribution || [0,0,0,0],    backgroundColor: '#1A2744', borderColor: '#D93025', borderWidth: 2 },
      ]
    : [
        { label: '% of packets', data: sizeDist, backgroundColor: '#1A2744', borderColor: '#D93025', borderWidth: 2 },
      ];
 
  sizeChartInst = new Chart(
    document.getElementById('sizeChart').getContext('2d'),
    {
      type: 'bar',
      data: { labels: sizeLabels, datasets: barDatasets },
      options: {
        plugins: { legend: { display: isCompare, labels: { font: { family: "'Nunito'", weight: '700' }, color: '#1A2744' } } },
        scales: {
          x: { ticks: { font: { family: "'Nunito'", weight: '700' }, color: '#1A2744' }, grid: { color: '#ddd' } },
          y: { ticks: { font: { family: "'Nunito'", weight: '700' }, color: '#1A2744' }, grid: { color: '#ddd' } },
        },
      },
    }
  );
 
  // 3. Line — Traffic over time
  // Single mode: one line.  Compare mode: TWO lines (Site A + Site B) — FR-7 spec
  const timelineA  = fp.timeline  || Array(12).fill(0);
  const timeLabels = timelineA.map((_, i) => `T${i + 1}`);
 
  const lineDatasets = [
    {
      label:                isCompare ? fp.site_url  + ' (A)' : 'Bytes/slice',
      data:                 timelineA,
      borderColor:          '#D93025',
      backgroundColor:      'rgba(217,48,37,.15)',
      borderWidth:          2.5,
      pointRadius:          4,
      pointBackgroundColor: '#D93025',
      fill:                 true,
      tension:              0.35,
    },
  ];
 
  // Add Site B line only in compare mode
  if (isCompare) {
    lineDatasets.push({
      label:                fpB.site_url + ' (B)',
      data:                 fpB.timeline || Array(12).fill(0),
      borderColor:          '#1A2744',
      backgroundColor:      'rgba(26,39,68,.10)',
      borderWidth:          2.5,
      pointRadius:          4,
      pointBackgroundColor: '#1A2744',
      fill:                 true,
      tension:              0.35,
    });
  }
 
  timelineChartInst = new Chart(
    document.getElementById('timelineChart').getContext('2d'),
    {
      type: 'line',
      data: { labels: timeLabels, datasets: lineDatasets },
      options: {
        plugins: { legend: { display: isCompare, labels: { font: { family: "'Nunito'", weight: '700' }, color: '#1A2744' } } },
        scales: {
          x: { ticks: { font: { family: "'Nunito'", weight: '700' }, color: '#1A2744' }, grid: { color: '#ddd' } },
          y: { ticks: { font: { family: "'Nunito'", weight: '700' }, color: '#1A2744' }, grid: { color: '#ddd' } },
        },
      },
    }
  );
}
 
function destroyCharts() {
  if (protocolChartInst)  { protocolChartInst.destroy();  protocolChartInst  = null; }
  if (protocolChartBInst) { protocolChartBInst.destroy(); protocolChartBInst = null; }
  if (sizeChartInst)      { sizeChartInst.destroy();      sizeChartInst      = null; }
  if (timelineChartInst)  { timelineChartInst.destroy();  timelineChartInst  = null; }
}
 
 
// ═══════════════════════════════════════════════════════════════
//  FR-6  Comparison table
// ═══════════════════════════════════════════════════════════════
function renderCompareTable(fpA, fpB, diff) {
  document.getElementById('thA').textContent = fpA.site_url || 'Site A';
  document.getElementById('thB').textContent = fpB.site_url || 'Site B';
 
  const rows = [
    { label: '📦 Total Packets',  key: 'total_packets',   fmt: v => v.toLocaleString(),  higher: 'red' },
    { label: '💾 Total Bytes',    key: 'total_bytes',      fmt: fmtBytes,                 higher: 'red' },
    { label: '📏 Avg Packet Size',key: 'mean_packet_size', fmt: v => v + ' B',            higher: 'red' },
    { label: '⬆️ Max Packet',      key: 'max_packet_size',  fmt: v => v + ' B',            higher: 'red' },
    { label: '🌐 Unique IPs',     key: 'unique_ips',       fmt: v => v.toString(),        higher: 'red' },
    { label: '🏷 Behavior',       key: 'behavior_label',   fmt: v => v,                   higher: null  },
    { label: '✅ Confidence',     key: 'confidence',       fmt: v => v + '%',             higher: 'green'},
  ];
 
  const tbody = document.getElementById('compareTbody');
  tbody.innerHTML = rows.map(r => {
    const va = fpA[r.key]; const vb = fpB[r.key];
    let classA = '', classB = '';
    if (r.higher && typeof va === 'number' && typeof vb === 'number') {
      if (va > vb) { classA = r.higher === 'red' ? 'winner-red' : 'winner-green'; }
      else if (vb > va) { classB = r.higher === 'red' ? 'winner-red' : 'winner-green'; }
    }
    return `<tr>
      <td>${r.label}</td>
      <td class="${classA}">${r.fmt(va ?? 0)}</td>
      <td class="${classB}">${r.fmt(vb ?? 0)}</td>
    </tr>`;
  }).join('');
 
  document.getElementById('compareCard').style.display = '';
}
 
 
// ═══════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════
function fmtBytes(b) {
  if (!b) return '0 B';
  if (b >= 1_000_000) return (b / 1_000_000).toFixed(2) + ' MB';
  if (b >= 1_000)     return (b / 1_000).toFixed(1) + ' KB';
  return b + ' B';
}
 
function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
 