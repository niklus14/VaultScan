/**
 * VaultScan Cloud Security Dashboard
 * Single-page application frontend
 */

/* ==========================================================================
   1. State Management
   ========================================================================== */

const state = {
  currentPage: 'dashboard',
  scanResults: null,
  scanHistory: [],
  isScanning: false,
};

/* Severity colour palette */
const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
};

/* ==========================================================================
   2. Utility Functions
   ========================================================================== */

/**
 * Format an ISO-8601 date string into a human-readable form.
 * @param {string} isoString
 * @returns {string}
 */
function formatDate(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return isoString;
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Return the hex colour for a severity level.
 * @param {string} severity
 * @returns {string}
 */
function getSeverityColor(severity) {
  return SEVERITY_COLORS[severity?.toUpperCase()] || '#6b7280';
}

/**
 * Escape HTML entities to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' };
  return str.replace(/[&<>"']/g, (ch) => map[ch]);
}

/**
 * Animate a number counting up from 0 to `target` inside `element`.
 * @param {HTMLElement} element
 * @param {number} target
 * @param {number} duration – milliseconds
 */
function animateNumber(element, target, duration = 800) {
  if (!element) return;
  const start = performance.now();
  target = Number(target) || 0;

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // ease-out quad
    const eased = 1 - (1 - progress) * (1 - progress);
    element.textContent = Math.round(eased * target);
    if (progress < 1) requestAnimationFrame(tick);
  }

  requestAnimationFrame(tick);
}

/* ==========================================================================
   3. Toast Notifications
   ========================================================================== */

/**
 * Show a toast notification.
 * @param {string} message
 * @param {'success'|'error'|'info'} type
 */
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const colours = { success: '#22c55e', error: '#ef4444', info: '#3b82f6' };
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  const bg = colours[type] || colours.info;
  const icon = icons[type] || icons.info;

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.style.cssText = `
    display:flex;align-items:center;gap:10px;
    padding:12px 20px;margin-bottom:8px;
    background:${bg}22;border:1px solid ${bg}66;border-left:4px solid ${bg};
    border-radius:8px;color:#f1f5f9;font-size:0.9rem;
    box-shadow:0 4px 15px rgba(0,0,0,.3);
    opacity:0;transform:translateX(40px);
    transition:opacity .3s ease,transform .3s ease;
    pointer-events:auto;max-width:380px;
  `;
  toast.innerHTML = `
    <span style="font-size:1.1rem;color:${bg}">${icon}</span>
    <span>${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);

  // Trigger entrance animation
  requestAnimationFrame(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateX(0)';
  });

  // Auto-remove after 4 s
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(40px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

/* ==========================================================================
   4. Navigation
   ========================================================================== */

/**
 * Wire up sidebar navigation items.
 */
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      const page = item.dataset.page;
      if (!page) return;
      navigateTo(page);
    });
  });
}

/**
 * Navigate to a named page section.
 * @param {string} page – e.g. "dashboard", "scan", "findings", "reports"
 */
function navigateTo(page) {
  state.currentPage = page;

  // Toggle page sections
  document.querySelectorAll('.page-section').forEach((section) => {
    section.classList.toggle('active', section.id === `page-${page}`);
  });

  // Toggle nav active state
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.dataset.page === page);
  });

  // Re-render the target page
  switch (page) {
    case 'dashboard':
      renderDashboard();
      break;
    case 'findings':
      renderFindings();
      break;
    case 'reports':
      renderReports();
      break;
    // 'scan' is a static page – no dynamic rendering needed
  }
}

/* ==========================================================================
   5. Dashboard Rendering
   ========================================================================== */

function renderDashboard() {
  const results = state.scanResults;

  /* ---------- empty state ---------- */
  const emptyEl = document.getElementById('dashboard-empty');
  const contentEl = document.getElementById('dashboard-content');

  if (!results) {
    if (emptyEl) {
      emptyEl.style.display = 'flex';
      emptyEl.innerHTML = `
        <div style="text-align:center;padding:60px 20px;opacity:.7">
          <div style="font-size:3rem;margin-bottom:16px">🔍</div>
          <h3 style="margin-bottom:8px">No Scan Results Yet</h3>
          <p style="color:#94a3b8">Run your first scan to see results</p>
        </div>
      `;
    }
    if (contentEl) contentEl.style.display = 'none';
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';
  if (contentEl) contentEl.style.display = '';

  /* ---------- stat cards ---------- */
  const summary = results.summary || {};
  const stats = { critical: summary.CRITICAL, high: summary.HIGH, medium: summary.MEDIUM, low: summary.LOW };
  Object.entries(stats).forEach(([key, value]) => {
    const el = document.getElementById(`stat-${key}`);
    animateNumber(el, value || 0);
  });

  /* ---------- charts ---------- */
  drawDonutChart('severity-chart', summary);
  drawBarChart('resource-chart', results.findings || []);

  /* ---------- recent findings ---------- */
  const tbody = document.getElementById('recent-findings-body');
  if (tbody) {
    const recent = (results.findings || []).slice(0, 5);
    tbody.innerHTML = recent
      .map(
        (f) => `
      <tr>
        <td><span class="severity-badge severity-${f.severity?.toLowerCase()}"
              style="background:${getSeverityColor(f.severity)}22;color:${getSeverityColor(f.severity)};
              padding:3px 10px;border-radius:20px;font-size:.75rem;font-weight:600">
              ${escapeHtml(f.severity)}</span></td>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml(f.resource_type)}</td>
        <td style="color:#94a3b8;font-size:.85rem">${formatDate(f.timestamp)}</td>
      </tr>`
      )
      .join('');
  }
}

/* ==========================================================================
   6. Canvas Charts
   ========================================================================== */

/**
 * Draw a donut chart for severity distribution.
 * @param {string} canvasId
 * @param {object} data – {CRITICAL:n, HIGH:n, MEDIUM:n, LOW:n}
 */
function drawDonutChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  canvas.width = 250;
  canvas.height = 250;
  const ctx = canvas.getContext('2d');
  const cx = 125;
  const cy = 125;
  const outerR = 105;
  const innerR = 70;
  const gap = 0.04; // radians gap between arcs

  ctx.clearRect(0, 0, 250, 250);

  const total =
    (data.CRITICAL || 0) + (data.HIGH || 0) + (data.MEDIUM || 0) + (data.LOW || 0);

  if (total === 0) {
    // Empty ring
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.arc(cx, cy, innerR, Math.PI * 2, 0, true);
    ctx.closePath();
    ctx.fillStyle = '#334155';
    ctx.fill();
  } else {
    const segments = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
      .filter((k) => (data[k] || 0) > 0)
      .map((k) => ({ key: k, value: data[k], color: SEVERITY_COLORS[k] }));

    const totalGap = gap * segments.length;
    const available = Math.PI * 2 - totalGap;
    let angle = -Math.PI / 2; // start at top

    segments.forEach((seg) => {
      const sweep = (seg.value / total) * available;
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, angle, angle + sweep);
      ctx.arc(cx, cy, innerR, angle + sweep, angle, true);
      ctx.closePath();
      ctx.fillStyle = seg.color;
      ctx.fill();
      angle += sweep + gap;
    });
  }

  // Center text
  ctx.fillStyle = '#f1f5f9';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.font = 'bold 32px Inter, system-ui, sans-serif';
  ctx.fillText(String(total), cx, cy - 8);
  ctx.font = '13px Inter, system-ui, sans-serif';
  ctx.fillStyle = '#94a3b8';
  ctx.fillText('Findings', cx, cy + 18);
}

/**
 * Draw a horizontal bar chart grouped by resource_type.
 * @param {string} canvasId
 * @param {Array} findings
 */
function drawBarChart(canvasId, findings) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  // Group by resource_type
  const groups = {};
  findings.forEach((f) => {
    const key = f.resource_type || 'Unknown';
    groups[key] = (groups[key] || 0) + 1;
  });

  const entries = Object.entries(groups).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return;

  const barHeight = 28;
  const barGap = 12;
  const labelWidth = 160;
  const padding = { top: 10, bottom: 10, left: labelWidth + 10, right: 60 };
  const height = padding.top + entries.length * (barHeight + barGap) + padding.bottom;

  canvas.width = canvas.parentElement?.clientWidth || 500;
  canvas.height = Math.max(200, height);
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const maxVal = Math.max(...entries.map((e) => e[1]));
  const barAreaWidth = canvas.width - padding.left - padding.right;

  entries.forEach(([label, count], i) => {
    const y = padding.top + i * (barHeight + barGap);
    const barW = Math.max(6, (count / maxVal) * barAreaWidth);

    // Label
    ctx.fillStyle = '#cbd5e1';
    ctx.font = '13px Inter, system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(label, padding.left - 14, y + barHeight / 2);

    // Bar (rounded)
    const radius = barHeight / 2;
    const gradient = ctx.createLinearGradient(padding.left, 0, padding.left + barW, 0);
    gradient.addColorStop(0, '#6366f1');
    gradient.addColorStop(1, '#8b5cf6');
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.moveTo(padding.left + radius, y);
    ctx.lineTo(padding.left + barW - radius, y);
    ctx.arcTo(padding.left + barW, y, padding.left + barW, y + radius, radius);
    ctx.arcTo(padding.left + barW, y + barHeight, padding.left + barW - radius, y + barHeight, radius);
    ctx.lineTo(padding.left + radius, y + barHeight);
    ctx.arcTo(padding.left, y + barHeight, padding.left, y + barHeight - radius, radius);
    ctx.arcTo(padding.left, y, padding.left + radius, y, radius);
    ctx.closePath();
    ctx.fill();

    // Count
    ctx.fillStyle = '#94a3b8';
    ctx.font = 'bold 13px Inter, system-ui, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(String(count), padding.left + barW + 8, y + barHeight / 2);
  });
}

/* ==========================================================================
   7. Scan Functionality
   ========================================================================== */

/**
 * Show the scan modal.
 */
function openScanModal() {
  const modal = document.getElementById('scan-modal');
  if (!modal) return;
  modal.classList.add('active');
  modal.style.display = 'flex';
  // Fade-in
  requestAnimationFrame(() => (modal.style.opacity = '1'));
}

/**
 * Hide the scan modal.
 */
function closeScanModal() {
  const modal = document.getElementById('scan-modal');
  if (!modal) return;
  modal.style.opacity = '0';
  setTimeout(() => {
    modal.classList.remove('active');
    modal.style.display = 'none';
  }, 250);
}

/**
 * Start a security scan.
 * Reads form values, calls the API, and updates state.
 */
async function startScan() {
  if (state.isScanning) return;
  state.isScanning = true;

  // Read form values (fall back to defaults)
  const modeEl = document.getElementById('scan-mode');
  const providerEl = document.getElementById('scan-provider');
  const mode = modeEl?.value || 'simulated';
  const provider = providerEl?.value || 'aws';

  // Show progress bar
  const progress = document.getElementById('scan-progress');
  if (progress) {
    progress.style.display = 'block';
    const bar = progress.querySelector('.progress-bar') || progress;
    bar.style.width = '0%';
    // Animate to ~90% while waiting
    requestAnimationFrame(() => {
      bar.style.transition = 'width 3s ease-out';
      bar.style.width = '90%';
    });
  }

  // Disable button
  const btn = document.getElementById('btn-start-scan');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Scanning…';
  }

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, provider }),
    });

    if (!res.ok) throw new Error(`Scan failed (${res.status})`);

    const data = await res.json();

    // Fill progress to 100%
    if (progress) {
      const bar = progress.querySelector('.progress-bar') || progress;
      bar.style.transition = 'width .3s ease';
      bar.style.width = '100%';
    }

    // Store results
    state.scanResults = data;
    state.scanHistory.unshift({
      scan_id: data.scan_id,
      timestamp: data.timestamp,
      mode: data.mode,
      provider: data.provider,
      total_findings: data.total_findings,
      summary: data.summary,
    });

    // Brief pause so user sees 100%
    await new Promise((r) => setTimeout(r, 400));

    closeScanModal();
    showToast('Scan completed successfully!', 'success');
    navigateTo('dashboard');
  } catch (err) {
    console.error('Scan error:', err);
    showToast(err.message || 'Scan failed. Please try again.', 'error');
  } finally {
    state.isScanning = false;
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Start Scan';
    }
    if (progress) {
      const bar = progress.querySelector('.progress-bar') || progress;
      bar.style.transition = 'none';
      bar.style.width = '0%';
      progress.style.display = 'none';
    }
  }
}

/* ==========================================================================
   8. Findings Page
   ========================================================================== */

/**
 * Render the full findings table based on current filters.
 */
function renderFindings() {
  const findings = getFilteredFindings();
  const tbody = document.getElementById('findings-table-body');
  if (!tbody) return;

  if (findings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center;padding:40px;color:#64748b">
          ${state.scanResults ? 'No findings match the current filters.' : 'No scan data available. Run a scan first.'}
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = findings
    .map(
      (f, i) => `
    <tr class="finding-row" data-index="${i}" style="cursor:pointer">
      <td><span style="background:${getSeverityColor(f.severity)}22;color:${getSeverityColor(f.severity)};
            padding:3px 10px;border-radius:20px;font-size:.75rem;font-weight:600">
            ${escapeHtml(f.severity)}</span></td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml(f.resource_type)}</td>
      <td style="font-family:monospace;font-size:.85rem">${escapeHtml(f.resource)}</td>
      <td style="color:#94a3b8;font-size:.85rem;white-space:nowrap">${formatDate(f.timestamp)}</td>
    </tr>
    <tr class="finding-detail" id="detail-${i}" style="display:none">
      <td colspan="5" style="padding:16px 24px;background:#1e293b;border-left:3px solid ${getSeverityColor(f.severity)}">
        <div style="margin-bottom:12px">
          <strong style="color:#94a3b8">Description</strong>
          <p style="margin:4px 0 0;color:#cbd5e1">${escapeHtml(f.description)}</p>
        </div>
        <div style="margin-bottom:12px">
          <strong style="color:#94a3b8">Remediation</strong>
          <pre style="margin:4px 0 0;padding:12px;background:#0f172a;border-radius:6px;
                color:#a5f3fc;font-size:.85rem;overflow-x:auto">${escapeHtml(f.remediation)}</pre>
        </div>
        <div>
          <strong style="color:#94a3b8">Compliance</strong>
          <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">
            ${(f.compliance || [])
              .map(
                (c) =>
                  `<span style="background:#334155;padding:3px 10px;border-radius:12px;font-size:.75rem;color:#93c5fd">${escapeHtml(c)}</span>`
              )
              .join('')}
          </div>
        </div>
      </td>
    </tr>`
    )
    .join('');

  // Attach click handlers for toggling detail rows
  tbody.querySelectorAll('.finding-row').forEach((row) => {
    row.addEventListener('click', () => {
      const idx = row.dataset.index;
      const detail = document.getElementById(`detail-${idx}`);
      if (!detail) return;
      const isOpen = detail.style.display !== 'none';
      // Close all
      tbody.querySelectorAll('.finding-detail').forEach((d) => (d.style.display = 'none'));
      // Toggle current
      if (!isOpen) detail.style.display = '';
    });
  });
}

/**
 * Return findings filtered by current controls.
 * @returns {Array}
 */
function getFilteredFindings() {
  if (!state.scanResults || !state.scanResults.findings) return [];

  let findings = [...state.scanResults.findings];

  // Severity filter
  const sevEl = document.getElementById('filter-severity');
  const sevVal = sevEl?.value;
  if (sevVal && sevVal !== 'all') {
    findings = findings.filter((f) => f.severity === sevVal);
  }

  // Search filter
  const searchEl = document.getElementById('filter-search');
  const q = searchEl?.value?.toLowerCase().trim();
  if (q) {
    findings = findings.filter(
      (f) =>
        (f.title || '').toLowerCase().includes(q) ||
        (f.resource || '').toLowerCase().includes(q) ||
        (f.resource_type || '').toLowerCase().includes(q) ||
        (f.rule_id || '').toLowerCase().includes(q) ||
        (f.description || '').toLowerCase().includes(q)
    );
  }

  return findings;
}

/**
 * Handler called when filter controls change.
 */
function filterFindings() {
  renderFindings();
}

/* ==========================================================================
   9. Reports Page
   ========================================================================== */

function renderReports() {
  const container = document.getElementById('reports-list');
  if (!container) return;

  if (state.scanHistory.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:60px;color:#64748b">
        <p>No scan history available.</p>
      </div>`;
    return;
  }

  container.innerHTML = state.scanHistory
    .map(
      (scan, i) => `
    <div class="report-card" style="background:#1e293b;border:1px solid #334155;border-radius:12px;
          padding:20px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;
          flex-wrap:wrap;gap:12px">
      <div>
        <h4 style="margin:0 0 6px;color:#f1f5f9">
          Scan #${escapeHtml(scan.scan_id?.slice(0, 8) || String(i + 1))}
        </h4>
        <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:.85rem;color:#94a3b8">
          <span>📅 ${formatDate(scan.timestamp)}</span>
          <span>☁️ ${escapeHtml(scan.provider?.toUpperCase() || 'AWS')}</span>
          <span>⚙️ ${escapeHtml(scan.mode || 'simulated')}</span>
        </div>
        <div style="display:flex;gap:10px;margin-top:8px">
          ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            .map(
              (s) =>
                `<span style="background:${getSeverityColor(s)}22;color:${getSeverityColor(s)};
                  padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600">
                  ${s}: ${scan.summary?.[s] ?? 0}</span>`
            )
            .join('')}
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="downloadJSON(${i})"
          style="padding:8px 16px;background:#334155;border:none;border-radius:8px;
            color:#e2e8f0;font-size:.85rem;cursor:pointer">⬇ JSON</button>
        <button onclick="downloadHTMLReport(${i})"
          style="padding:8px 16px;background:#6366f1;border:none;border-radius:8px;
            color:#fff;font-size:.85rem;cursor:pointer">⬇ HTML Report</button>
      </div>
    </div>`
    )
    .join('');
}

/**
 * Trigger a JSON download for a scan history entry.
 * If index 0 and full results exist, use those; otherwise use the summary.
 * @param {number} index
 */
function downloadJSON(index) {
  const scan =
    index === 0 && state.scanResults
      ? state.scanResults
      : state.scanHistory[index];

  if (!scan) return;

  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vaultscan-${scan.scan_id || 'report'}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('JSON report downloaded', 'info');
}

/**
 * Generate and download a self-contained HTML report.
 * @param {number} index
 */
function downloadHTMLReport(index) {
  const scan =
    index === 0 && state.scanResults
      ? state.scanResults
      : state.scanHistory[index];

  if (!scan) return;

  const html = generateHTMLReport(scan);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vaultscan-report-${scan.scan_id || 'export'}.html`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('HTML report downloaded', 'info');
}

/* ==========================================================================
   10. HTML Report Generation
   ========================================================================== */

/**
 * Create a complete, standalone HTML report string.
 * @param {object} scanResult
 * @returns {string}
 */
function generateHTMLReport(scanResult) {
  const summary = scanResult.summary || {};
  const findings = scanResult.findings || [];
  const total = (summary.CRITICAL || 0) + (summary.HIGH || 0) + (summary.MEDIUM || 0) + (summary.LOW || 0);

  const findingRows = findings
    .map(
      (f) => `
    <tr>
      <td><span class="sev sev-${(f.severity || '').toLowerCase()}">${escapeHtml(f.severity)}</span></td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml(f.resource_type)}</td>
      <td><code>${escapeHtml(f.resource)}</code></td>
      <td>${escapeHtml(f.description)}</td>
      <td><pre>${escapeHtml(f.remediation)}</pre></td>
      <td>${(f.compliance || []).map((c) => `<span class="tag">${escapeHtml(c)}</span>`).join(' ')}</td>
    </tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VaultScan Report – ${escapeHtml(scanResult.scan_id || '')}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Inter,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:40px 24px;line-height:1.6}
.container{max-width:1100px;margin:0 auto}
header{text-align:center;margin-bottom:40px;padding-bottom:24px;border-bottom:1px solid #1e293b}
header h1{font-size:1.8rem;color:#f1f5f9}
header h1 span{color:#818cf8}
header p{color:#94a3b8;margin-top:6px;font-size:.9rem}
.meta{display:flex;justify-content:center;gap:24px;margin-top:12px;font-size:.85rem;color:#64748b}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px}
.stat{background:#1e293b;border-radius:12px;padding:20px;text-align:center;border:1px solid #334155}
.stat .count{font-size:2rem;font-weight:700}
.stat .label{font-size:.8rem;color:#94a3b8;text-transform:uppercase;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:.85rem;margin-top:24px}
th{text-align:left;padding:10px 12px;background:#1e293b;color:#94a3b8;font-weight:600;border-bottom:2px solid #334155}
td{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover td{background:#1e293b55}
pre{background:#0f172a;padding:8px;border-radius:6px;overflow-x:auto;font-size:.8rem;color:#a5f3fc;white-space:pre-wrap}
code{font-family:monospace;font-size:.85rem;color:#a5f3fc}
.sev{padding:3px 10px;border-radius:20px;font-size:.75rem;font-weight:600;display:inline-block}
.sev-critical{background:#ef444422;color:#ef4444}
.sev-high{background:#f9731622;color:#f97316}
.sev-medium{background:#eab30822;color:#eab308}
.sev-low{background:#3b82f622;color:#3b82f6}
.tag{display:inline-block;background:#334155;padding:2px 8px;border-radius:10px;font-size:.7rem;color:#93c5fd;margin:2px}
footer{text-align:center;margin-top:48px;color:#475569;font-size:.8rem;border-top:1px solid #1e293b;padding-top:20px}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ <span>VaultScan</span> Security Report</h1>
    <p>Scan ID: ${escapeHtml(scanResult.scan_id || 'N/A')}</p>
    <div class="meta">
      <span>📅 ${formatDate(scanResult.timestamp)}</span>
      <span>☁️ ${escapeHtml((scanResult.provider || 'aws').toUpperCase())}</span>
      <span>⚙️ ${escapeHtml(scanResult.mode || 'simulated')}</span>
      <span>📊 ${total} Findings</span>
    </div>
  </header>

  <div class="stats">
    <div class="stat"><div class="count" style="color:#ef4444">${summary.CRITICAL || 0}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="count" style="color:#f97316">${summary.HIGH || 0}</div><div class="label">High</div></div>
    <div class="stat"><div class="count" style="color:#eab308">${summary.MEDIUM || 0}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="count" style="color:#3b82f6">${summary.LOW || 0}</div><div class="label">Low</div></div>
  </div>

  <h2 style="margin-bottom:4px;font-size:1.2rem">Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Title</th><th>Resource Type</th><th>Resource</th><th>Description</th><th>Remediation</th><th>Compliance</th></tr>
    </thead>
    <tbody>${findingRows}</tbody>
  </table>

  <footer>
    <p>Generated by VaultScan on ${formatDate(new Date().toISOString())}</p>
  </footer>
</div>
</body>
</html>`;
}

/* ==========================================================================
   11. Initialisation
   ========================================================================== */

document.addEventListener('DOMContentLoaded', init);

async function init() {
  // Navigation
  initNavigation();

  // Scan button(s)
  document.getElementById('btn-new-scan')?.addEventListener('click', openScanModal);
  document.getElementById('btn-start-scan')?.addEventListener('click', startScan);
  document.getElementById('btn-close-modal')?.addEventListener('click', closeScanModal);

  // Close modal on backdrop click
  const modal = document.getElementById('scan-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeScanModal();
    });
  }

  // Filter controls
  document.getElementById('filter-severity')?.addEventListener('change', filterFindings);
  document.getElementById('filter-search')?.addEventListener('input', filterFindings);

  // Fetch scan history
  try {
    const res = await fetch('/api/history');
    if (res.ok) {
      const data = await res.json();
      state.scanHistory = data.scans || [];
    }
  } catch (err) {
    console.warn('Could not fetch scan history:', err);
  }

  // If history exists, load the most recent scan as current results
  if (state.scanHistory.length > 0) {
    // Try to load full results for the most recent scan
    try {
      const latest = state.scanHistory[0];
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: latest.mode || 'simulated', provider: latest.provider || 'aws' }),
      });
      if (res.ok) {
        state.scanResults = await res.json();
      }
    } catch (err) {
      console.warn('Could not reload latest scan:', err);
    }
  }

  // Render dashboard
  renderDashboard();

  // Auto-scan on first load if no history exists
  if (state.scanHistory.length === 0 && !state.scanResults) {
    showToast('Running initial scan…', 'info');
    await autoScan();
  }
}

/**
 * Perform an automatic simulated scan (used on first load).
 */
async function autoScan() {
  state.isScanning = true;
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'simulated', provider: 'aws' }),
    });

    if (!res.ok) throw new Error(`Auto-scan failed (${res.status})`);

    const data = await res.json();
    state.scanResults = data;
    state.scanHistory.unshift({
      scan_id: data.scan_id,
      timestamp: data.timestamp,
      mode: data.mode,
      provider: data.provider,
      total_findings: data.total_findings,
      summary: data.summary,
    });

    renderDashboard();
    showToast('Initial scan complete!', 'success');
  } catch (err) {
    console.warn('Auto-scan error:', err);
    showToast('Could not run initial scan.', 'error');
  } finally {
    state.isScanning = false;
  }
}
