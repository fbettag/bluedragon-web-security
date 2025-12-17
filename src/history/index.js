/**
 * BlueDragon Web Security - History Page
 */

import { MESSAGE_TYPES, SEVERITY_COLORS } from '../shared/constants.js';

let history = [];
let filteredHistory = [];
let stats = {};
let selectedItems = new Set();
let currentPage = 1;
const itemsPerPage = 50;

/**
 * Initialize history page
 */
async function init() {
  // Load history
  await loadHistory();

  // Set up event listeners
  setupEventListeners();

  // Initial render
  applyFilters();
}

/**
 * Load history from background
 */
async function loadHistory() {
  try {
    const response = await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.GET_HISTORY
    });

    if (response.success) {
      history = response.history || [];
      stats = response.stats || {};
      updateStats();
    }
  } catch (e) {
    console.warn('Failed to load history:', e);
  }
}

/**
 * Update statistics display
 */
function updateStats() {
  document.getElementById('totalCount').textContent = stats.total || 0;
  document.getElementById('criticalCount').textContent = stats.bySeverity?.critical || 0;
  document.getElementById('highCount').textContent = stats.bySeverity?.high || 0;
  document.getElementById('mediumCount').textContent = stats.bySeverity?.medium || 0;
  document.getElementById('lowCount').textContent = stats.bySeverity?.low || 0;
  document.getElementById('unviewedCount').textContent = stats.unviewed || 0;
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
  // Filters
  document.getElementById('severityFilter').addEventListener('change', applyFilters);
  document.getElementById('typeFilter').addEventListener('change', applyFilters);
  document.getElementById('frameworkFilter').addEventListener('change', applyFilters);
  document.getElementById('searchInput').addEventListener('input', debounce(applyFilters, 300));

  // Select all
  document.getElementById('selectAll').addEventListener('change', handleSelectAll);

  // Export dropdown
  document.getElementById('exportBtn').addEventListener('click', () => {
    document.getElementById('exportDropdown').classList.toggle('open');
  });

  document.querySelectorAll('#exportDropdown .dropdown-item').forEach(item => {
    item.addEventListener('click', (e) => {
      exportHistory(e.target.dataset.format);
      document.getElementById('exportDropdown').classList.remove('open');
    });
  });

  // Selected actions
  document.getElementById('exportSelectedBtn').addEventListener('click', exportSelected);
  document.getElementById('deleteSelectedBtn').addEventListener('click', deleteSelected);

  // Clear all
  document.getElementById('clearAllBtn').addEventListener('click', clearAll);

  // Pagination
  document.getElementById('prevPage').addEventListener('click', () => changePage(-1));
  document.getElementById('nextPage').addEventListener('click', () => changePage(1));

  // Close dropdowns on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#exportDropdown')) {
      document.getElementById('exportDropdown').classList.remove('open');
    }
  });
}

/**
 * Apply filters and render
 */
function applyFilters() {
  const severity = document.getElementById('severityFilter').value;
  const type = document.getElementById('typeFilter').value;
  const framework = document.getElementById('frameworkFilter').value;
  const search = document.getElementById('searchInput').value.toLowerCase();

  filteredHistory = history.filter(item => {
    if (severity && item.severity !== severity) return false;
    if (type && item.type !== type) return false;
    if (framework && item.framework !== framework) return false;
    if (search) {
      const searchStr = `${item.name} ${item.cve} ${item.url} ${item.description}`.toLowerCase();
      if (!searchStr.includes(search)) return false;
    }
    return true;
  });

  // Reset to first page
  currentPage = 1;

  renderHistory();
}

/**
 * Render history table
 */
function renderHistory() {
  const tbody = document.getElementById('historyBody');
  const emptyState = document.getElementById('emptyState');

  if (filteredHistory.length === 0) {
    tbody.innerHTML = '';
    emptyState.classList.remove('hidden');
    document.getElementById('pagination').style.display = 'none';
    return;
  }

  emptyState.classList.add('hidden');
  document.getElementById('pagination').style.display = 'flex';

  // Calculate pagination
  const totalPages = Math.ceil(filteredHistory.length / itemsPerPage);
  const start = (currentPage - 1) * itemsPerPage;
  const end = start + itemsPerPage;
  const pageItems = filteredHistory.slice(start, end);

  // Update pagination info
  document.getElementById('currentPage').textContent = currentPage;
  document.getElementById('totalPages').textContent = totalPages;
  document.getElementById('prevPage').disabled = currentPage === 1;
  document.getElementById('nextPage').disabled = currentPage === totalPages;

  // Render rows
  tbody.innerHTML = pageItems.map(item => `
    <tr data-id="${item.id}" class="${item.viewed ? '' : 'unviewed'}">
      <td>
        <input type="checkbox" class="item-checkbox" ${selectedItems.has(item.id) ? 'checked' : ''}>
      </td>
      <td class="severity-cell">
        <span class="badge badge-${item.severity?.toLowerCase() || 'info'}">${item.severity || 'INFO'}</span>
      </td>
      <td class="type-cell">${escapeHtml(item.type || '')}</td>
      <td class="name-cell">
        <strong>${escapeHtml(item.name || item.type || '')}</strong>
        ${item.cve ? `<br><span class="text-muted text-xs">${item.cve}</span>` : ''}
      </td>
      <td class="url-cell truncate" title="${escapeHtml(item.url || '')}">
        ${escapeHtml(truncate(item.url || '', 40))}
      </td>
      <td>${escapeHtml(item.framework || '-')}</td>
      <td class="date-cell">${formatDate(item.timestamp)}</td>
      <td class="actions-cell">
        <button class="btn btn-sm btn-ghost view-btn" title="View details">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
        </button>
        <button class="btn btn-sm btn-ghost delete-btn" title="Delete">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M3 6h18"></path>
            <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>
          </svg>
        </button>
      </td>
    </tr>
  `).join('');

  // Attach row event listeners
  tbody.querySelectorAll('.item-checkbox').forEach(checkbox => {
    checkbox.addEventListener('change', handleItemSelect);
  });

  tbody.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.target.closest('tr').dataset.id;
      viewItem(id);
    });
  });

  tbody.querySelectorAll('.delete-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = e.target.closest('tr').dataset.id;
      deleteItem(id);
    });
  });

  updateSelectBar();
}

/**
 * Handle select all
 */
function handleSelectAll(e) {
  const checked = e.target.checked;
  const start = (currentPage - 1) * itemsPerPage;
  const end = start + itemsPerPage;
  const pageItems = filteredHistory.slice(start, end);

  if (checked) {
    pageItems.forEach(item => selectedItems.add(item.id));
  } else {
    pageItems.forEach(item => selectedItems.delete(item.id));
  }

  renderHistory();
}

/**
 * Handle individual item select
 */
function handleItemSelect(e) {
  const id = e.target.closest('tr').dataset.id;

  if (e.target.checked) {
    selectedItems.add(id);
  } else {
    selectedItems.delete(id);
  }

  updateSelectBar();
}

/**
 * Update select bar visibility
 */
function updateSelectBar() {
  const selectBar = document.getElementById('selectBar');
  const selectedCount = document.getElementById('selectedCount');

  if (selectedItems.size > 0) {
    selectBar.classList.add('visible');
    selectedCount.textContent = selectedItems.size;
  } else {
    selectBar.classList.remove('visible');
  }
}

/**
 * Change page
 */
function changePage(delta) {
  const totalPages = Math.ceil(filteredHistory.length / itemsPerPage);
  const newPage = currentPage + delta;

  if (newPage >= 1 && newPage <= totalPages) {
    currentPage = newPage;
    renderHistory();
  }
}

/**
 * View item details
 */
function viewItem(id) {
  const item = history.find(h => h.id === id);
  if (!item) return;

  // Mark as viewed
  item.viewed = true;

  // Open in modal or new tab
  const details = `
${item.name || item.type}
${'='.repeat(50)}
Severity: ${item.severity || 'INFO'}
CVE: ${item.cve || 'N/A'}
Type: ${item.type || 'Unknown'}
Framework: ${item.framework || 'Unknown'}
URL: ${item.url || 'N/A'}

Description:
${item.description || 'No description'}

${item.testVector ? `Test Vector:\n${item.testVector}\n` : ''}
${item.note ? `Note:\n${item.note}\n` : ''}
${item.remediation ? `Remediation:\n${item.remediation}` : ''}
  `;

  alert(details);
  renderHistory();
}

/**
 * Delete item
 */
async function deleteItem(id) {
  if (!confirm('Delete this finding?')) return;

  history = history.filter(h => h.id !== id);
  selectedItems.delete(id);

  // Save to storage
  await chrome.storage.local.set({ scanHistory: history });

  applyFilters();
  showToast('Item deleted', 'success');
}

/**
 * Delete selected items
 */
async function deleteSelected() {
  if (!confirm(`Delete ${selectedItems.size} selected items?`)) return;

  history = history.filter(h => !selectedItems.has(h.id));
  selectedItems.clear();

  await chrome.storage.local.set({ scanHistory: history });

  applyFilters();
  showToast('Items deleted', 'success');
}

/**
 * Export history
 */
async function exportHistory(format) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.EXPORT_REQUEST,
      format,
      data: filteredHistory
    });

    if (response.success) {
      downloadFile(response.exported, format);
      showToast('Export downloaded', 'success');
    }
  } catch (e) {
    showToast('Export failed', 'error');
  }
}

/**
 * Export selected items
 */
async function exportSelected() {
  const selectedData = history.filter(h => selectedItems.has(h.id));

  try {
    const response = await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.EXPORT_REQUEST,
      format: 'json',
      data: selectedData
    });

    if (response.success) {
      downloadFile(response.exported, 'json');
      showToast('Export downloaded', 'success');
    }
  } catch (e) {
    showToast('Export failed', 'error');
  }
}

/**
 * Clear all history
 */
async function clearAll() {
  if (!confirm('Delete ALL scan history? This cannot be undone.')) return;

  try {
    await chrome.runtime.sendMessage({ type: MESSAGE_TYPES.CLEAR_HISTORY });
    history = [];
    filteredHistory = [];
    stats = {};
    selectedItems.clear();
    updateStats();
    renderHistory();
    showToast('History cleared', 'success');
  } catch (e) {
    showToast('Failed to clear history', 'error');
  }
}

/**
 * Download file
 */
function downloadFile(content, format) {
  const ext = format === 'json' ? 'json' : format === 'nuclei' ? 'yaml' : 'md';
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `bluedragon-export-${Date.now()}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Show toast
 */
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    padding: 12px 24px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    z-index: 1000;
  `;

  if (type === 'success') toast.style.borderColor = 'var(--severity-low)';
  if (type === 'error') toast.style.borderColor = 'var(--severity-critical)';

  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// Utility functions
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function truncate(str, max) {
  if (!str || str.length <= max) return str;
  return str.substring(0, max) + '...';
}

function formatDate(timestamp) {
  if (!timestamp) return '-';
  return new Date(timestamp).toLocaleString();
}

function debounce(fn, delay) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn.apply(this, args), delay);
  };
}

// Initialize
document.addEventListener('DOMContentLoaded', init);
