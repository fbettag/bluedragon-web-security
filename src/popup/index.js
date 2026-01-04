/**
 * BlueDragon Web Security - Popup Script
 * Main popup interface logic
 */

import { MESSAGE_TYPES, SEVERITY, SEVERITY_COLORS } from '../shared/constants.js';

// DOM Elements
let elements = {};

// State
let currentTab = null;
let tabStatus = null;
let scanResults = [];
let isScanning = false;
let settings = {};

/**
 * Initialize popup
 */
async function init() {
  console.log('[BlueDragon] Popup initializing...');

  // Cache DOM elements
  cacheElements();

  // Set up event listeners
  setupEventListeners();

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;

  // Update target info
  updateTargetInfo();

  // Load settings
  await loadSettings();

  // Get tab status from background
  await refreshStatus();

  console.log('[BlueDragon] Popup initialized');
}

/**
 * Cache DOM elements
 */
function cacheElements() {
  elements = {
    // Header
    logoIcon: document.getElementById('logoIcon'),
    historyBtn: document.getElementById('historyBtn'),
    settingsBtn: document.getElementById('settingsBtn'),

    // Mode
    modeToggle: document.getElementById('modeToggle'),

    // Target
    targetUrl: document.getElementById('targetUrl'),
    frameworkBadge: document.getElementById('frameworkBadge'),

    // Scan
    quickScanBtn: document.getElementById('quickScanBtn'),
    deepScanBtn: document.getElementById('deepScanBtn'),
    progressSection: document.getElementById('progressSection'),
    progressBar: document.getElementById('progressBar'),
    progressText: document.getElementById('progressText'),

    // Results
    vulnCount: document.getElementById('vulnCount'),
    resultsList: document.getElementById('resultsList'),
    emptyState: document.getElementById('emptyState'),
    exportBtn: document.getElementById('exportBtn'),
    exportDropdown: document.getElementById('exportDropdown'),
    clearBtn: document.getElementById('clearBtn'),

    // Stats
    statCritical: document.getElementById('statCritical'),
    statHigh: document.getElementById('statHigh'),
    statMedium: document.getElementById('statMedium'),

    // Modal
    vulnModal: document.getElementById('vulnModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    closeModal: document.getElementById('closeModal'),
    modalCopyBtn: document.getElementById('modalCopyBtn'),
    modalExploitBtn: document.getElementById('modalExploitBtn'),

    // Exploit Section
    exploitSection: document.getElementById('exploitSection'),
    exploitCommand: document.getElementById('exploitCommand'),
    runExploitBtn: document.getElementById('runExploitBtn'),
    exploitOutput: document.getElementById('exploitOutput'),
    copyOutputBtn: document.getElementById('copyOutputBtn'),
    clearOutputBtn: document.getElementById('clearOutputBtn'),
    exploitStatus: document.getElementById('exploitStatus'),

    // Container
    app: document.getElementById('app')
  };
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
  // Navigation buttons
  elements.historyBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('history/history.html') });
  });

  elements.settingsBtn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('settings/settings.html') });
  });

  // Mode toggle button
  elements.modeToggle.addEventListener('click', handleModeToggle);

  // Scan buttons
  elements.quickScanBtn.addEventListener('click', () => startScan('manual'));
  elements.deepScanBtn.addEventListener('click', () => startScan('deep'));

  // Export dropdown
  elements.exportBtn.addEventListener('click', () => {
    elements.exportDropdown.classList.toggle('open');
  });

  document.querySelectorAll('#exportDropdown .dropdown-item').forEach(item => {
    item.addEventListener('click', (e) => {
      const format = e.target.dataset.format;
      exportResults(format);
      elements.exportDropdown.classList.remove('open');
    });
  });

  // Clear button
  elements.clearBtn.addEventListener('click', clearResults);

  // Modal
  elements.closeModal.addEventListener('click', closeModal);
  elements.vulnModal.addEventListener('click', (e) => {
    if (e.target === elements.vulnModal) closeModal();
  });
  elements.modalCopyBtn.addEventListener('click', copyVulnDetails);
  elements.modalExploitBtn.addEventListener('click', toggleExploitSection);

  // Exploit section
  elements.runExploitBtn.addEventListener('click', runExploit);
  elements.copyOutputBtn.addEventListener('click', copyExploitOutput);
  elements.clearOutputBtn.addEventListener('click', clearExploitOutput);
  elements.exploitCommand.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runExploit();
  });

  // Close dropdown when clicking outside
  document.addEventListener('click', (e) => {
    if (!elements.exportDropdown.contains(e.target)) {
      elements.exportDropdown.classList.remove('open');
    }
  });

  // Listen for messages from background
  chrome.runtime.onMessage.addListener(handleMessage);
}

/**
 * Load settings from background
 */
async function loadSettings() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    if (response.success) {
      settings = response.settings;
      updateModeUI();
    }
  } catch (e) {
    console.warn('[BlueDragon] Failed to load settings:', e);
  }
}

/**
 * Update target information display
 */
function updateTargetInfo() {
  if (!currentTab?.url) {
    elements.targetUrl.textContent = 'No active tab';
    return;
  }

  try {
    const url = new URL(currentTab.url);
    elements.targetUrl.textContent = url.hostname + url.pathname;
    elements.targetUrl.title = currentTab.url;
  } catch (e) {
    elements.targetUrl.textContent = currentTab.url;
  }
}

/**
 * Refresh status from content script/background
 */
async function refreshStatus() {
  try {
    // Get status from background
    const response = await chrome.runtime.sendMessage({
      type: 'GET_TAB_STATUS',
      tabId: currentTab.id
    });

    if (response.success) {
      tabStatus = response.status;
      updateFrameworkInfo(tabStatus.framework);

      // Also try to get current status from content script
      try {
        const contentResponse = await chrome.tabs.sendMessage(currentTab.id, {
          type: MESSAGE_TYPES.GET_STATUS
        });
        if (contentResponse) {
          updateFrameworkInfo(contentResponse.framework);
          if (contentResponse.scanResults?.length > 0) {
            scanResults = contentResponse.scanResults;
            renderResults();
          }
        }
      } catch (e) {
        // Content script might not be loaded
        console.log('[BlueDragon] Content script not available');
      }
    }
  } catch (e) {
    console.warn('[BlueDragon] Failed to get status:', e);
  }
}

/**
 * Update framework information display
 */
function updateFrameworkInfo(framework) {
  if (!framework) {
    elements.frameworkBadge.textContent = 'Unknown';
    elements.frameworkBadge.classList.remove('vulnerable');
    return;
  }

  let text = framework.framework;
  if (framework.version) {
    text += ` ${framework.version}`;
  }

  elements.frameworkBadge.textContent = text;

  // Check if vulnerable
  if (framework.hasRSC || framework.isSSR) {
    elements.frameworkBadge.classList.add('vulnerable');
    elements.frameworkBadge.title = 'SSR detected - potential attack surface';
  } else {
    elements.frameworkBadge.classList.remove('vulnerable');
    elements.frameworkBadge.title = '';
  }
}

/**
 * Handle mode toggle
 */
async function handleModeToggle() {
  // Toggle the current state
  const isCurrentlyActive = settings.scanMode === 'active' || settings.autoScanEnabled;
  const isActive = !isCurrentlyActive;

  settings.autoScanEnabled = isActive;
  settings.scanMode = isActive ? 'active' : 'passive';

  // Update UI
  updateModeUI();

  // Save settings
  await chrome.runtime.sendMessage({
    type: 'SAVE_SETTINGS',
    settings
  });
}

/**
 * Update mode UI
 */
function updateModeUI() {
  const isActive = settings.scanMode === 'active' || settings.autoScanEnabled;
  const modeText = elements.modeToggle.querySelector('.mode-text');

  if (isActive) {
    elements.modeToggle.classList.add('active');
    modeText.textContent = 'Auto';
  } else {
    elements.modeToggle.classList.remove('active');
    modeText.textContent = 'Manual';
  }

  // Update icon with/without orange dot
  setIconWithDot(isActive);
}

/**
 * Set icon with optional orange dot overlay
 */
function setIconWithDot(showDot) {
  const sizes = [16, 48, 128];
  const imageData = {};

  let loaded = 0;
  sizes.forEach(size => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext('2d');

      // Draw base icon
      ctx.drawImage(img, 0, 0, size, size);

      // Add orange dot if active
      if (showDot) {
        const dotRadius = size === 16 ? 4 : size === 48 ? 10 : 24;
        const cx = size - dotRadius - 1;
        const cy = size - dotRadius - 1;

        ctx.beginPath();
        ctx.arc(cx, cy, dotRadius, 0, Math.PI * 2);
        ctx.fillStyle = '#f97316';
        ctx.fill();
        ctx.strokeStyle = '#ea580c';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      imageData[size] = ctx.getImageData(0, 0, size, size);
      loaded++;

      if (loaded === sizes.length) {
        chrome.action.setIcon({ imageData }).catch(() => {});
      }
    };
    img.src = chrome.runtime.getURL(`icons/icon${size}.png`);
  });
}

/**
 * Ensure content script is injected
 */
async function ensureContentScript() {
  try {
    // Try to ping the content script
    await chrome.tabs.sendMessage(currentTab.id, { type: 'PING' });
    return true;
  } catch (e) {
    // Content script not loaded, inject it
    console.log('[BlueDragon] Injecting content script...');
    try {
      await chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        files: ['content.js']
      });
      // Wait a moment for script to initialize
      await new Promise(resolve => setTimeout(resolve, 500));
      return true;
    } catch (injectError) {
      console.error('[BlueDragon] Failed to inject content script:', injectError);
      return false;
    }
  }
}

/**
 * Start a scan
 */
async function startScan(type) {
  if (isScanning) return;

  isScanning = true;
  elements.app.classList.add('scanning');
  elements.progressSection.classList.remove('hidden');
  elements.progressBar.style.width = '10%';
  elements.progressText.textContent = `Starting ${type} scan...`;

  try {
    // Ensure content script is loaded
    elements.progressText.textContent = 'Preparing scanner...';
    const injected = await ensureContentScript();
    if (!injected) {
      throw new Error('Cannot inject scanner into this page');
    }

    elements.progressBar.style.width = '20%';
    elements.progressText.textContent = `Running ${type} scan...`;

    // Send scan request to content script
    const response = await chrome.tabs.sendMessage(currentTab.id, {
      type: MESSAGE_TYPES.START_SCAN,
      scanType: type
    });

    if (response?.success) {
      scanResults = response.results || [];
      renderResults();
      showToast(`Scan complete: ${scanResults.length} findings`, 'success');
    } else {
      showToast(response?.error || 'Scan failed', 'error');
    }
  } catch (e) {
    console.error('[BlueDragon] Scan error:', e);
    showToast(e.message || 'Failed to start scan', 'error');
  } finally {
    isScanning = false;
    elements.app.classList.remove('scanning');
    elements.progressSection.classList.add('hidden');
  }
}

/**
 * Render scan results
 */
function renderResults() {
  elements.vulnCount.textContent = scanResults.length;

  // Update stats
  const stats = {
    critical: scanResults.filter(r => r.severity === 'CRITICAL').length,
    high: scanResults.filter(r => r.severity === 'HIGH').length,
    medium: scanResults.filter(r => r.severity === 'MEDIUM').length
  };

  elements.statCritical.textContent = stats.critical;
  elements.statHigh.textContent = stats.high;
  elements.statMedium.textContent = stats.medium;

  // Render list
  if (scanResults.length === 0) {
    elements.emptyState.classList.remove('hidden');
    elements.resultsList.innerHTML = '';
    elements.resultsList.appendChild(elements.emptyState);
    return;
  }

  elements.emptyState.classList.add('hidden');
  elements.resultsList.innerHTML = '';

  for (const result of scanResults) {
    const item = createVulnItem(result);
    elements.resultsList.appendChild(item);
  }
}

/**
 * Create vulnerability item element
 */
function createVulnItem(result) {
  const item = document.createElement('div');
  item.className = `vuln-item severity-${result.severity?.toLowerCase() || 'info'}`;
  item.dataset.id = result.id;

  const severityColor = SEVERITY_COLORS[result.severity] || SEVERITY_COLORS.INFO;

  item.innerHTML = `
    <div class="vuln-header">
      <div class="flex items-center gap-sm">
        <span class="severity-indicator ${result.severity?.toLowerCase() || 'info'}"></span>
        <span class="vuln-title">${escapeHtml(result.name || result.type)}</span>
      </div>
      <span class="badge badge-${result.severity?.toLowerCase() || 'info'}">${result.severity || 'INFO'}</span>
    </div>
    <div class="vuln-meta">
      ${result.cve ? `<span class="vuln-cve">${result.cve}</span>` : ''}
      ${result.framework ? `<span class="vuln-framework">${result.framework}</span>` : ''}
    </div>
    ${result.url ? `<div class="vuln-url">${escapeHtml(truncate(result.url, 60))}</div>` : ''}
    <div class="vuln-actions">
      <button class="btn btn-sm btn-ghost view-details">Details</button>
      ${result.requiresProbe ? '<button class="btn btn-sm btn-fire test-exploit">Test</button>' : ''}
    </div>
  `;

  // Event listeners
  item.querySelector('.view-details').addEventListener('click', () => showVulnModal(result));

  const testBtn = item.querySelector('.test-exploit');
  if (testBtn) {
    testBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      showVulnModal(result, true);
    });
  }

  return item;
}

/**
 * Show vulnerability detail modal
 */
function showVulnModal(result, showExploit = false) {
  elements.modalTitle.textContent = result.name || result.type;

  elements.modalBody.innerHTML = `
    <div class="vuln-detail-section">
      <h4>Severity</h4>
      <p><span class="badge badge-${result.severity?.toLowerCase() || 'info'}">${result.severity || 'INFO'}</span>
      ${result.cvss ? `<span class="text-muted ml-sm">CVSS: ${result.cvss}</span>` : ''}</p>
    </div>

    ${result.cve ? `
    <div class="vuln-detail-section">
      <h4>CVE</h4>
      <p><code>${result.cve}</code></p>
    </div>
    ` : ''}

    <div class="vuln-detail-section">
      <h4>Description</h4>
      <p>${escapeHtml(result.description || 'No description available')}</p>
    </div>

    <div class="vuln-detail-section">
      <h4>URL</h4>
      <p><code class="truncate">${escapeHtml(result.url || 'N/A')}</code></p>
    </div>

    ${result.framework ? `
    <div class="vuln-detail-section">
      <h4>Framework</h4>
      <p>${result.framework}${result.version ? ` ${result.version}` : ''}</p>
    </div>
    ` : ''}

    ${result.testVector ? `
    <div class="vuln-detail-section">
      <h4>Test Vector</h4>
      <pre><code>${escapeHtml(result.testVector)}</code></pre>
    </div>
    ` : ''}

    ${result.note ? `
    <div class="vuln-detail-section">
      <h4>Note</h4>
      <p class="text-muted">${escapeHtml(result.note)}</p>
    </div>
    ` : ''}

    ${result.indicators?.length ? `
    <div class="vuln-detail-section">
      <h4>Detection Indicators</h4>
      <ul class="text-sm">
        ${result.indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;

  // Store current result for actions
  elements.vulnModal.dataset.resultId = result.id;

  // Show/hide exploit button
  elements.modalExploitBtn.classList.toggle('hidden', !result.requiresProbe);

  elements.vulnModal.classList.add('open');
}

/**
 * Close modal
 */
function closeModal() {
  elements.vulnModal.classList.remove('open');

  // Reset exploit section
  elements.exploitSection.classList.add('hidden');
  elements.exploitCommand.value = '';
  elements.exploitOutput.innerHTML = '<div class="exploit-output-placeholder">Output will appear here...</div>';
  elements.exploitStatus.textContent = '';
  elements.exploitStatus.className = 'exploit-status';
  elements.modalExploitBtn.textContent = 'Test Exploit';
}

/**
 * Copy vulnerability details to clipboard
 */
async function copyVulnDetails() {
  const resultId = elements.vulnModal.dataset.resultId;
  const result = scanResults.find(r => r.id === resultId);

  if (!result) return;

  const text = `
${result.name || result.type}
${'='.repeat(40)}
Severity: ${result.severity}
CVE: ${result.cve || 'N/A'}
URL: ${result.url}
Framework: ${result.framework || 'Unknown'}
Description: ${result.description || 'N/A'}
${result.testVector ? `Test Vector: ${result.testVector}` : ''}
  `.trim();

  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard', 'success');
  } catch (e) {
    showToast('Failed to copy', 'error');
  }
}

/**
 * Get the vulnerability type for exploit testing
 */
function getVulnType(result) {
  if (result.cve === 'CVE-2025-55182' || result.name?.includes('React2Shell')) {
    return 'react2shell';
  } else if (result.cve === 'CVE-2025-29927' || result.name?.includes('Middleware')) {
    return 'middleware-bypass';
  } else if (result.cve === 'CVE-2024-34351' || result.name?.includes('Server Action SSRF')) {
    return 'server-action-ssrf';
  } else if (result.cve === 'CVE-2025-3248' || (result.name?.includes('Langflow') && result.name?.includes('Unauthenticated'))) {
    return 'langflow-rce';
  } else if (result.cve === 'CVE-2025-34291' || result.name?.includes('Langflow CORS')) {
    return 'langflow-cors-rce';
  }
  return null;
}

/**
 * Get default command for vulnerability type
 */
function getDefaultCommand(vulnType) {
  switch (vulnType) {
    case 'react2shell':
    case 'langflow-rce':
      return 'id && whoami && hostname';
    case 'middleware-bypass':
      return ''; // No command needed
    case 'server-action-ssrf':
      return ''; // No command needed
    case 'langflow-cors-rce':
      return ''; // No command needed
    default:
      return 'echo test';
  }
}

/**
 * Toggle the exploit section visibility
 */
function toggleExploitSection() {
  const resultId = elements.vulnModal.dataset.resultId;
  const result = scanResults.find(r => r.id === resultId);

  if (!result) return;

  const vulnType = getVulnType(result);
  if (!vulnType) {
    showToast('Exploit test not available for this vulnerability type', 'info');
    return;
  }

  // Store vuln type for later use
  elements.exploitSection.dataset.vulnType = vulnType;

  // Toggle visibility
  const isHidden = elements.exploitSection.classList.contains('hidden');

  if (isHidden) {
    elements.exploitSection.classList.remove('hidden');
    elements.modalExploitBtn.textContent = 'Hide Exploit';

    // Set default command
    const defaultCmd = getDefaultCommand(vulnType);
    if (defaultCmd && !elements.exploitCommand.value) {
      elements.exploitCommand.value = defaultCmd;
    }

    // Focus input
    elements.exploitCommand.focus();
  } else {
    elements.exploitSection.classList.add('hidden');
    elements.modalExploitBtn.textContent = 'Test Exploit';
  }
}

/**
 * Add line to exploit output
 */
function addOutputLine(text, type = 'result') {
  // Clear placeholder if present
  const placeholder = elements.exploitOutput.querySelector('.exploit-output-placeholder');
  if (placeholder) {
    placeholder.remove();
  }

  const timestamp = new Date().toLocaleTimeString();
  const line = document.createElement('span');
  line.className = `output-line ${type}`;

  if (type === 'command') {
    line.innerHTML = `<span class="output-timestamp">[${timestamp}]</span>${escapeHtml(text)}`;
  } else {
    line.textContent = text;
  }

  elements.exploitOutput.appendChild(line);
  elements.exploitOutput.scrollTop = elements.exploitOutput.scrollHeight;
}

/**
 * Set exploit status message
 */
function setExploitStatus(message, type = '') {
  elements.exploitStatus.textContent = message;
  elements.exploitStatus.className = `exploit-status ${type}`;
}

/**
 * Run the exploit with the current command
 */
async function runExploit() {
  const resultId = elements.vulnModal.dataset.resultId;
  const result = scanResults.find(r => r.id === resultId);
  const vulnType = elements.exploitSection.dataset.vulnType;
  const command = elements.exploitCommand.value.trim();

  if (!result || !vulnType) {
    showToast('No vulnerability selected', 'error');
    return;
  }

  // Disable button and show loading
  elements.runExploitBtn.classList.add('loading');
  elements.runExploitBtn.disabled = true;
  setExploitStatus('Running exploit...', 'running');

  // Add command to output
  if (command) {
    addOutputLine(command, 'command');
  } else {
    addOutputLine('Running exploit probe...', 'info');
  }

  try {
    const response = await chrome.tabs.sendMessage(currentTab.id, {
      type: MESSAGE_TYPES.TEST_EXPLOIT,
      vulnType,
      options: {
        path: result.url ? new URL(result.url).pathname : '/',
        command: command || 'echo BlueDragon_Test_$(date +%s)',
        endpoint: result.url
      }
    });

    if (response.success && response.result) {
      const testResult = response.result;

      if (testResult.vulnerable === true) {
        setExploitStatus('VULNERABLE - RCE Confirmed!', 'success');
        addOutputLine('', 'result');
        addOutputLine('=== OUTPUT ===', 'success');

        // Display output line by line
        const output = testResult.output || 'Command executed (no output)';
        output.split('\n').forEach(line => {
          addOutputLine(line, 'result');
        });

        addOutputLine('', 'result');
        addOutputLine(`[+] ${testResult.message}`, 'success');

        // Update the result
        result.confirmed = true;
        result.exploitOutput = output;

      } else if (testResult.vulnerable === 'possible') {
        setExploitStatus('Possibly vulnerable', 'running');
        addOutputLine(`[?] ${testResult.message}`, 'info');
        if (testResult.note) {
          addOutputLine(`    ${testResult.note}`, 'info');
        }

      } else {
        setExploitStatus('Not vulnerable or not exploitable', 'error');
        addOutputLine(`[-] ${testResult.message}`, 'error');
        if (testResult.suggestion) {
          addOutputLine(`    Suggestion: ${testResult.suggestion}`, 'info');
        }
      }

      // Show debug info if available
      if (testResult.debug) {
        addOutputLine('', 'result');
        addOutputLine('[DEBUG] ' + testResult.debug, 'info');
      }

    } else {
      setExploitStatus('Exploit failed', 'error');
      addOutputLine(`[!] Error: ${response.error || 'Unknown error'}`, 'error');
    }

  } catch (e) {
    console.error('[BlueDragon] Exploit error:', e);
    setExploitStatus('Error running exploit', 'error');
    addOutputLine(`[!] Exception: ${e.message}`, 'error');
  } finally {
    elements.runExploitBtn.classList.remove('loading');
    elements.runExploitBtn.disabled = false;
  }
}

/**
 * Copy exploit output to clipboard
 */
async function copyExploitOutput() {
  const output = elements.exploitOutput.innerText;

  try {
    await navigator.clipboard.writeText(output);
    showToast('Output copied!', 'success');
  } catch (e) {
    showToast('Failed to copy', 'error');
  }
}

/**
 * Clear exploit output
 */
function clearExploitOutput() {
  elements.exploitOutput.innerHTML = '<div class="exploit-output-placeholder">Output will appear here...</div>';
  setExploitStatus('');
}

/**
 * Export results
 */
async function exportResults(format) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: MESSAGE_TYPES.EXPORT_REQUEST,
      format,
      data: scanResults
    });

    if (response.success) {
      // Download the exported data
      const blob = new Blob([response.exported], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `bluedragon-export-${Date.now()}.${format === 'json' ? 'json' : format === 'nuclei' ? 'yaml' : 'md'}`;
      a.click();
      URL.revokeObjectURL(url);

      showToast('Export downloaded', 'success');
    }
  } catch (e) {
    showToast('Export failed', 'error');
  }
}

/**
 * Clear results
 */
function clearResults() {
  scanResults = [];
  renderResults();
  showToast('Results cleared', 'success');
}

/**
 * Handle messages from background
 */
function handleMessage(message, sender, sendResponse) {
  switch (message.type) {
    case MESSAGE_TYPES.STATUS_UPDATE:
      if (message.data.tabId === currentTab?.id) {
        // Update progress or status
      }
      break;

    case MESSAGE_TYPES.RESULTS_UPDATE:
      if (message.data.tabId === currentTab?.id) {
        scanResults = message.data.results;
        renderResults();
      }
      break;
  }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
}

/**
 * Escape HTML
 */
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Truncate string
 */
function truncate(str, maxLength) {
  if (!str || str.length <= maxLength) return str;
  return str.substring(0, maxLength) + '...';
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
