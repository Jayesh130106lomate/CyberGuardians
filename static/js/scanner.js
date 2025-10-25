// scanner.js - Unified Scanner Module with Mode Switching
class ScannerModule {
    constructor(core) {
        this.core = core;
        this.currentMode = 'single'; // 'single', 'chain'
        this.advancedOptions = {
            timeout: 30,
            concurrency: 2,
            executionMode: 'sequential',
            enableAI: true,
            enableVulnerabilityIntel: false,
            intensity: 'medium'
        };
        this.init();
    }

    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.initializeScanner();
            });
        } else {
            // DOM is already ready
            this.initializeScanner();
        }
    }

    initializeScanner() {
        this.setupModeTabs();
        this.setupAdvancedOptions();
        this.setupSingleScanForm();
        this.setupChainScanForm();
        this.setupUnifiedProgress();
        this.setDefaultMode();
    }

    // Mode Tab Management
    setupModeTabs() {
        const modeTabs = document.querySelectorAll('.mode-tab');
        modeTabs.forEach(tab => {
            tab.addEventListener('click', (e) => {
                const mode = e.target.closest('.mode-tab').dataset.mode;
                this.switchMode(mode);
            });
        });
    }

    switchMode(mode) {
        // Update active tab
        document.querySelectorAll('.mode-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        const modeTab = document.querySelector(`[data-mode="${mode}"]`);
        if (modeTab) {
            modeTab.classList.add('active');
        }

        // Update active content
        document.querySelectorAll('.scan-mode-content').forEach(content => {
            content.style.display = 'none';
            content.classList.remove('active');
        });
        const activeContent = document.getElementById(`${mode}ModeContent`);
        if (activeContent) {
            activeContent.style.display = 'block';
            activeContent.classList.add('active');
        }

        this.currentMode = mode;
        this.updateProgressModeIndicator();
    }

    setDefaultMode() {
        this.switchMode('single');
    }

    // Advanced Options Management
    setupAdvancedOptions() {
        const toggleBtn = document.getElementById('toggleAdvanced');
        const content = document.getElementById('advancedOptions');

        if (toggleBtn && content) {
            toggleBtn.addEventListener('click', () => {
                const isVisible = content.style.display !== 'none';
                content.style.display = isVisible ? 'none' : 'block';
                const icon = toggleBtn.querySelector('i');
                if (icon) {
                    icon.className = isVisible ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
                }
            });

            // Initially hide advanced options
            content.style.display = 'none';
        }

        // Setup option inputs
        this.setupAdvancedOptionInputs();
    }

    setupAdvancedOptionInputs() {
        // Timeout input
        const timeoutInput = document.getElementById('timeout');
        if (timeoutInput) {
            timeoutInput.value = this.advancedOptions.timeout;
            timeoutInput.addEventListener('input', (e) => {
                this.advancedOptions.timeout = parseInt(e.target.value) || 30;
            });
        }

        // Concurrency input
        const concurrencyInput = document.getElementById('maxConcurrency');
        if (concurrencyInput) {
            concurrencyInput.value = this.advancedOptions.concurrency;
            concurrencyInput.addEventListener('input', (e) => {
                this.advancedOptions.concurrency = parseInt(e.target.value) || 2;
            });
        }

        // Execution mode select
        const executionModeSelect = document.getElementById('executionMode');
        if (executionModeSelect) {
            executionModeSelect.value = this.advancedOptions.executionMode;
            executionModeSelect.addEventListener('change', (e) => {
                this.advancedOptions.executionMode = e.target.value;
                this.updateExecutionModeIndicator();
            });
        }

        // Enable AI checkbox
        const enableAICheckbox = document.getElementById('enableAI');
        if (enableAICheckbox) {
            enableAICheckbox.checked = this.advancedOptions.enableAI;
            enableAICheckbox.addEventListener('change', (e) => {
                this.advancedOptions.enableAI = e.target.checked;
            });
        }

        const enableVulnIntelCheckbox = document.getElementById('enableVulnerabilityIntel');
        if (enableVulnIntelCheckbox) {
            enableVulnIntelCheckbox.checked = this.advancedOptions.enableVulnerabilityIntel;
            enableVulnIntelCheckbox.addEventListener('change', (e) => {
                this.advancedOptions.enableVulnerabilityIntel = e.target.checked;
            });
        }

        // Intensity select
        const intensitySelect = document.getElementById('intensity');
        if (intensitySelect) {
            intensitySelect.value = this.advancedOptions.intensity;
            intensitySelect.addEventListener('change', (e) => {
                this.advancedOptions.intensity = e.target.value;
            });
        }
    }

    updateExecutionModeIndicator() {
        const indicators = document.querySelectorAll('.execution-mode-indicator');
        indicators.forEach(indicator => {
            indicator.className = `execution-mode-indicator ${this.advancedOptions.executionMode}`;
            indicator.innerHTML = `<i class="fas fa-${this.advancedOptions.executionMode === 'sequential' ? 'arrow-right' : 'arrows-alt'}"></i> ${this.advancedOptions.executionMode}`;
        });
    }

    // Single Scan Form
    setupSingleScanForm() {
        const scanForm = document.getElementById('unifiedScanForm');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startScanBasedOnMode();
            });
        }

        // Stop button
        const stopBtn = document.getElementById('stopScanBtn');
        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                this.stopScan();
            });
        }
    }

    startScanBasedOnMode() {
        switch (this.currentMode) {
            case 'single':
                this.startSingleScan();
                break;
            case 'chain':
                this.startChainScan();
                break;
            default:
                this.core.showNotification('Unknown scan mode', 'error');
        }
    }

    async startSingleScan() {
        const target = document.getElementById('target')?.value?.trim();
        const tool = document.getElementById('tool')?.value;

        if (!target || !tool) {
            this.core.showNotification('Please enter target and select tool', 'error');
            return;
        }

        // Update UI
        const scanBtn = document.getElementById('startScanBtn');
        if (scanBtn) {
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
            scanBtn.disabled = true;
        }

        // Enable stop button
        const stopBtn = document.getElementById('stopScanBtn');
        if (stopBtn) stopBtn.disabled = false;

        this.core.updateStatus('Starting single scan...', 'warning');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target: target,
                    tool: tool,
                    intensity: this.advancedOptions.intensity,
                    enable_ai: this.advancedOptions.enableAI,
                    enable_vulnerability_intel: this.advancedOptions.enableVulnerabilityIntel,
                    timeout: this.advancedOptions.timeout
                })
            });

            const data = await response.json();

            if (response.ok && data.message === 'Scan started') {
                this.core.showNotification('Single scan started successfully', 'success');
                this.core.updateStatus('Single scan in progress...', 'warning');
                this.startUnifiedScanMonitoring();
            } else {
                throw new Error(data.error || 'Failed to start scan');
            }
        } catch (error) {
            console.error('Scan error:', error);
            this.core.showNotification(error.message || 'Failed to start scan', 'error');
            this.resetSingleScanUI();
        }
    }

    resetSingleScanUI() {
        const scanBtn = document.getElementById('startScanBtn');
        if (scanBtn) {
            scanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
            scanBtn.disabled = false;
        }

        const stopBtn = document.getElementById('stopScanBtn');
        if (stopBtn) stopBtn.disabled = true;
    }

    // Chain Scan Form
    setupChainScanForm() {
        // Setup predefined chain selector
        const predefinedChainSelect = document.getElementById('predefinedChain');
        if (predefinedChainSelect) {
            predefinedChainSelect.addEventListener('change', (e) => {
                this.handlePredefinedChainSelection(e.target.value);
            });
        }

        // Setup tool checkboxes
        this.setupToolCheckboxes();

        // Setup action buttons
        const selectAllBtn = document.getElementById('selectAllTools');
        if (selectAllBtn) {
            selectAllBtn.addEventListener('click', () => this.selectAllTools());
        }

        const clearAllBtn = document.getElementById('clearAllTools');
        if (clearAllBtn) {
            clearAllBtn.addEventListener('click', () => this.clearAllTools());
        }

        const invertBtn = document.getElementById('invertSelection');
        if (invertBtn) {
            invertBtn.addEventListener('click', () => this.invertSelection());
        }

        // Update tool count initially
        this.updateToolCount();
    }

    setupToolCheckboxes() {
        const checkboxes = document.querySelectorAll('.tool-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => {
                this.updateToolCount();
            });
        });
    }

    handlePredefinedChainSelection(chainId) {
        // Clear all current selections
        this.clearAllTools();

        if (!chainId) return;

        const predefinedChains = {
            'quick_recon': ['whois', 'dnslookup', 'sslcheck'],
            'web_audit': ['whois', 'dnslookup', 'sslcheck', 'httpheaders', 'whatweb', 'nikto'],
            'network_deep': ['whois', 'dnslookup', 'portscan', 'nmap', 'masscan'],
            'wordpress_full': ['whois', 'dnslookup', 'sslcheck', 'whatweb', 'wpscan', 'nikto'],
            'complete': ['whois', 'dnslookup', 'sslcheck', 'httpheaders', 'portscan', 'nmap', 'whatweb', 'nikto', 'wpscan']
        };

        const tools = predefinedChains[chainId] || [];
        tools.forEach(tool => {
            const checkbox = document.getElementById(`tool_${tool}`);
            if (checkbox) {
                checkbox.checked = true;
            }
        });

        this.updateToolCount();
    }

    selectAllTools() {
        const checkboxes = document.querySelectorAll('.tool-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = true;
        });
        this.updateToolCount();
    }

    clearAllTools() {
        const checkboxes = document.querySelectorAll('.tool-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
        });
        this.updateToolCount();
    }

    invertSelection() {
        const checkboxes = document.querySelectorAll('.tool-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = !checkbox.checked;
        });
        this.updateToolCount();
    }

    updateToolCount() {
        const checkedBoxes = document.querySelectorAll('.tool-checkbox:checked');
        const countElement = document.getElementById('selectedCount');
        if (countElement) {
            countElement.textContent = `(${checkedBoxes.length} selected)`;
        }
    }

    async startChainScan() {
        const target = document.getElementById('target')?.value?.trim();
        const selectedTools = Array.from(document.querySelectorAll('.tool-checkbox:checked')).map(cb => cb.value);
        const intensity = document.getElementById('chainIntensity')?.value || 'medium';
        const executionMode = document.getElementById('executionMode')?.value || 'sequential';

        if (!target) {
            this.core.showNotification('Please enter target', 'error');
            return;
        }

        if (selectedTools.length === 0) {
            this.core.showNotification('Please select at least one tool', 'error');
            return;
        }

        // Update UI
        const scanBtn = document.getElementById('startScanBtn');
        if (scanBtn) {
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting Chain...';
            scanBtn.disabled = true;
        }

        // Enable stop button
        const stopBtn = document.getElementById('stopScanBtn');
        if (stopBtn) stopBtn.disabled = false;

        this.core.updateStatus('Starting chain scan...', 'warning');

        try {
            const response = await fetch('/api/chain-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target: target,
                    tools: selectedTools,
                    intensity: intensity,
                    enable_ai: this.advancedOptions.enableAI,
                    enable_vulnerability_intel: this.advancedOptions.enableVulnerabilityIntel,
                    timeout: this.advancedOptions.timeout
                })
            });

            const data = await response.json();

            if (response.ok && data.message === 'Chain scan started') {
                this.core.showNotification('Chain scan started successfully', 'success');
                this.core.updateStatus('Chain scan in progress...', 'warning');
                this.startUnifiedScanMonitoring();
            } else {
                throw new Error(data.error || 'Failed to start chain scan');
            }
        } catch (error) {
            console.error('Chain scan error:', error);
            this.core.showNotification(error.message || 'Failed to start chain scan', 'error');
            this.resetChainScanUI();
        }
    }

    resetChainScanUI() {
        // Reset scan button
        const scanBtn = document.getElementById('startScanBtn');
        if (scanBtn) {
            scanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
            scanBtn.disabled = false;
        }

        const stopBtn = document.getElementById('stopScanBtn');
        if (stopBtn) stopBtn.disabled = true;
    }

    // Unified Progress Management
    setupUnifiedProgress() {
        // Progress is handled in the HTML, just ensure it's initialized
        this.updateProgressModeIndicator();
        this.updateExecutionModeIndicator();
    }

    updateProgressModeIndicator() {
        const indicator = document.getElementById('progressModeIndicator');
        if (indicator) {
            const modeNames = {
                'single': 'Single Tool Scan',
                'chain': 'Chain Scan'
            };
            indicator.textContent = modeNames[this.currentMode] || 'Unknown Mode';
        }
    }

    startUnifiedScanMonitoring() {
        // Show progress section
        const progressSection = document.getElementById('unifiedProgressSection');
        if (progressSection) {
            progressSection.style.display = 'block';
        }

        // Clear any existing monitoring
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }

        // Start monitoring scan status
        this.monitoringInterval = setInterval(() => {
            this.checkUnifiedScanStatus();
        }, 1000);
    }

    async checkUnifiedScanStatus() {
        try {
            const response = await fetch('/api/scan-status');
            const status = await response.json();

            this.updateUnifiedProgressUI(status);

            if (!status.running) {
                // Scan completed
                clearInterval(this.monitoringInterval);
                this.handleUnifiedScanCompletion(status);
            }
        } catch (error) {
            console.error('Status check error:', error);
        }
    }

    updateUnifiedProgressUI(status) {
        // Update overall progress
        const progressFill = document.getElementById('progressFill');
        const progressPercent = document.getElementById('progressPercent');

        if (progressFill && status.progress !== undefined) {
            progressFill.style.width = `${status.progress}%`;
        }

        if (progressPercent) {
            progressPercent.textContent = `${status.progress || 0}%`;
        }

        // Update current tool info
        const currentToolIcon = document.getElementById('currentToolIcon');
        const currentToolName = document.getElementById('currentToolName');
        const currentToolDesc = document.getElementById('currentToolDesc');

        if (status.current_tool) {
            if (currentToolIcon) {
                currentToolIcon.innerHTML = `<i class="fas fa-${this.getToolIcon(status.current_tool)}"></i>`;
            }
            if (currentToolName) {
                currentToolName.textContent = this.getToolName(status.current_tool);
            }
            if (currentToolDesc) {
                currentToolDesc.textContent = status.tool_status || 'Running...';
            }
        }

        // Update step queue for chain scans
        this.updateStepQueue(status);
    }

    updateStepQueue(status) {
        const stepQueue = document.getElementById('stepQueue');
        if (!stepQueue) return;

        stepQueue.innerHTML = '';

        if (status.chain_progress && Array.isArray(status.chain_progress)) {
            status.chain_progress.forEach((step, index) => {
                const stepElement = document.createElement('div');
                stepElement.className = `step-queue-item ${step.status}`;

                stepElement.innerHTML = `
                    <div class="step-queue-number">${index + 1}</div>
                    <div class="step-queue-name">${this.getToolName(step.tool)}</div>
                    <div class="step-queue-status">${step.status}</div>
                `;

                stepQueue.appendChild(stepElement);
            });
        }
    }

    handleUnifiedScanCompletion(status) {
        const modeNames = {
            'single': 'Single scan',
            'chain': 'Chain scan'
        };

        this.core.updateStatus(`${modeNames[this.currentMode]} completed`, status.results?.success ? 'success' : 'error');

        if (status.results?.success) {
            this.core.showNotification(`${modeNames[this.currentMode]} completed successfully`, 'success');
        } else {
            this.core.showNotification(`${modeNames[this.currentMode]} failed or was stopped`, 'error');
        }

        this.resetAllScanUIs();

        // Switch to results tab if scan was successful
        if (status.results?.success) {
            setTimeout(() => {
                this.core.switchTab('results');
                // Refresh analytics with new scan data
                if (window.analyticsModule) {
                    window.analyticsModule.refreshAnalytics();
                }
            }, 500);
        }
    }

    resetAllScanUIs() {
        // Reset single scan UI
        this.resetSingleScanUI();

        // Reset chain scan UI
        this.resetChainScanUI();

        // Reset unified progress
        const progressSection = document.getElementById('unifiedProgressSection');
        if (progressSection) {
            progressSection.style.display = 'none';
        }

        const progressFill = document.getElementById('progressFill');
        if (progressFill) progressFill.style.width = '0%';

        const progressPercent = document.getElementById('progressPercent');
        if (progressPercent) progressPercent.textContent = '0%';
    }

    async stopScan() {
        try {
            const response = await fetch('/api/stop-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const data = await response.json();

            if (response.ok) {
                this.core.showNotification('Scan stopped successfully', 'info');
                this.core.updateStatus('Scan stopped', 'info');
                clearInterval(this.monitoringInterval);
                this.resetAllScanUIs();
            } else {
                throw new Error(data.error || 'Failed to stop scan');
            }
        } catch (error) {
            this.core.showNotification('Failed to stop scan', 'error');
        }
    }

    // Utility methods
    getToolName(toolId) {
        const toolNames = {
            'whois': 'WHOIS Lookup',
            'dnslookup': 'DNS Lookup',
            'sslcheck': 'SSL Certificate Check',
            'httpheaders': 'HTTP Headers Audit',
            'portscan': 'Port Scanner',
            'nmap': 'Nmap Network Scanner',
            'masscan': 'Masscan Port Scanner',
            'whatweb': 'WhatWeb Technology Scanner',
            'nikto': 'Nikto Web Scanner',
            'wpscan': 'WPScan WordPress Scanner',
            'sqlmap': 'SQLMap Injection Tester',
            'metasploit': 'Metasploit Framework',
            'burpsuite': 'Burp Suite Scanner',
            'wireshark': 'Wireshark Analyzer'
        };
        return toolNames[toolId] || toolId.replace(/^\w/, c => c.toUpperCase());
    }

    getToolIcon(toolId) {
        const toolIcons = {
            'whois': 'search',
            'dnslookup': 'globe',
            'sslcheck': 'lock',
            'httpheaders': 'file-code',
            'portscan': 'plug',
            'nmap': 'network-wired',
            'masscan': 'tachometer-alt',
            'whatweb': 'spider',
            'nikto': 'bug',
            'wpscan': 'wordpress',
            'sqlmap': 'database',
            'metasploit': 'bug',
            'burpsuite': 'shield-alt',
            'wireshark': 'wave-square'
        };
        return toolIcons[toolId] || 'tool';
    }
}

// Export for module system
window.ScannerModule = ScannerModule;