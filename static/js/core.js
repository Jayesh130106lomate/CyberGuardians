// core.js - Core functionality and utilities
class CoreUtils {
    constructor() {
        this.currentTab = 'scanner';
        this.scanHistory = [];
        this.charts = {};
        this.terminalEventSource = null;
        this.currentScanId = null;
        this.scanStartTime = null;
        this.timerInterval = null;
        this.vulnerabilityCounts = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0
        };
    }

    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.setupTabNavigation();
                this.setupEventListeners();
                this.loadToolsList();
                this.loadScanHistory();
            });
        } else {
            // DOM is already ready
            this.setupTabNavigation();
            this.setupEventListeners();
            this.loadToolsList();
            this.loadScanHistory();
        }
    }

    setupTabNavigation() {
        console.log('Setting up tab navigation...');

        // Set up click handlers for tabs
        const tabButtons = document.querySelectorAll('.tab-btn');
        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const tabId = button.getAttribute('data-tab');
                this.switchTab(tabId);
            });
        });

        // Get initial tab from URL hash or default to scanner
        const hash = window.location.hash.substring(1) || 'scanner';
        this.switchTab(hash);

        this.currentTab = hash;
    }

    switchTab(tabId) {
        console.log('Switching to tab:', tabId);

        // Update URL hash without triggering navigation
        window.location.hash = tabId;

        // Remove active class from all tabs
        const allTabs = document.querySelectorAll('.tab-btn');
        allTabs.forEach(tab => {
            tab.classList.remove('active');
        });

        // Add active class to clicked tab
        const activeBtn = document.querySelector(`[data-tab="${tabId}"]`);
        if (activeBtn) {
            activeBtn.classList.add('active');
        }

        // Hide all tab content
        const allContent = document.querySelectorAll('.tab-content');
        allContent.forEach(content => {
            content.classList.remove('active');
        });

        // Show selected tab content
        const activeContent = document.getElementById(tabId);
        if (activeContent) {
            activeContent.classList.add('active');
        }

        // Load content for specific tabs if needed
        this.loadTabContent(tabId);

        this.currentTab = tabId;
    }

    loadTabContent(tabId) {
        // Load dynamic content for certain tabs
        if (tabId === 'tools') {
            this.loadToolsList();
        } else if (tabId === 'history') {
            this.loadScanHistory();
        } else if (tabId === 'charts') {
            // Charts will be loaded when the tab becomes active
            if (window.AnalyticsModule && !window.analyticsModule) {
                // Initialize analytics module if not already done
                window.analyticsModule = new window.AnalyticsModule(this);
            }
            if (window.analyticsModule) {
                window.analyticsModule.updateAnalytics();
            }
        }
    }

    setupEventListeners() {
        // Global event listeners
        document.addEventListener('DOMContentLoaded', () => {
            this.updateStatus('Ready');
        });

        // Tools tab event listeners
        const refreshToolsBtn = document.getElementById('refreshTools');
        if (refreshToolsBtn) {
            refreshToolsBtn.addEventListener('click', () => {
                this.refreshTools();
            });
        }

        // History tab event listeners
        const clearHistoryBtn = document.getElementById('clearHistory');
        if (clearHistoryBtn) {
            clearHistoryBtn.addEventListener('click', () => {
                this.clearHistory();
            });
        }
    }

    updateStatus(message, type = 'info') {
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');

        if (statusDot) {
            statusDot.className = `status-dot status-${type}`;
        }
        if (statusText) {
            statusText.textContent = message;
        }
    }

    showNotification(message, type = 'info') {
        // Simple notification system
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'times' : 'info'}"></i>
            ${message}
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    async loadToolsList() {
        try {
            const response = await fetch('/api/check-tools');
            const data = await response.json();

            // Update tools display
            this.updateToolsDisplay(data.tools);
        } catch (error) {
            console.error('Failed to load tools:', error);
        }
    }

    updateToolsDisplay(tools) {
        const toolsContainer = document.getElementById('toolsGrid');
        if (!toolsContainer) return;

        toolsContainer.innerHTML = '';

        Object.entries(tools).forEach(([toolName, toolInfo]) => {
            const toolCard = document.createElement('div');
            toolCard.className = `tool-card ${toolInfo.installed ? 'installed' : 'not-installed'}`;

            toolCard.innerHTML = `
                <div class="tool-header">
                    <h4>${toolName.toUpperCase()}</h4>
                    <span class="tool-status ${toolInfo.installed ? 'status-success' : 'status-error'}">
                        ${toolInfo.installed ? '✓' : '✗'}
                    </span>
                </div>
                <div class="tool-info">
                    <p>${toolInfo.description}</p>
                    ${toolInfo.version ? `<small>Version: ${toolInfo.version}</small>` : ''}
                </div>
            `;

            toolsContainer.appendChild(toolCard);
        });
    }

    async loadScanHistory() {
        try {
            const response = await fetch('/api/scan-history');
            const history = await response.json();

            this.scanHistory = history;
            this.updateHistoryDisplay();
        } catch (error) {
            console.error('Failed to load scan history:', error);
        }
    }

    updateHistoryDisplay() {
        const historyContainer = document.getElementById('historyContainer');
        if (!historyContainer) return;

        if (this.scanHistory.length === 0) {
            historyContainer.innerHTML = '<div class="empty-state">No scan history available</div>';
            return;
        }

        historyContainer.innerHTML = '';

        this.scanHistory.slice(0, 10).forEach(scan => {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';

            historyItem.innerHTML = `
                <div class="history-header">
                    <span class="history-tool">${scan.tool || scan.type || 'Unknown'}</span>
                    <span class="history-time">${new Date(scan.timestamp).toLocaleString()}</span>
                </div>
                <div class="history-target">${scan.target || 'Unknown target'}</div>
                <div class="history-status status-${scan.success ? 'success' : 'error'}">
                    ${scan.success ? 'Success' : 'Failed'}
                </div>
            `;

            historyContainer.appendChild(historyItem);
        });
    }

    async refreshTools() {
        const refreshBtn = document.getElementById('refreshTools');
        if (refreshBtn) {
            refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
            refreshBtn.disabled = true;
        }

        try {
            await this.loadToolsList();
            this.showNotification('Tools list refreshed successfully', 'success');
        } catch (error) {
            console.error('Failed to refresh tools:', error);
            this.showNotification('Failed to refresh tools list', 'error');
        } finally {
            if (refreshBtn) {
                refreshBtn.innerHTML = '<i class="fas fa-sync"></i> Refresh';
                refreshBtn.disabled = false;
            }
        }
    }

    async clearHistory() {
        const clearBtn = document.getElementById('clearHistory');
        if (clearBtn) {
            clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
            clearBtn.disabled = true;
        }

        try {
            const response = await fetch('/api/clear-history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            const data = await response.json();

            if (response.ok) {
                this.scanHistory = [];
                this.updateHistoryDisplay();
                this.showNotification('Scan history cleared successfully', 'success');
                // Refresh analytics after clearing history
                if (window.analyticsModule) {
                    window.analyticsModule.refreshAnalytics();
                }
            } else {
                throw new Error(data.error || 'Failed to clear history');
            }
        } catch (error) {
            console.error('Failed to clear history:', error);
            this.showNotification(error.message || 'Failed to clear scan history', 'error');
        } finally {
            if (clearBtn) {
                clearBtn.innerHTML = '<i class="fas fa-trash"></i> Clear History';
                clearBtn.disabled = false;
            }
        }
    }
}

// Export for module system
window.CoreUtils = CoreUtils;