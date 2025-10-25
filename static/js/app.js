// ============================================
// 🚀 Modular Security Scanner - Optimized for Mobile
// Security Scanner Pro - Modular Application Loader
// Features: Modular architecture, lazy loading, mobile optimization
// ============================================

// Global application state
window.SecurityScanner = {
    modules: {},
    config: {
        apiBaseUrl: window.location.origin,
        maxRetries: 3,
        timeout: 30000
    }
};

// SecurityScanner Main Class
class SecurityScanner {
    constructor() {
        this.modules = {};
        this.init();
    }

    async init() {
        console.log('🚀 Initializing Security Scanner Pro...');

        try {
            // Load core module first
            console.log('Loading core.js...');
            await this.loadScript('core.js');
            this.modules.core = new window.CoreUtils();
            console.log('Core module loaded');

            // Load all modules since we're using single-page application
            console.log('Loading scanner.js...');
            await this.loadScript('scanner.js');
            this.modules.scanner = new window.ScannerModule(this.modules.core);
            console.log('Scanner module loaded');

            // Make scanner module globally accessible for HTML event handlers
            window.scannerModule = this.modules.scanner;

            console.log('Loading terminal.js...');
            await this.loadScript('terminal.js');
            this.modules.terminal = new window.TerminalModule(this.modules.core);
            console.log('Terminal module loaded');

            console.log('Loading results.js...');
            await this.loadScript('results.js');
            this.modules.results = new window.ResultsModule(this.modules.core);
            window.resultsModule = this.modules.results; // Set global reference for analytics
            console.log('Results module loaded');

            // Load analytics module
            console.log('Loading analytics.js...');
            await this.loadScript('analytics.js');
            this.modules.analytics = new window.AnalyticsModule(this.modules.core);
            window.analyticsModule = this.modules.analytics; // Set global reference
            console.log('Analytics module loaded');

            // Set up global references for backward compatibility
            window.coreUtils = this.modules.core;

            // Initialize core utilities (this handles tab navigation)
            console.log('Initializing core utilities...');
            await this.modules.core.init();
            console.log('Core utilities initialized');

            // Start monitoring scan status
            this.startStatusMonitoring();

            console.log('✅ Security Scanner initialized with modular architecture');

        } catch (error) {
            console.error('❌ Failed to initialize application:', error);
            showInitializationError(error);
        }
    }

    async loadScript(filename) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = `/static/js/${filename}`;
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    startStatusMonitoring() {
        // Monitor scan status and update UI accordingly
        setInterval(async () => {
            try {
                const response = await fetch('/api/scan-status');
                const status = await response.json();
                this.updateGlobalStatus(status);
            } catch (error) {
                console.error('Status monitoring error:', error);
            }
        }, 2000); // Less frequent polling for mobile optimization
    }

    updateGlobalStatus(status) {
        // Update results if available
        console.log('🔄 updateGlobalStatus called with:', {
            hasResults: !!status.results,
            chainResultsLength: status.chain_results?.length || 0,
            hasResultsModule: !!this.modules.results
        });

        if ((status.results || (status.chain_results && status.chain_results.length > 0)) && this.modules.results) {
            if (status.chain_results && status.chain_results.length > 0) {
                console.log('📊 Displaying chain results:', status.chain_results.length);
                this.modules.results.displayChainResults(status.chain_results);
            } else if (status.results) {
                console.log('📊 Displaying single scan result');
                this.modules.results.displayScanResult(status.results);
            }
        } else {
            console.warn('⚠️ No results to display or results module not available');
        }

        // Update AI analysis
        if (status.ai_analysis && this.modules.results) {
            this.modules.results.displayAIAnalysis(status.ai_analysis);
        }

        // Update live AI analysis
        if (status.live_ai_analysis && this.modules.results) {
            this.modules.results.displayLiveAIAnalysis(status.live_ai_analysis);
        }

        // Update status indicator
        if (this.modules.core) {
            const statusType = status.running ? 'warning' :
                (status.results?.success ? 'success' : 'error');
            const statusMessage = status.running ? 'Scan in progress...' :
                (status.results?.success ? 'Scan completed' : 'Scan failed');
            this.modules.core.updateStatus(statusMessage, statusType);
        }
    }
}

// Lazy load analytics module only when charts tab is accessed
function setupAnalyticsLazyLoading() {
    const chartsTab = document.querySelector('[data-tab="charts"]');
    const aiReportTab = document.querySelector('[data-tab="ai-report"]');

    if (chartsTab) {
        chartsTab.addEventListener('click', async function loadAnalytics() {
            if (window.analyticsModule || window.securityScanner.modules.analytics) {
                return; // Already loaded
            }

            try {
                console.log('📊 Loading analytics module...');

                // Dynamically load analytics module
                await loadScript('/static/js/analytics.js');

                const analyticsModule = new window.AnalyticsModule(window.securityScanner.modules.core);
                window.analyticsModule = analyticsModule;
                window.securityScanner.modules.analytics = analyticsModule; // Also set in scanner modules

                await analyticsModule.init();

                console.log('✅ Analytics module loaded successfully');

                // Remove event listener after first load
                chartsTab.removeEventListener('click', loadAnalytics);

            } catch (error) {
                console.error('❌ Failed to load analytics module:', error);
            }
        });
    }

    if (aiReportTab) {
        aiReportTab.addEventListener('click', async function loadAnalyticsForAI() {
            if (window.analyticsModule || window.securityScanner.modules.analytics) {
                return; // Already loaded
            }

            try {
                console.log('🤖 Loading analytics module for AI reports...');

                // Dynamically load analytics module
                await loadScript('/static/js/analytics.js');

                const analyticsModule = new window.AnalyticsModule(window.securityScanner.modules.core);
                window.analyticsModule = analyticsModule;
                window.securityScanner.modules.analytics = analyticsModule; // Also set in scanner modules

                await analyticsModule.init();

                console.log('✅ Analytics module loaded successfully for AI reports');

                // Remove event listener after first load
                aiReportTab.removeEventListener('click', loadAnalyticsForAI);

            } catch (error) {
                console.error('❌ Failed to load analytics module for AI reports:', error);
            }
        });
    }
}

// Helper function to load scripts dynamically
function loadScript(src) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

// Error handling for initialization failures
function showInitializationError(error) {
    const container = document.querySelector('.container');
    if (container) {
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #1e293b;
            border: 1px solid #ef4444;
            border-radius: 8px;
            padding: 20px;
            max-width: 400px;
            text-align: center;
            z-index: 9999;
        `;
        errorDiv.innerHTML = `
            <h3 style="color: #ef4444; margin-bottom: 10px;">⚠️ Initialization Error</h3>
            <p style="color: #94a3b8; margin-bottom: 15px;">Failed to load Security Scanner Pro</p>
            <details style="text-align: left;">
                <summary style="cursor: pointer; color: #6366f1;">Error Details</summary>
                <pre style="background: #0f172a; padding: 10px; border-radius: 4px; margin-top: 10px; font-size: 12px; color: #ef4444;">${error.message}</pre>
            </details>
            <button onclick="location.reload()" style="margin-top: 15px; padding: 8px 16px; background: #6366f1; color: white; border: none; border-radius: 4px; cursor: pointer;">Reload Page</button>
        `;
        container.appendChild(errorDiv);
    }
}

// Global error handler
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
});

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.securityScanner = new SecurityScanner();
    setupAnalyticsLazyLoading();
});
