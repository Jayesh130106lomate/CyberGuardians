// analytics.js - Charts and analytics (lazy loaded)
class AnalyticsModule {
    constructor(core) {
        this.core = core;
        this.charts = {};
        this.chartInstances = {};
        this.init();
    }

    init() {
        // Initialize charts when tab is activated
        this.loadChartJS().then(() => {
            this.initializeCharts();
            this.updateAnalytics();
        });
        this.setupEventListeners();
    }

    async loadChartJS() {
        return new Promise((resolve) => {
            if (window.Chart) {
                resolve();
                return;
            }

            // Chart.js is already loaded in HTML, just wait for it
            const checkChart = () => {
                if (window.Chart) {
                    resolve();
                } else {
                    setTimeout(checkChart, 100);
                }
            };
            checkChart();
        });
    }

    initializeCharts() {
        this.createScanDistributionChart();
        this.createScanTimelineChart();
        this.createToolsUsageChart();
        this.createSuccessRateChart();
        this.createTargetTypesChart();
        this.createScanIntensityChart();
    }

    createScanDistributionChart() {
        const ctx = document.getElementById('scanDistributionChart');
        if (!ctx) return;

        this.chartInstances.scanDistribution = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Single Scans', 'Chain Scans', 'Recon Scans'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        '#6366f1',
                        '#10b981',
                        '#f59e0b'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f1f5f9',
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
    }

    createScanTimelineChart() {
        const ctx = document.getElementById('scanTimelineChart');
        if (!ctx) return;

        this.chartInstances.scanTimeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Scans per Day',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#f1f5f9'
                        }
                    }
                }
            }
        });
    }

    createToolsUsageChart() {
        const ctx = document.getElementById('toolsUsageChart');
        if (!ctx) return;

        this.chartInstances.toolsUsage = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Usage Count',
                    data: [],
                    backgroundColor: '#10b981',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#f1f5f9'
                        }
                    }
                }
            }
        });
    }

    createSuccessRateChart() {
        const ctx = document.getElementById('successRateChart');
        if (!ctx) return;

        this.chartInstances.successRate = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Successful', 'Failed'],
                datasets: [{
                    data: [0, 0],
                    backgroundColor: [
                        '#10b981',
                        '#ef4444'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f1f5f9',
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
    }

    createTargetTypesChart() {
        const ctx = document.getElementById('targetTypesChart');
        if (!ctx) return;

        this.chartInstances.targetTypes = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Domains', 'IP Addresses', 'URLs'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        '#6366f1',
                        '#10b981',
                        '#f59e0b'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#f1f5f9',
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
    }

    createScanIntensityChart() {
        const ctx = document.getElementById('scanIntensityChart');
        if (!ctx) return;

        this.chartInstances.scanIntensity = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Low', 'Medium', 'Deep'],
                datasets: [{
                    label: 'Scan Count',
                    data: [0, 0, 0],
                    backgroundColor: [
                        '#10b981',
                        '#f59e0b',
                        '#ef4444'
                    ],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#f1f5f9'
                        }
                    }
                }
            }
        });
    }

    updateAnalytics() {
        // Get scan history and update charts
        this.fetchScanHistory().then(data => {
            this.updateChartsWithRealData(data);
        }).catch(error => {
            console.error('Failed to fetch scan history:', error);
            // Clear charts on error
            this.clearAllCharts();
        });
    }

    refreshAnalytics() {
        // Force refresh analytics data
        console.log('🔄 Refreshing analytics data...');
        this.updateAnalytics();
    }

    async fetchScanHistory() {
        const response = await fetch('/api/scan-history');
        if (!response.ok) {
            throw new Error('Failed to fetch scan history');
        }
        return await response.json();
    }

    updateChartsWithRealData(scanHistory) {
        if (!scanHistory || scanHistory.length === 0) {
            // No data, show empty charts
            this.clearAllCharts();
            return;
        }

        // Process real data
        const data = this.processScanHistory(scanHistory);
        this.updateScanDistributionChart(data.scanTypes);
        this.updateScanTimelineChart(data.timeline);
        this.updateToolsUsageChart(data.tools);
        this.updateSuccessRateChart(data.successRate);
        this.updateTargetTypesChart(data.targetTypes);
        this.updateScanIntensityChart(data.intensities);
    }

    clearAllCharts() {
        // Clear all charts to show empty state
        const emptyData = {
            scanTypes: { single: 0, chain: 0, recon: 0 },
            timeline: { labels: [], data: [] },
            tools: { labels: [], data: [] },
            successRate: { success: 0, failed: 0 },
            targetTypes: { domains: 0, ips: 0, urls: 0 },
            intensities: { low: 0, medium: 0, deep: 0 }
        };

        this.updateScanDistributionChart(emptyData.scanTypes);
        this.updateScanTimelineChart(emptyData.timeline);
        this.updateToolsUsageChart(emptyData.tools);
        this.updateSuccessRateChart(emptyData.successRate);
        this.updateTargetTypesChart(emptyData.targetTypes);
        this.updateScanIntensityChart(emptyData.intensities);
    }

    processScanHistory(scanHistory) {
        const scanTypes = { single: 0, chain: 0, recon: 0 };
        const timeline = { labels: [], data: [] };
        const tools = {};
        const successRate = { success: 0, failed: 0 };
        const targetTypes = { domains: 0, ips: 0, urls: 0 };
        const intensities = { low: 0, medium: 0, deep: 0 };

        // Group scans by date for timeline
        const scansByDate = {};

        // Process each scan
        scanHistory.forEach(scan => {
            // Count scan types
            if (scan.type === 'chain') {
                scanTypes.chain++;
                // For chain scans, count each tool
                if (scan.tools && Array.isArray(scan.tools)) {
                    scan.tools.forEach(tool => {
                        tools[tool] = (tools[tool] || 0) + 1;
                    });
                }
            } else {
                // Single scan
                const tool = scan.tool;
                if (tool) {
                    tools[tool] = (tools[tool] || 0) + 1;

                    // Categorize scan type
                    if (['whois', 'dnslookup', 'sslcheck', 'httpheaders', 'portscan'].includes(tool)) {
                        scanTypes.recon++;
                    } else {
                        scanTypes.single++;
                    }
                }
            }

            // Count success/failure
            if (scan.success) {
                successRate.success++;
            } else {
                successRate.failed++;
            }

            // Analyze target types
            const target = scan.target || '';
            if (this.isDomain(target)) {
                targetTypes.domains++;
            } else if (this.isIPAddress(target)) {
                targetTypes.ips++;
            } else if (this.isURL(target)) {
                targetTypes.urls++;
            }

            // Count scan intensities
            const intensity = scan.intensity || 'medium';
            if (intensity === 'low') intensities.low++;
            else if (intensity === 'medium') intensities.medium++;
            else if (intensity === 'deep') intensities.deep++;

            // Process timeline (group by day)
            if (scan.timestamp) {
                const date = new Date(scan.timestamp).toLocaleDateString();
                scansByDate[date] = (scansByDate[date] || 0) + 1;
            }
        });

        // Create timeline data from actual scan history
        const sortedDates = Object.keys(scansByDate).sort((a, b) => new Date(a) - new Date(b));
        timeline.labels = sortedDates;
        timeline.data = sortedDates.map(date => scansByDate[date]);

        // If no timeline data, create empty labels for last 7 days
        if (timeline.labels.length === 0) {
            const last7Days = [];
            for (let i = 6; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                last7Days.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
            }
            timeline.labels = last7Days;
            timeline.data = new Array(7).fill(0);
        }

        // Convert tools object to arrays for chart
        const toolLabels = Object.keys(tools);
        const toolData = Object.values(tools);

        return {
            scanTypes,
            timeline,
            tools: {
                labels: toolLabels,
                data: toolData
            },
            successRate,
            targetTypes,
            intensities
        };
    }

    updateScanDistributionChart(data) {
        if (this.chartInstances.scanDistribution) {
            this.chartInstances.scanDistribution.data.datasets[0].data =
                [data.single || 0, data.chain || 0, data.recon || 0];
            this.chartInstances.scanDistribution.update();
        }
    }

    updateScanTimelineChart(data) {
        if (this.chartInstances.scanTimeline) {
            this.chartInstances.scanTimeline.data.labels = data.labels || [];
            this.chartInstances.scanTimeline.data.datasets[0].data = data.data || [];
            this.chartInstances.scanTimeline.update();
        }
    }

    updateToolsUsageChart(data) {
        if (this.chartInstances.toolsUsage) {
            this.chartInstances.toolsUsage.data.labels = data.labels || [];
            this.chartInstances.toolsUsage.data.datasets[0].data = data.data || [];
            this.chartInstances.toolsUsage.update();
        }
    }

    updateSuccessRateChart(data) {
        if (this.chartInstances.successRate) {
            this.chartInstances.successRate.data.datasets[0].data =
                [data.success || 0, data.failed || 0];
            this.chartInstances.successRate.update();
        }
    }

    updateTargetTypesChart(data) {
        if (this.chartInstances.targetTypes) {
            this.chartInstances.targetTypes.data.datasets[0].data =
                [data.domains || 0, data.ips || 0, data.urls || 0];
            this.chartInstances.targetTypes.update();
        }
    }

    updateScanIntensityChart(data) {
        if (this.chartInstances.scanIntensity) {
            this.chartInstances.scanIntensity.data.datasets[0].data =
                [data.low || 0, data.medium || 0, data.deep || 0];
            this.chartInstances.scanIntensity.update();
        }
    }

    // Helper methods for target type detection
    isDomain(target) {
        // Check if target looks like a domain (no protocol, no IP-like pattern)
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return domainRegex.test(target) && !this.isIPAddress(target) && !target.includes('/');
    }

    isIPAddress(target) {
        // Check for IPv4 or IPv6 addresses
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(target) || ipv6Regex.test(target);
    }

    isURL(target) {
        // Check if target contains protocol or path indicators
        return target.includes('://') || target.includes('/') || target.includes('www.');
    }

    setupEventListeners() {
        console.log('🎧 Setting up analytics event listeners');

        // Generate AI report button
        const generateBtn = document.getElementById('generateReportBtn');
        if (generateBtn) {
            console.log('✅ Found generateReportBtn, adding event listener');
            generateBtn.addEventListener('click', () => {
                console.log('🖱️ Generate Report button clicked');
                this.generateComprehensiveAIReport();
            });
        } else {
            console.warn('❌ generateReportBtn not found');
        }

        // Generate session report button
        const sessionBtn = document.getElementById('generateSessionReportBtn');
        if (sessionBtn) {
            sessionBtn.addEventListener('click', () => {
                this.generateSessionAIReport();
            });
        }

        // Export AI report button
        const exportBtn = document.getElementById('exportAIReport');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportAIReport();
            });
        }

        // Refresh analytics button
        const refreshBtn = document.getElementById('refreshAnalytics');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.refreshAnalytics();
            });
        }
    }

    destroy() {
        // Clean up charts when module is unloaded
        Object.values(this.chartInstances).forEach(chart => {
            if (chart) chart.destroy();
        });
        this.chartInstances = {};
    }

    async generateComprehensiveAIReport() {
        console.log('🚀 generateComprehensiveAIReport called');

        const generateBtn = document.getElementById('generateReportBtn');
        if (generateBtn) {
            generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
            generateBtn.disabled = true;
        }

        try {
            // Get selected options
            const reportType = document.getElementById('reportTypeSelect')?.value || 'comprehensive';
            const includeCurrentSession = document.getElementById('includeCurrentSession')?.checked || false;
            const includeScanHistory = document.getElementById('includeScanHistory')?.checked || false;
            const includeAnalytics = document.getElementById('includeAnalytics')?.checked || false;

            console.log('📋 Report options:', {
                reportType,
                includeCurrentSession,
                includeScanHistory,
                includeAnalytics
            });

            const focusVulnerabilities = document.getElementById('focusVulnerabilities')?.checked || false;
            const focusRecommendations = document.getElementById('focusRecommendations')?.checked || false;
            const focusSummary = document.getElementById('focusSummary')?.checked || false;
            const focusTechnical = document.getElementById('focusTechnical')?.checked || false;

            // Collect data based on selected options
            let scanData = [];
            let analyticsData = {};

            // Always try to get current session results first (main data source)
            try {
                console.log('🔍 Checking for results module:', {
                    windowResultsModule: !!window.resultsModule,
                    securityScannerResults: !!window.securityScanner?.modules?.results
                });

                const rawSessionResults = window.resultsModule?.getCurrentSessionResults() || [];
                console.log(`📊 generateComprehensiveAIReport: Retrieved ${rawSessionResults.length} raw current session results`);

                // Convert to backend expected format
                const sessionResults = rawSessionResults.map(result => ({
                    tool: result.tool,
                    target: 'current-session', // Default target for session results
                    output: result.output,
                    timestamp: result.timestamp,
                    success: true, // Assume success for displayed results
                    intensity: 'medium' // Default intensity
                }));

                if (sessionResults && sessionResults.length > 0) {
                    scanData = scanData.concat(sessionResults);
                    console.log(`📊 Added ${sessionResults.length} formatted current session results`);
                    console.log('📊 First formatted result:', sessionResults[0]);
                } else {
                    console.warn('⚠️ No current session results available');
                }
            } catch (error) {
                console.warn('Failed to get current session results:', error);
            }

            // Get current session results if selected (additional data)
            if (includeCurrentSession && scanData.length === 0) {
                // Already tried above, but if it failed, try again or show message
                console.log('📋 Current session checkbox is checked but no data found');
            }

            // Get scan history if selected
            if (includeScanHistory) {
                try {
                    const historyResponse = await fetch('/api/scan-history');
                    if (historyResponse.ok) {
                        const historyData = await historyResponse.json();
                        if (historyData && historyData.length > 0) {
                            // Convert history format to scan data format
                            const historyScans = historyData.map(scan => ({
                                tool: scan.tool || scan.type || 'unknown',
                                target: scan.target || 'unknown',
                                output: scan.output || scan.results?.output || '',
                                timestamp: scan.timestamp || '',
                                success: scan.success !== false,
                                intensity: scan.intensity || 'medium'
                            })).filter(scan => scan.output && scan.output.length > 20);

                            scanData = scanData.concat(historyScans);
                            console.log(`📊 Added ${historyScans.length} historical scan results`);
                        }
                    }
                } catch (error) {
                    console.warn('Failed to fetch scan history:', error);
                }
            }

            // Get analytics data if selected
            if (includeAnalytics) {
                analyticsData = {
                    scanDistribution: this.getChartData('scanDistribution'),
                    scanTimeline: this.getChartData('scanTimeline'),
                    toolsUsage: this.getChartData('toolsUsage'),
                    successRate: this.getChartData('successRate')
                };
                console.log('📊 Added analytics data');
            }

            // Build focus areas array
            const focusAreas = [];
            if (focusVulnerabilities) focusAreas.push('vulnerabilities');
            if (focusRecommendations) focusAreas.push('recommendations');
            if (focusSummary) focusAreas.push('summary');
            if (focusTechnical) focusAreas.push('technical');

            if (scanData.length === 0) {
                throw new Error('No scan data available. Please run a scan first to generate results, then try generating the AI report.');
            }

            // Prepare request payload
            const requestData = {
                scan_data: scanData,
                report_type: reportType,
                focus_areas: focusAreas,
                include_analytics: includeAnalytics,
                analytics_data: analyticsData
            };

            console.log(`🤖 Generating ${reportType} AI report with ${scanData.length} scans and focus areas:`, focusAreas);

            const response = await fetch('/api/ai-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (response.ok && data.report) {
                // Display the AI report
                this.displayAIReport(data.report, reportType, focusAreas);
                this.core.showNotification(`AI ${reportType} report generated successfully`, 'success');
            } else {
                throw new Error(data.error || 'Failed to generate AI report');
            }
        } catch (error) {
            console.error('Comprehensive AI report generation error:', error);
            this.core.showNotification(error.message || 'Failed to generate comprehensive AI report', 'error');
        } finally {
            if (generateBtn) {
                generateBtn.innerHTML = '<i class="fas fa-magic"></i> Generate Report';
                generateBtn.disabled = false;
            }
        }
    }

    async generateSessionAIReport() {
        const sessionBtn = document.getElementById('generateSessionReportBtn');
        if (sessionBtn) {
            sessionBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
            sessionBtn.disabled = true;
        }

        try {
            // Get current session results
            const rawSessionResults = window.resultsModule?.getCurrentSessionResults() || [];

            console.log(`🤖 generateSessionAIReport: Retrieved ${rawSessionResults.length} raw session results`);
            if (rawSessionResults.length > 0) {
                console.log('📊 First raw result sample:', {
                    tool: rawSessionResults[0].tool,
                    output_length: rawSessionResults[0].output?.length || 0,
                    title: rawSessionResults[0].title
                });
            }

            // Convert to backend expected format
            const sessionResults = rawSessionResults.map(result => ({
                tool: result.tool,
                target: 'current-session',
                output: result.output,
                timestamp: result.timestamp,
                success: true,
                intensity: 'medium'
            }));

            if (!sessionResults || sessionResults.length === 0) {
                throw new Error('No current session results available. Please run a scan first.');
            }

            // Get focus areas from checkboxes
            const focusAreas = [];
            if (document.getElementById('focusVulnerabilities')?.checked) focusAreas.push('vulnerabilities');
            if (document.getElementById('focusRecommendations')?.checked) focusAreas.push('recommendations');
            if (document.getElementById('focusSummary')?.checked) focusAreas.push('summary');
            if (document.getElementById('focusTechnical')?.checked) focusAreas.push('technical');

            // If no focus areas selected, use defaults
            if (focusAreas.length === 0) {
                focusAreas.push('vulnerabilities', 'recommendations', 'summary');
            }

            console.log(`🔍 Analyzing ${sessionResults.length} current session results with focus areas:`, focusAreas);

            // Prepare request payload for session-only analysis
            const requestData = {
                scan_data: sessionResults,
                report_type: 'session',
                focus_areas: focusAreas,
                include_analytics: false,
                session_only: true
            };

            const response = await fetch('/api/ai-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (response.ok && data.report) {
                // Display the session AI report
                this.displayAIReport(data.report, 'session', focusAreas);
                this.core.showNotification('Current session analysis completed', 'success');
            } else {
                throw new Error(data.error || 'Failed to analyze current session');
            }
        } catch (error) {
            console.error('Session AI report generation error:', error);
            this.core.showNotification(error.message || 'Failed to analyze current session', 'error');
        } finally {
            if (sessionBtn) {
                sessionBtn.innerHTML = '<i class="fas fa-bolt"></i> Analyze Current Results';
                sessionBtn.disabled = false;
            }
        }
    }

    getChartData(chartType) {
        // Extract data from Chart.js instances
        const chart = this.chartInstances[chartType];
        if (!chart) return {};

        return {
            labels: chart.data.labels || [],
            datasets: chart.data.datasets || []
        };
    }

    // Quick analysis functions for preset reports
    async generateQuickAnalysis() {
        // Quick analysis using current session with basic focus areas
        console.log('🚀 generateQuickAnalysis called');
        await this.generateSessionAIReport();
    }

    async generateVulnerabilityReport() {
        // Generate vulnerability-focused report
        const generateBtn = document.getElementById('generateReportBtn');
        if (generateBtn) {
            generateBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Generating...';
            generateBtn.disabled = true;
        }

        try {
            // Get current session results
            const rawSessionResults = window.resultsModule?.getCurrentSessionResults() || [];

            // Convert to backend expected format
            const sessionResults = rawSessionResults.map(result => ({
                tool: result.tool,
                target: 'current-session',
                output: result.output,
                timestamp: result.timestamp,
                success: true,
                intensity: 'medium'
            }));

            if (sessionResults.length === 0) {
                throw new Error('No current session results available. Please run a scan first.');
            }

            const requestData = {
                scan_data: sessionResults,
                report_type: 'vulnerabilities',
                focus_areas: ['vulnerabilities'],
                include_analytics: false,
                session_only: true
            };

            console.log(`🛡️ Generating vulnerability report from ${sessionResults.length} scans`);

            const response = await fetch('/api/ai-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (response.ok && data.report) {
                this.displayAIReport(data.report, 'vulnerabilities', ['vulnerabilities']);
                this.core.showNotification('Vulnerability report generated successfully', 'success');
            } else {
                throw new Error(data.error || 'Failed to generate vulnerability report');
            }
        } catch (error) {
            console.error('Vulnerability report generation error:', error);
            this.core.showNotification(error.message || 'Failed to generate vulnerability report', 'error');
        } finally {
            if (generateBtn) {
                generateBtn.innerHTML = '<i class="fas fa-magic"></i> Generate Report';
                generateBtn.disabled = false;
            }
        }
    }

    async generateExecutiveSummary() {
        // Generate executive summary report
        const generateBtn = document.getElementById('generateReportBtn');
        if (generateBtn) {
            generateBtn.innerHTML = '<i class="fas fa-chart-line"></i> Generating...';
            generateBtn.disabled = true;
        }

        try {
            // Get current session results
            const rawSessionResults = window.resultsModule?.getCurrentSessionResults() || [];

            // Convert to backend expected format
            const sessionResults = rawSessionResults.map(result => ({
                tool: result.tool,
                target: 'current-session',
                output: result.output,
                timestamp: result.timestamp,
                success: true,
                intensity: 'medium'
            }));

            if (sessionResults.length === 0) {
                throw new Error('No current session results available. Please run a scan first.');
            }

            const requestData = {
                scan_data: sessionResults,
                report_type: 'executive',
                focus_areas: ['summary'],
                include_analytics: false,
                session_only: true
            };

            console.log(`📊 Generating executive summary from ${sessionResults.length} scans`);

            const response = await fetch('/api/ai-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            if (response.ok && data.report) {
                this.displayAIReport(data.report, 'executive', ['summary']);
                this.core.showNotification('Executive summary generated successfully', 'success');
            } else {
                throw new Error(data.error || 'Failed to generate executive summary');
            }
        } catch (error) {
            console.error('Executive summary generation error:', error);
            this.core.showNotification(error.message || 'Failed to generate executive summary', 'error');
        } finally {
            if (generateBtn) {
                generateBtn.innerHTML = '<i class="fas fa-magic"></i> Generate Report';
                generateBtn.disabled = false;
            }
        }
    }

    displayAIReport(report, reportType = 'comprehensive', focusAreas = []) {
        const aiReportContainer = document.getElementById('aiReportContainer');
        if (!aiReportContainer) return;

        const reportTypeLabel = reportType === 'session' ? 'Session Analysis' :
                               reportType === 'vulnerabilities' ? 'Vulnerability Report' :
                               reportType === 'executive' ? 'Executive Summary' :
                               reportType === 'technical' ? 'Technical Deep Dive' :
                               'Comprehensive Analysis';

        const focusAreasText = focusAreas.length > 0 ? focusAreas.join(', ') : 'All areas';

        aiReportContainer.innerHTML = `
            <div class="ai-report-card">
                <div class="ai-report-header">
                    <div class="report-meta">
                        <h3><i class="fas fa-robot"></i> AI Security Report</h3>
                        <div class="report-info">
                            <span class="report-type">${reportTypeLabel}</span>
                            <span class="focus-areas">Focus: ${focusAreasText}</span>
                        </div>
                    </div>
                    <span class="ai-report-date">Generated: ${new Date().toLocaleString()}</span>
                </div>
                <div class="ai-report-content">
                    ${this.markdownToHtml(report)}
                </div>
                <div class="ai-report-actions">
                    <button class="btn btn-small" onclick="window.analyticsModule.exportAIReport()">
                        <i class="fas fa-download"></i> Export Report
                    </button>
                    <button class="btn btn-small" onclick="window.analyticsModule.generateSessionAIReport()">
                        <i class="fas fa-refresh"></i> Re-analyze Current
                    </button>
                </div>
            </div>
        `;
    }

    exportAIReport() {
        const aiReportContainer = document.getElementById('aiReportContainer');
        if (!aiReportContainer) {
            this.core.showNotification('No AI report to export', 'error');
            return;
        }

        const reportContent = aiReportContainer.querySelector('.ai-report-content');
        if (!reportContent) {
            this.core.showNotification('No AI report content to export', 'error');
            return;
        }

        const exportData = {
            timestamp: new Date().toISOString(),
            report: reportContent.innerHTML
        };

        // Create and download HTML file with professional dark theme design
        const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberGuardians - AI Security Report</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #6366f1;
            --primary-dark: #4f46e5;
            --secondary-color: #10b981;
            --danger-color: #ef4444;
            --warning-color: #f59e0b;
            --dark-bg: #0f172a;
            --darker-bg: #020617;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --success-color: #22c55e;
            --gradient-1: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-2: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --gradient-3: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            --shadow-sm: 0 2px 4px rgba(0, 0, 0, 0.2);
            --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.3);
            --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.4);
            --shadow-xl: 0 20px 25px rgba(0, 0, 0, 0.5);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            min-height: 100vh;
        }

        /* Header Section */
        .report-header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: var(--shadow-xl);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }

        .report-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 30%, rgba(99, 102, 241, 0.1) 50%, transparent 70%);
            animation: shimmer-bg 3s infinite;
        }

        @keyframes shimmer-bg {
            0%, 100% { transform: translateX(-100%); }
            50% { transform: translateX(100%); }
        }

        .header-content {
            position: relative;
            z-index: 1;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }

        .logo-section {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .logo-icon {
            width: 80px;
            height: 80px;
            background: var(--gradient-1);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-lg);
            animation: float 3s ease-in-out infinite;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }

        .logo-icon i {
            font-size: 2.5rem;
            color: white;
        }

        .header-text h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 5px;
        }

        .header-text .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
            font-weight: 500;
        }

        .report-meta {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            font-size: 0.95rem;
        }

        .meta-item:last-child {
            margin-bottom: 0;
        }

        .meta-item i {
            color: var(--primary-color);
            width: 20px;
        }

        .meta-item strong {
            color: var(--text-primary);
        }

        /* Main Content */
        .report-content {
            background: var(--card-bg);
            border-radius: 20px;
            padding: 40px;
            box-shadow: var(--shadow-xl);
            border: 1px solid var(--border-color);
            margin-bottom: 30px;
        }

        .content-header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 30px;
            border-bottom: 2px solid var(--border-color);
        }

        .content-header h2 {
            font-size: 2rem;
            font-weight: 700;
            background: var(--gradient-2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }

        .content-header .report-type-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--gradient-1);
            color: white;
            border-radius: 25px;
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Typography */
        .report-body {
            font-size: 1.1rem;
            line-height: 1.8;
        }

        .report-body h1 {
            font-size: 2.2rem;
            font-weight: 700;
            color: var(--text-primary);
            margin: 40px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 3px solid var(--primary-color);
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .report-body h1 i {
            color: var(--primary-color);
        }

        .report-body h2 {
            font-size: 1.8rem;
            font-weight: 600;
            color: var(--text-primary);
            margin: 35px 0 15px 0;
            padding: 10px 0;
            border-left: 4px solid var(--secondary-color);
            padding-left: 20px;
            background: linear-gradient(90deg, rgba(16, 185, 129, 0.1) 0%, transparent 100%);
        }

        .report-body h3 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text-primary);
            margin: 30px 0 12px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .report-body h3 i {
            color: var(--warning-color);
            font-size: 1.2rem;
        }

        .report-body p {
            margin-bottom: 20px;
            color: var(--text-secondary);
            text-align: justify;
        }

        .report-body ul, .report-body ol {
            margin: 20px 0;
            padding-left: 30px;
        }

        .report-body li {
            margin-bottom: 10px;
            color: var(--text-secondary);
            position: relative;
        }

        .report-body li::marker {
            color: var(--primary-color);
        }

        .report-body strong {
            color: var(--text-primary);
            font-weight: 600;
        }

        .report-body em {
            color: var(--text-secondary);
            font-style: italic;
        }

        /* Code blocks */
        .report-body pre {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            overflow-x: auto;
            box-shadow: var(--shadow-md);
            position: relative;
        }

        .report-body pre::before {
            content: '';
            position: absolute;
            top: 10px;
            left: 10px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--danger-color);
            box-shadow: 20px 0 0 var(--warning-color), 40px 0 0 var(--success-color);
        }

        .report-body code {
            background: rgba(99, 102, 241, 0.1);
            color: var(--primary-color);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }

        .report-body pre code {
            background: transparent;
            color: var(--text-primary);
            padding: 0;
        }

        /* Tables */
        .report-body table {
            width: 100%;
            border-collapse: collapse;
            margin: 25px 0;
            background: var(--dark-bg);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow-md);
        }

        .report-body th, .report-body td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .report-body th {
            background: var(--gradient-1);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9rem;
            letter-spacing: 0.5px;
        }

        .report-body tr:nth-child(even) {
            background: rgba(255, 255, 255, 0.02);
        }

        .report-body tr:hover {
            background: rgba(99, 102, 241, 0.1);
        }

        /* Special sections */
        .highlight-box {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 15px;
            padding: 25px;
            margin: 25px 0;
            position: relative;
            overflow: hidden;
        }

        .highlight-box::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--gradient-1);
        }

        .highlight-box.warning {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(239, 68, 68, 0.1) 100%);
            border-color: rgba(245, 158, 11, 0.3);
        }

        .highlight-box.warning::before {
            background: var(--gradient-2);
        }

        .highlight-box.success {
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(16, 185, 129, 0.1) 100%);
            border-color: rgba(34, 197, 94, 0.3);
        }

        .highlight-box.success::before {
            background: var(--success-color);
        }

        /* Footer */
        .report-footer {
            text-align: center;
            padding: 30px;
            background: var(--dark-bg);
            border-radius: 15px;
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-lg);
        }

        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }

        .footer-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 600;
            color: var(--primary-color);
        }

        .footer-meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .footer-links {
            display: flex;
            gap: 20px;
        }

        .footer-links a {
            color: var(--text-secondary);
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer-links a:hover {
            color: var(--primary-color);
        }

        /* Animations */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .report-content, .report-header, .report-footer {
            animation: fadeInUp 0.8s ease-out;
        }

        /* Print styles */
        @media print {
            body {
                background: white !important;
                color: black !important;
            }

            .report-container {
                max-width: none;
                padding: 0;
            }

            .report-header, .report-content, .report-footer {
                box-shadow: none !important;
                border: 1px solid #ccc !important;
                page-break-inside: avoid;
            }

            .report-body h1, .report-body h2, .report-body h3 {
                color: black !important;
                page-break-after: avoid;
            }

            .report-body pre {
                background: #f5f5f5 !important;
                border: 1px solid #ccc !important;
            }
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .report-container {
                padding: 10px;
            }

            .report-header, .report-content {
                padding: 20px;
            }

            .header-content {
                flex-direction: column;
                text-align: center;
            }

            .header-text h1 {
                font-size: 2rem;
            }

            .report-body h1 {
                font-size: 1.8rem;
            }

            .report-body h2 {
                font-size: 1.5rem;
            }

            .footer-content {
                flex-direction: column;
                gap: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <header class="report-header">
            <div class="header-content">
                <div class="logo-section">
                    <div class="logo-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="header-text">
                        <h1>CyberGuardians</h1>
                        <div class="subtitle">Advanced Security Analysis Platform</div>
                    </div>
                </div>
                <div class="report-meta">
                    <div class="meta-item">
                        <i class="fas fa-chart-line"></i>
                        <span><strong>Report Type:</strong> Comprehensive Analysis</span>
                    </div>
                    <div class="meta-item">
                        <i class="fas fa-target"></i>
                        <span><strong>Focus Areas:</strong> Focus: All areas</span>
                    </div>
                    <div class="meta-item">
                        <i class="fas fa-calendar-alt"></i>
                        <span><strong>Generated:</strong> ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <main class="report-content">
            <div class="content-header">
                <h2><i class="fas fa-robot"></i> AI Security Analysis Report</h2>
                <div class="report-type-badge">
                    <i class="fas fa-certificate"></i>
                    Comprehensive Analysis
                </div>
            </div>

            <div class="report-body">
                ${reportContent.innerHTML}
            </div>
        </main>

        <!-- Footer -->
        <footer class="report-footer">
            <div class="footer-content">
                <div class="footer-logo">
                    <i class="fas fa-shield-alt"></i>
                    CyberGuardians Security Platform
                </div>
                <div class="footer-meta">
                    Report generated on ${new Date().toLocaleDateString()} at ${new Date().toLocaleTimeString()}
                </div>
                <div class="footer-links">
                    <a href="#" onclick="window.print(); return false;">
                        <i class="fas fa-print"></i> Print Report
                    </a>
                    <a href="https://github.com/Jayesh130106lomate/CyberGuardians" target="_blank">
                        <i class="fab fa-github"></i> View on GitHub
                    </a>
                </div>
            </div>
        </footer>
    </div>

    <script>
        // Add some interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Smooth scrolling for anchor links
            const links = document.querySelectorAll('a[href^="#"]');
            links.forEach(link => {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({ behavior: 'smooth' });
                    }
                });
            });

            // Add click tracking for interactive elements
            const highlightBoxes = document.querySelectorAll('.highlight-box');
            highlightBoxes.forEach(box => {
                box.addEventListener('click', function() {
                    this.style.transform = 'scale(0.98)';
                    setTimeout(() => {
                        this.style.transform = 'scale(1)';
                    }, 150);
                });
            });

            // Add print optimization
            window.addEventListener('beforeprint', function() {
                document.body.classList.add('printing');
            });

            window.addEventListener('afterprint', function() {
                document.body.classList.remove('printing');
            });
        });
    </script>
</body>
</html>`;

        const dataBlob = new Blob([htmlContent], {type: 'text/html'});
        const url = URL.createObjectURL(dataBlob);

        const link = document.createElement('a');
        link.href = url;
        link.download = `cyberguardians_ai_security_report_${new Date().toISOString().split('T')[0]}.html`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        this.core.showNotification('Professional AI report exported successfully!', 'success');
    }

    markdownToHtml(markdown) {
        // Simple markdown to HTML converter
        if (!markdown) return '';

        return markdown
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            .replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>')
            .replace(/\*(.*)\*/gim, '<em>$1</em>')
            .replace(/^\- (.*$)/gim, '<li>$1</li>')
            .replace(/^\d+\. (.*$)/gim, '<li>$1</li>')
            .replace(/\n\n/gim, '</p><p>')
            .replace(/\n/gim, '<br>')
            .replace(/<\/p><p>/g, '</p>\n\n<p>')
            .replace(/^/, '<p>')
            .replace(/$/, '</p>');
    }
}

// Export for lazy loading
window.AnalyticsModule = AnalyticsModule;

// Global functions for HTML onclick handlers
window.generateQuickAnalysis = async function() {
    if (window.analyticsModule) {
        await window.analyticsModule.generateQuickAnalysis();
    } else {
        console.error('Analytics module not loaded');
    }
};

window.generateVulnerabilityReport = async function() {
    if (window.analyticsModule) {
        await window.analyticsModule.generateVulnerabilityReport();
    } else {
        console.error('Analytics module not loaded');
    }
};

window.generateExecutiveSummary = async function() {
    if (window.analyticsModule) {
        await window.analyticsModule.generateExecutiveSummary();
    } else {
        console.error('Analytics module not loaded');
    }
};

// Lazy load function
window.loadAnalytics = function() {
    if (!window.analyticsModule) {
        window.analyticsModule = new AnalyticsModule(window.coreUtils || window.securityScanner?.modules?.core);
    }
};