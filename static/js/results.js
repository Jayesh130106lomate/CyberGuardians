// results.js - Results display and management
class ResultsModule {
    constructor(core) {
        this.core = core;
        this.init();
    }

    init() {
        // Results are updated via status polling, no specific setup needed
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Setup any event listeners needed for the results module
        const scanButton = document.getElementById('scanButton');
        if (scanButton) {
            scanButton.addEventListener('click', () => {
                this.core.startScan();
            });
        }

        // Clear results button
        const clearBtn = document.getElementById('clearResults');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearResults();
            });
        }

        // Export results button
        const exportBtn = document.getElementById('exportResults');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportResults();
            });
        }

        // Add more event listeners as needed
    }

    displayScanResult(result) {
        const resultsContainer = document.getElementById('resultsContainer');
        if (!resultsContainer) return;

        // Clear previous results
        resultsContainer.innerHTML = '';

        if (!result) {
            resultsContainer.innerHTML = '<div class="empty-state">No scan results available</div>';
            return;
        }

        // Create result card
        const resultCard = document.createElement('div');
        resultCard.className = 'result-card';

        const statusClass = result.success ? 'badge-success' : 'badge-error';
        const statusText = result.success ? 'Success' : 'Failed';

        resultCard.innerHTML = `
            <div class="result-header">
                <h3>Scan Results</h3>
                <span class="badge ${statusClass}">${statusText}</span>
            </div>
            <div class="result-meta">
                <span><i class="fas fa-clock"></i> ${new Date().toLocaleString()}</span>
                <span><i class="fas fa-cog"></i> Tool: ${result.tool || 'Unknown'}</span>
            </div>
            <div class="result-output">
                <pre>${this.escapeHtml(result.output || 'No output')}</pre>
            </div>
        `;

        resultsContainer.appendChild(resultCard);
    }

    displayChainResults(chainResults) {
        const resultsContainer = document.getElementById('resultsContainer');
        if (!resultsContainer) {
            console.warn('⚠️ displayChainResults: Results container not found');
            return;
        }

        console.log(`📊 displayChainResults: Displaying ${chainResults?.length || 0} chain results`);

        resultsContainer.innerHTML = '';

        if (!chainResults || chainResults.length === 0) {
            console.warn('⚠️ displayChainResults: No chain results to display');
            resultsContainer.innerHTML = '<div class="empty-state">No chain results available</div>';
            return;
        }

        chainResults.forEach((item, index) => {
            const result = item.result;
            if (!result) {
                console.warn(`⚠️ displayChainResults: Item ${index} has no result`);
                return;
            }

            console.log(`📊 displayChainResults: Creating card for ${item.tool} (output length: ${result.output?.length || 0})`);

            const resultCard = document.createElement('div');
            resultCard.className = 'result-card';

            const statusClass = result.success ? 'badge-success' : 'badge-error';
            const statusText = result.success ? 'Success' : 'Failed';

            resultCard.innerHTML = `
                <div class="result-header">
                    <h3>${item.tool.toUpperCase()} Scan ${index + 1}</h3>
                    <span class="badge ${statusClass}">${statusText}</span>
                </div>
                <div class="result-meta">
                    <span><i class="fas fa-clock"></i> ${new Date().toLocaleString()}</span>
                </div>
                <div class="result-output">
                    <pre>${this.escapeHtml(result.output || 'No output')}</pre>
                </div>
            `;

            resultsContainer.appendChild(resultCard);
        });

        console.log(`✅ displayChainResults: Successfully displayed ${chainResults.length} results`);
    }

    displayAIAnalysis(aiAnalysis) {
        const aiContainer = document.getElementById('aiAnalysisContainer');
        if (!aiContainer) return;

        if (!aiAnalysis) {
            aiContainer.innerHTML = '<div class="empty-state">No AI analysis available</div>';
            return;
        }

        // Check if this is enhanced analysis with vulnerabilities
        const hasVulnerabilities = aiAnalysis.vulnerabilities && aiAnalysis.vulnerabilities.length > 0;

        let vulnerabilitiesHtml = '';
        if (hasVulnerabilities) {
            vulnerabilitiesHtml = `
                <div class="vulnerabilities-section">
                    <h4><i class="fas fa-shield-alt"></i> Vulnerability Intelligence (${aiAnalysis.vulnerabilities.length} CVEs found)</h4>
                    <div class="vulnerabilities-list">
                        ${aiAnalysis.vulnerabilities.map(vuln => `
                            <div class="vulnerability-item severity-${vuln.severity?.toLowerCase() || 'unknown'}">
                                <div class="vulnerability-header">
                                    <span class="cve-id">${vuln.id}</span>
                                    <span class="severity-badge ${vuln.severity?.toLowerCase() || 'unknown'}">${vuln.severity || 'UNKNOWN'}</span>
                                </div>
                                <div class="vulnerability-content">
                                    <p class="description">${this.escapeHtml(vuln.description || 'No description available')}</p>
                                    ${vuln.cvss_v3 ? `<p class="cvss-score">CVSS v3 Score: ${vuln.cvss_v3.baseScore || 'N/A'}</p>` : ''}
                                    ${vuln.detected_software ? `<p class="detected-software">Detected in: ${this.escapeHtml(vuln.detected_software)}</p>` : ''}
                                    ${vuln.references && vuln.references.length > 0 ? `
                                        <div class="references">
                                            <small>References:</small>
                                            <ul>
                                                ${vuln.references.slice(0, 3).map(ref => `<li><a href="${ref.url}" target="_blank">${ref.source || 'Link'}</a></li>`).join('')}
                                            </ul>
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        aiContainer.innerHTML = `
            <div class="ai-analysis-card">
                <div class="ai-header">
                    <h3><i class="fas fa-robot"></i> AI Security Analysis ${hasVulnerabilities ? '+ Vulnerability Intelligence' : ''}</h3>
                    <span class="ai-badge">Powered by Gemini</span>
                </div>
                <div class="ai-content">
                    ${this.markdownToHtml(aiAnalysis.analysis || aiAnalysis)}
                </div>
                ${vulnerabilitiesHtml}
            </div>
        `;
    }

    displayLiveAIAnalysis(analysis) {
        const resultsContainer = document.getElementById('resultsContainer');
        if (!resultsContainer) return;

        // Check if live AI card already exists
        let liveAICard = document.getElementById('live-ai-card');

        if (!liveAICard) {
            // Remove empty state and create live AI card
            const emptyState = resultsContainer.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            liveAICard = document.createElement('div');
            liveAICard.id = 'live-ai-card';
            liveAICard.className = 'result-card live-ai-card';
            resultsContainer.insertBefore(liveAICard, resultsContainer.firstChild);
        }

        // Update content with live analysis
        liveAICard.innerHTML = `
            <div class="result-header live-ai-header">
                <h3>
                    <i class="fas fa-robot"></i> Live AI Analysis
                    <span class="live-badge">🔴 LIVE</span>
                </h3>
                <span class="badge badge-ai">Real-time</span>
            </div>
            <div class="ai-analysis live-ai-content">
                ${this.markdownToHtml(analysis)}
            </div>
            <div class="live-ai-footer">
                <small>⚡ Updating as scan progresses...</small>
            </div>
        `;
    }

    removeLiveAICard() {
        const liveAICard = document.getElementById('live-ai-card');
        if (liveAICard) {
            liveAICard.remove();
        }
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

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    clearResults() {
        const resultsContainer = document.getElementById('resultsContainer');
        const aiContainer = document.getElementById('aiAnalysisContainer');

        if (resultsContainer) {
            resultsContainer.innerHTML = '<div class="empty-state">No results to display</div>';
        }

        if (aiContainer) {
            aiContainer.innerHTML = '<div class="empty-state">No AI analysis available</div>';
        }

        this.removeLiveAICard();
    }

    exportResults() {
        const resultsContainer = document.getElementById('resultsContainer');
        const aiContainer = document.getElementById('aiAnalysisContainer');

        let exportData = {
            timestamp: new Date().toISOString(),
            results: [],
            aiAnalysis: null
        };

        // Collect results data
        if (resultsContainer) {
            const resultCards = resultsContainer.querySelectorAll('.result-card');
            resultCards.forEach(card => {
                const header = card.querySelector('.result-header h3');
                const output = card.querySelector('.result-output pre');
                if (header && output) {
                    exportData.results.push({
                        title: header.textContent.trim(),
                        output: output.textContent.trim()
                    });
                }
            });
        }

        // Collect AI analysis data
        if (aiContainer) {
            const aiCard = aiContainer.querySelector('.ai-analysis-card .ai-content');
            if (aiCard) {
                exportData.aiAnalysis = aiCard.innerHTML;
            }
        }

        // Create and download JSON file
        const dataStr = JSON.stringify(exportData, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);

        const link = document.createElement('a');
        link.href = url;
        link.download = `scan_results_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        this.core.showNotification('Results exported successfully', 'success');
    }

    // New method to get current session results for AI report generation
    getCurrentSessionResults() {
        const resultsContainer = document.getElementById('resultsContainer');
        const sessionResults = [];

        if (resultsContainer) {
            const resultCards = resultsContainer.querySelectorAll('.result-card:not(#live-ai-card)');
            console.log(`🔍 getCurrentSessionResults: Found ${resultCards.length} result cards`);

            resultCards.forEach((card, index) => {
                const header = card.querySelector('.result-header h3');
                const output = card.querySelector('.result-output pre');
                const meta = card.querySelector('.result-meta');

                if (header && output) {
                    const result = {
                        title: header.textContent.trim(),
                        output: output.textContent.trim(),
                        timestamp: new Date().toISOString(),
                        tool: 'unknown'
                    };

                    // Extract tool name from title or meta
                    if (meta) {
                        const toolMatch = meta.textContent.match(/Tool: (\w+)/);
                        if (toolMatch) {
                            result.tool = toolMatch[1].toLowerCase();
                        }
                    }

                    // Extract tool from title for chain scans (e.g., "NMAP Scan 1" -> "nmap")
                    const titleMatch = header.textContent.match(/^(\w+)\s+Scan/);
                    if (titleMatch) {
                        result.tool = titleMatch[1].toLowerCase();
                        console.log(`🔧 Extracted tool from title: "${header.textContent}" -> "${result.tool}"`);
                    } else {
                        console.warn(`⚠️ Could not extract tool from title: "${header.textContent}"`);
                    }

                    console.log(`📊 Extracted result ${index + 1}: tool=${result.tool}, output_length=${result.output.length}`);
                    sessionResults.push(result);
                } else {
                    console.warn(`⚠️ Result card ${index + 1} missing header or output elements`);
                }
            });
        } else {
            console.warn('⚠️ Results container not found');
        }

        console.log(`✅ getCurrentSessionResults returning ${sessionResults.length} results`);
        return sessionResults;
    }

    // Method to generate AI report from current session results
    async generateSessionAIReport(options = {}) {
        const sessionResults = this.getCurrentSessionResults();

        if (sessionResults.length === 0) {
            throw new Error('No current session results available for AI analysis');
        }

        // Prepare data for AI analysis
        const scanData = sessionResults.map(result => ({
            tool: result.tool,
            target: 'current-session', // Could be enhanced to extract from results
            output: result.output,
            timestamp: result.timestamp,
            success: true, // Assume success if results are displayed
            intensity: 'medium'
        }));

        // Call AI report generation with session data
        const response = await fetch('/api/ai-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_results: scanData,
                report_type: options.reportType || 'comprehensive',
                focus_areas: options.focusAreas || ['vulnerabilities', 'recommendations', 'summary'],
                include_history: false // Don't include historical data for session reports
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to generate AI report');
        }

        return data.report;
    }
}

// Export for module system
window.ResultsModule = ResultsModule;