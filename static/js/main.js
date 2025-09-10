// Enhanced AI Cybersecurity Scanner JavaScript

class CybersecurityScanner {
    constructor() {
        this.isScanning = false;
        this.scanProgress = 0;
        this.currentStep = '';
        this.urlsScanned = 0;
        this.vulnerabilities = [];
        this.lastScanResults = null;
        
        this.initializeEventListeners();
        this.loadingMessages = [
            "🔍 Initializing security scan...",
            "🎯 Analyzing target URL structure...",
            "🕷️ Starting web crawling process...",
            "⚡ Testing XSS vulnerabilities...",
            "💉 Probing for SQL injection...",
            "🤖 Running AI-powered analysis...",
            "📊 Compiling security report...",
            "✅ Finalizing results..."
        ];
        this.currentMessageIndex = 0;
        this.messageInterval = null;
    }

    initializeEventListeners() {
        // Start scan button
        const startButton = document.getElementById('start-scan');
        if (startButton) {
            startButton.addEventListener('click', () => this.startScan());
        }

        // URL input validation
        const urlInput = document.getElementById('target-url');
        if (urlInput) {
            urlInput.addEventListener('input', (e) => this.validateURL(e.target.value));
        }

        // Checkbox dependencies
        this.setupCheckboxDependencies();
    }

    validateURL(url) {
        const urlPattern = /^https?:\/\/.+/i;
        const startButton = document.getElementById('start-scan');
        
        if (!url) {
            this.showURLFeedback('', 'neutral');
            startButton.disabled = true;
            return;
        }

        if (urlPattern.test(url)) {
            this.showURLFeedback('✅ Valid URL format', 'success');
            startButton.disabled = false;
        } else {
            this.showURLFeedback('❌ Please enter a valid URL (https://example.com)', 'error');
            startButton.disabled = true;
        }
    }

    showURLFeedback(message, type) {
        let feedback = document.querySelector('.url-feedback');
        if (!feedback) {
            feedback = document.createElement('div');
            feedback.className = 'url-feedback';
            document.getElementById('target-url').parentNode.appendChild(feedback);
        }
        
        feedback.textContent = message;
        feedback.className = `url-feedback ${type}`;
    }

    setupCheckboxDependencies() {
        const crawlEnabled = document.getElementById('crawl-enabled');
        const deepCrawl = document.getElementById('deep-crawl');
        
        if (crawlEnabled && deepCrawl) {
            crawlEnabled.addEventListener('change', (e) => {
                deepCrawl.disabled = !e.target.checked;
                if (!e.target.checked) {
                    deepCrawl.checked = false;
                }
            });
        }
    }

    async startScan() {
        if (this.isScanning) return;

        const scanConfig = this.getScanConfiguration();
        if (!this.validateScanConfig(scanConfig)) {
            return;
        }

        this.isScanning = true;
        this.showScanStatus();
        this.startProgressAnimation();

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(scanConfig)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const results = await response.json();
            this.displayResults(results);
            
            // Show report generation status
            if (results.report_generated) {
                this.showReportStatus(results.report_path, true);
            } else if (scanConfig.generate_report) {
                this.showReportStatus(null, false);
            }
            
        } catch (error) {
            console.error('Scan failed:', error);
            this.showError(`Scan failed: ${error.message}`);
        } finally {
            this.hideScanStatus();
            this.stopProgressAnimation();
            this.isScanning = false;
        }
    }

    getScanConfiguration() {
        const targetUrl = document.getElementById('target-url').value.trim();
        const crawlEnabled = document.getElementById('crawl-enabled').checked;
        const deepCrawl = document.getElementById('deep-crawl').checked;
        const scanXSS = document.getElementById('scan-xss').checked;
        const scanSQLi = document.getElementById('scan-sqli').checked;
        const aiAnalysis = document.getElementById('ai-analysis').checked;
        const generateReport = document.getElementById('generate-report').checked;

        const scanTypes = [];
        if (scanXSS) scanTypes.push('xss');
        if (scanSQLi) scanTypes.push('sqli');

        return {
            url: targetUrl,
            crawl_enabled: crawlEnabled,
            deep_crawl: deepCrawl,
            scan_types: scanTypes,
            ai_analysis: aiAnalysis,
            generate_report: generateReport,
            timestamp: Date.now()
        };
    }

    validateScanConfig(config) {
        if (!config.url) {
            this.showError('Please enter a target URL');
            return false;
        }

        if (config.scan_types.length === 0) {
            this.showError('Please select at least one vulnerability type to scan');
            return false;
        }

        return true;
    }

    showReportStatus(reportPath, success) {
        const resultsContent = document.getElementById('results-content');
        const reportStatusDiv = document.createElement('div');
        reportStatusDiv.className = 'report-status';
        
        if (success && reportPath) {
            reportStatusDiv.innerHTML = `
                <div class="report-success">
                    <h4>📄 Report Generated Successfully</h4>
                    <p>Security report has been generated and saved to:</p>
                    <code>${this.escapeHtml(reportPath)}</code>
                    <div class="report-actions">
                        <button onclick="window.scanner.generateManualReport()" class="btn-secondary">
                            📄 Generate Another Report
                        </button>
                    </div>
                </div>
            `;
        } else {
            reportStatusDiv.innerHTML = `
                <div class="report-error">
                    <h4>❌ Report Generation Failed</h4>
                    <p>There was an issue generating the PDF report. You can try generating it manually.</p>
                    <div class="report-actions">
                        <button onclick="window.scanner.generateManualReport()" class="btn-secondary">
                            📄 Try Generate Report
                        </button>
                    </div>
                </div>
            `;
        }
        
        resultsContent.appendChild(reportStatusDiv);
    }

    async generateManualReport() {
        try {
            const scanData = this.lastScanResults || {};
            
            const response = await fetch('/generate_report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(scanData)
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showReportStatus(result.filepath, true);
                alert(`Report generated successfully!\nSaved to: ${result.filepath}`);
            } else {
                throw new Error(result.error || 'Unknown error');
            }
            
        } catch (error) {
            console.error('Manual report generation failed:', error);
            alert(`Report generation failed: ${error.message}`);
        }
    }

    showScanStatus() {
        const statusSection = document.getElementById('scan-status');
        const resultsSection = document.getElementById('results-section');
        
        statusSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        
        this.updateScanStatus('Initializing scan...', 0);
        this.startLoadingMessages();

        // Disable scan controls
        document.getElementById('start-scan').disabled = true;
        document.getElementById('target-url').disabled = true;
    }

    hideScanStatus() {
        const statusSection = document.getElementById('scan-status');
        statusSection.classList.add('hidden');
        
        this.stopLoadingMessages();

        // Re-enable scan controls
        document.getElementById('start-scan').disabled = false;
        document.getElementById('target-url').disabled = false;
    }

    startLoadingMessages() {
        this.currentMessageIndex = 0;
        this.updateLoadingMessage();
        
        this.messageInterval = setInterval(() => {
            this.currentMessageIndex = (this.currentMessageIndex + 1) % this.loadingMessages.length;
            this.updateLoadingMessage();
        }, 2000);
    }

    stopLoadingMessages() {
        if (this.messageInterval) {
            clearInterval(this.messageInterval);
            this.messageInterval = null;
        }
    }

    updateLoadingMessage() {
        const statusMessage = document.getElementById('status-message');
        const currentStep = document.getElementById('current-step');
        
        if (statusMessage) {
            statusMessage.textContent = this.loadingMessages[this.currentMessageIndex];
        }
        
        if (currentStep) {
            currentStep.textContent = this.loadingMessages[this.currentMessageIndex];
        }
    }

    startProgressAnimation() {
        let progress = 0;
        const progressFill = document.getElementById('progress-fill');
        const urlsScanned = document.getElementById('urls-scanned');

        const progressInterval = setInterval(() => {
            progress += Math.random() * 15;
            if (progress > 90) progress = 90;
            
            if (progressFill) {
                progressFill.style.width = progress + '%';
            }
            
            if (urlsScanned) {
                urlsScanned.textContent = `${Math.floor(progress / 10)} URLs scanned`;
            }

            if (!this.isScanning) {
                progress = 100;
                if (progressFill) progressFill.style.width = '100%';
                clearInterval(progressInterval);
            }
        }, 500);
    }

    stopProgressAnimation() {
        const progressFill = document.getElementById('progress-fill');
        if (progressFill) {
            progressFill.style.width = '100%';
        }
    }

    displayResults(results) {
        console.log('Displaying results:', results);
        
        // Store results for manual report generation
        this.lastScanResults = results;
        
        const resultsSection = document.getElementById('results-section');
        const resultsContent = document.getElementById('results-content');
        
        // Update summary metrics
        this.updateSummaryMetrics(results);
        
        // Clear previous results
        resultsContent.innerHTML = '';
        
        // Display scan results
        if (results.results && results.results.length > 0) {
            results.results.forEach((result, index) => {
                const resultCard = this.createResultCard(result, index + 1);
                resultsContent.appendChild(resultCard);
            });
        }
        
        // Display AI analysis if available
        if (results.ai_analysis) {
            const aiAnalysis = this.createAIAnalysisCard(results.ai_analysis);
            resultsContent.appendChild(aiAnalysis);
        }
        
        // Show results section
        resultsSection.classList.remove('hidden');
        
        // Smooth scroll to results
        setTimeout(() => {
            resultsSection.scrollIntoView({ 
                behavior: 'smooth', 
                block: 'start' 
            });
        }, 300);
    }

    updateSummaryMetrics(results) {
        const totalUrls = document.getElementById('total-urls');
        const vulnerabilitiesFound = document.getElementById('vulnerabilities-found');
        const riskLevel = document.getElementById('risk-level');

        if (totalUrls) {
            totalUrls.textContent = results.summary?.total_urls_scanned || 0;
        }

        if (vulnerabilitiesFound) {
            vulnerabilitiesFound.textContent = results.summary?.total_vulnerabilities || 0;
        }

        if (riskLevel) {
            const risk = results.ai_analysis?.risk_level || 'Low';
            riskLevel.textContent = risk;
            riskLevel.className = `metric-value risk-${risk.toLowerCase()}`;
        }
    }

    createResultCard(result, index) {
        const card = document.createElement('div');
        card.className = 'vulnerability-card';
        
        const hasVulnerabilities = result.xss_results?.vulnerable || result.sqli_results?.vulnerable;
        
        if (hasVulnerabilities) {
            card.classList.add('vulnerable');
        }

        card.innerHTML = `
            <div class="vuln-header">
                <div class="vuln-title">
                    <strong>🔍 URL ${index}: ${this.escapeHtml(result.url)}</strong>
                </div>
                <span class="severity-badge ${hasVulnerabilities ? 'high' : 'low'}">
                    ${hasVulnerabilities ? 'VULNERABLE' : 'SECURE'}
                </span>
            </div>
            <div class="vuln-content">
                ${this.createVulnerabilityDetails(result)}
            </div>
        `;

        return card;
    }

    createVulnerabilityDetails(result) {
        let html = '';

        // XSS Results
        if (result.xss_results) {
            html += this.formatScanResults('XSS', result.xss_results);
        }

        // SQL Injection Results
        if (result.sqli_results) {
            html += this.formatScanResults('SQL Injection', result.sqli_results);
        }

        if (!html) {
            html = '<div class="no-vulnerabilities">✅ No vulnerabilities detected for this URL</div>';
        }

        return html;
    }

    formatScanResults(scanType, results) {
        if (!results.vulnerable) {
            return `
                <div class="scan-result safe">
                    <strong>🛡️ ${scanType} Scan:</strong> No vulnerabilities detected
                </div>
            `;
        }

        let html = `
            <div class="scan-result vulnerable">
                <strong>⚠️ ${scanType} Vulnerabilities Found:</strong>
                <div class="vulnerability-list">
        `;

        if (results.vulnerabilities && results.vulnerabilities.length > 0) {
            results.vulnerabilities.forEach((vuln, index) => {
                html += `
                    <div class="vulnerability-item">
                        <div class="vuln-details">
                            <strong>Type:</strong> ${this.escapeHtml(vuln.type || 'Unknown')}
                        </div>
                        <div class="vuln-details">
                            <strong>Parameter:</strong> <code>${this.escapeHtml(vuln.parameter || 'N/A')}</code>
                        </div>
                        <div class="vuln-details">
                            <strong>Payload:</strong> <code>${this.escapeHtml(vuln.payload || 'N/A')}</code>
                        </div>
                        <div class="vuln-details">
                            <strong>Severity:</strong> 
                            <span class="severity-badge ${(vuln.severity || 'medium').toLowerCase()}">
                                ${vuln.severity || 'Medium'}
                            </span>
                        </div>
                        ${vuln.evidence ? `
                            <div class="vuln-details">
                                <strong>Evidence:</strong> ${this.escapeHtml(vuln.evidence)}
                            </div>
                        ` : ''}
                    </div>
                `;
            });
        }

        html += '</div></div>';
        return html;
    }

    createAIAnalysisCard(aiAnalysis) {
        const card = document.createElement('div');
        card.className = 'ai-analysis-card';
        
        card.innerHTML = `
            <div class="ai-header">
                <h3>🤖 AI Security Analysis</h3>
                <span class="ai-powered-badge">AI-Powered</span>
            </div>
            <div class="ai-content">
                <div class="executive-summary">
                    <h4>Executive Summary</h4>
                    <p>${this.escapeHtml(aiAnalysis.executive_summary || 'Analysis completed')}</p>
                </div>
                
                ${aiAnalysis.recommendations ? `
                    <div class="recommendations">
                        <h4>🛡️ Security Recommendations</h4>
                        <ul>
                            ${aiAnalysis.recommendations.map(rec => 
                                `<li><strong>${this.escapeHtml(rec.priority)}:</strong> ${this.escapeHtml(rec.action)}</li>`
                            ).join('')}
                        </ul>
                    </div>
                ` : ''}
                
                ${aiAnalysis.technical_details ? `
                    <div class="technical-details">
                        <h4>📊 Technical Details</h4>
                        <div class="details-grid">
                            <div class="detail-item">
                                <strong>Most Common Vulnerability:</strong>
                                <span>${this.escapeHtml(aiAnalysis.technical_details.most_common_vulnerability || 'None')}</span>
                            </div>
                            <div class="detail-item">
                                <strong>URLs Scanned:</strong>
                                <span>${aiAnalysis.technical_details.total_urls_scanned || 0}</span>
                            </div>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;

        return card;
    }

    showError(message) {
        const resultsSection = document.getElementById('results-section');
        const resultsContent = document.getElementById('results-content');
        
        resultsContent.innerHTML = `
            <div class="error-card">
                <div class="error-header">
                    <h3>❌ Scan Error</h3>
                </div>
                <div class="error-content">
                    <p>${this.escapeHtml(message)}</p>
                    <div class="error-actions">
                        <button onclick="location.reload()" class="btn-primary">
                            🔄 Try Again
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Update metrics to show error state
        document.getElementById('total-urls').textContent = '0';
        document.getElementById('vulnerabilities-found').textContent = '0';
        document.getElementById('risk-level').textContent = 'Error';
        
        resultsSection.classList.remove('hidden');
        
        // Scroll to error
        setTimeout(() => {
            resultsSection.scrollIntoView({ 
                behavior: 'smooth', 
                block: 'start' 
            });
        }, 300);
    }

    escapeHtml(text) {
        if (typeof text !== 'string') {
            return String(text || '');
        }
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    updateScanStatus(message, progress) {
        const statusMessage = document.getElementById('status-message');
        const progressFill = document.getElementById('progress-fill');
        
        if (statusMessage) {
            statusMessage.textContent = message;
        }
        
        if (progressFill) {
            progressFill.style.width = progress + '%';
        }
    }
}

// Initialize the scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 AI Cybersecurity Scanner initialized');
    
    // Initialize the main scanner class
    window.scanner = new CybersecurityScanner();
    
    // Add some interactive enhancements
    const logo = document.querySelector('.logo');
    if (logo) {
        logo.addEventListener('click', function() {
            // Easter egg - animate the logo
            logo.style.transform = 'scale(1.1)';
            setTimeout(() => {
                logo.style.transform = 'scale(1)';
            }, 200);
        });
    }
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl + Enter to start scan
        if (e.ctrlKey && e.key === 'Enter') {
            const startButton = document.getElementById('start-scan');
            if (startButton && !startButton.disabled) {
                startButton.click();
            }
        }
        
        // Escape to stop scan (if we implement this feature)
        if (e.key === 'Escape' && window.scanner.isScanning) {
            // Could implement scan cancellation here
            console.log('Scan cancellation requested via Escape key');
        }
    });
    
    // Add some visual enhancements
    const cards = document.querySelectorAll('.option-card, .metric-card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
});

// Export for potential external use
window.CybersecurityScanner = CybersecurityScanner;
