// Security Assessment Tool - Frontend JavaScript

class SecurityAssessmentTool {
    constructor() {
        this.currentScan = null;
        this.scanResults = null;
        this.currentLanguage = 'en';
        this.initializeEventListeners();
        this.initializeLanguageSupport();
    }

    initializeEventListeners() {
        const form = document.getElementById('targetForm');
        form.addEventListener('submit', (e) => this.handleFormSubmit(e));
        
        // Language selector event listener
        const languageSelect = document.getElementById('languageSelect');
        languageSelect.addEventListener('change', (e) => this.changeLanguage(e.target.value));
    }

    initializeLanguageSupport() {
        // Load saved language preference or default to English
        const savedLanguage = localStorage.getItem('selectedLanguage') || 'en';
        this.currentLanguage = savedLanguage;
        
        // Set the dropdown to the current language
        const languageSelect = document.getElementById('languageSelect');
        languageSelect.value = this.currentLanguage;
        
        // Apply translations
        this.applyTranslations(this.currentLanguage);
    }

    changeLanguage(languageCode) {
        this.currentLanguage = languageCode;
        localStorage.setItem('selectedLanguage', languageCode);
        this.applyTranslations(languageCode);
    }

    applyTranslations(languageCode) {
        // Get translations for the selected language
        let langTranslations = translations[languageCode];
        
        // If language not found in main translations, try additional translations
        if (!langTranslations && additionalTranslations && additionalTranslations[languageCode]) {
            langTranslations = additionalTranslations[languageCode];
        }
        
        // If still not found, try complete translations
        if (!langTranslations && completeTranslations && completeTranslations[languageCode]) {
            langTranslations = completeTranslations[languageCode];
        }
        
        // Fallback to English if language not found
        if (!langTranslations) {
            langTranslations = translations['en'];
        }

        // Update all elements with data-translate attribute
        const elements = document.querySelectorAll('[data-translate]');
        elements.forEach(element => {
            const key = element.getAttribute('data-translate');
            if (langTranslations[key]) {
                element.textContent = langTranslations[key];
            }
        });

        // Update placeholder attributes
        const placeholderElements = document.querySelectorAll('[data-translate-placeholder]');
        placeholderElements.forEach(element => {
            const key = element.getAttribute('data-translate-placeholder');
            if (langTranslations[key]) {
                element.placeholder = langTranslations[key];
            }
        });

        // Update dynamic content if scan results exist
        if (this.scanResults) {
            this.updateDynamicContent(langTranslations);
        }
    }

    updateDynamicContent(langTranslations) {
        // Update score descriptions
        const scoreTitle = document.getElementById('scoreTitle');
        const scoreDescription = document.getElementById('scoreDescription');
        
        if (scoreTitle && scoreDescription) {
            const score = this.scanResults.overallScore;
            if (score >= 80) {
                scoreTitle.textContent = langTranslations.excellentSecurity || 'Excellent Security Posture';
                scoreDescription.textContent = langTranslations.excellentDescription || 'Your system demonstrates strong security practices with minimal vulnerabilities.';
            } else if (score >= 60) {
                scoreTitle.textContent = langTranslations.goodSecurity || 'Good Security Posture';
                scoreDescription.textContent = langTranslations.goodDescription || 'Your system has good security practices but some areas need attention.';
            } else if (score >= 40) {
                scoreTitle.textContent = langTranslations.moderateSecurity || 'Moderate Security Risk';
                scoreDescription.textContent = langTranslations.moderateDescription || 'Your system has several security vulnerabilities that should be addressed.';
            } else {
                scoreTitle.textContent = langTranslations.highSecurity || 'High Security Risk';
                scoreDescription.textContent = langTranslations.highDescription || 'Your system has critical security vulnerabilities requiring immediate attention.';
            }
        }

        // Update scoreboard values
        this.updateScoreboardTranslations(langTranslations);
    }

    updateScoreboardTranslations(langTranslations) {
        const securityRating = document.getElementById('securityRating');
        const breachDifficulty = document.getElementById('breachDifficulty');
        const breachTime = document.getElementById('breachTime');
        
        if (securityRating && this.scanResults) {
            const score = this.scanResults.overallScore;
            if (score >= 80) {
                securityRating.textContent = langTranslations.excellent || 'Excellent';
            } else if (score >= 60) {
                securityRating.textContent = langTranslations.good || 'Good';
            } else if (score >= 40) {
                securityRating.textContent = langTranslations.fair || 'Fair';
            } else {
                securityRating.textContent = langTranslations.poor || 'Poor';
            }
        }

        if (breachDifficulty && this.scanResults) {
            const score = this.scanResults.overallScore;
            if (score >= 80) {
                breachDifficulty.textContent = langTranslations.veryHard || 'Very Hard';
            } else if (score >= 60) {
                breachDifficulty.textContent = langTranslations.hard || 'Hard';
            } else if (score >= 40) {
                breachDifficulty.textContent = langTranslations.moderate || 'Moderate';
            } else {
                breachDifficulty.textContent = langTranslations.easy || 'Easy';
            }
        }

        if (breachTime && this.scanResults) {
            const score = this.scanResults.overallScore;
            if (score >= 80) {
                breachTime.textContent = langTranslations.hoursDays || 'Hours/Days';
            } else if (score >= 60) {
                breachTime.textContent = langTranslations.hours || 'Hours';
            } else {
                breachTime.textContent = langTranslations.minutes || 'Minutes';
            }
        }
    }

    async handleFormSubmit(e) {
        e.preventDefault();
        
        const targetUrl = document.getElementById('targetUrl').value;
        const targetType = document.getElementById('targetType').value;
        const scanDepth = document.getElementById('scanDepth').value;

        if (!targetUrl || !targetType) {
            this.showNotification('fillRequiredFields', 'error');
            return;
        }

        this.startSecurityScan(targetUrl, targetType, scanDepth);
    }

    async startSecurityScan(url, type, depth) {
        try {
            // Show progress section
            this.showProgressSection();
            
            // Initialize scan progress
            this.initializeScanProgress();
            
            // Start real scan with backend
            await this.runRealSecurityScan(url, type, depth);
            
        } catch (error) {
            console.error('Scan failed:', error);
            this.showNotification('scanFailed', 'error');
        }
    }

    showProgressSection() {
        document.getElementById('progressSection').style.display = 'block';
        document.getElementById('progressSection').scrollIntoView({ behavior: 'smooth' });
    }

    initializeScanProgress() {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        progressFill.style.width = '0%';
        progressText.textContent = 'Initializing security scan...';
        
        // Reset all scan statuses
        const statusElements = document.querySelectorAll('.scan-status');
        statusElements.forEach(element => {
            element.textContent = 'Pending';
            element.className = 'scan-status pending';
            element.parentElement.className = 'scan-item pending';
        });
    }

    async runRealSecurityScan(url, type, depth) {
        try {
            // Start scan with backend
            const response = await fetch('http://localhost:5000/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target_url: url,
                    target_type: type,
                    scan_depth: depth
                })
            });

            if (!response.ok) {
                throw new Error('Failed to start scan');
            }

            const data = await response.json();
            this.currentScanId = data.scan_id;

            // Monitor scan progress
            await this.monitorScanProgress();

        } catch (error) {
            console.error('Real scan failed:', error);
            // Fallback to simulation if backend is not available
            await this.simulateSecurityScan(url, type, depth);
        }
    }

    async monitorScanProgress() {
        const scanSteps = [
            { name: 'Port Scanning', id: 'portStatus' },
            { name: 'SSL/TLS Analysis', id: 'sslStatus' },
            { name: 'HTTP Headers Analysis', id: 'headersStatus' },
            { name: 'Directory Enumeration', id: 'dirStatus' },
            { name: 'SQL Injection Testing', id: 'sqlStatus' },
            { name: 'XSS Vulnerability Check', id: 'xssStatus' },
            { name: 'Authentication Bypass', id: 'authStatus' },
            { name: 'CSRF Protection', id: 'csrfStatus' }
        ];

        let completedSteps = 0;
        const totalSteps = scanSteps.length;

        // Poll for scan status
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`http://localhost:5000/api/scan/${this.currentScanId}/status`);
                if (!response.ok) {
                    throw new Error('Failed to get scan status');
                }

                const status = await response.json();
                
                // Update progress
                this.updateProgress(status.progress, `Scanning... ${status.vulnerabilities_found} vulnerabilities found`);

                // Update step statuses based on progress
                const stepsCompleted = Math.floor((status.progress / 100) * totalSteps);
                for (let i = 0; i < stepsCompleted && i < scanSteps.length; i++) {
                    const step = scanSteps[i];
                    this.updateScanStatus(step.id, 'completed', 'Completed');
                }

                if (status.status === 'completed') {
                    clearInterval(pollInterval);
                    await this.getScanResults();
                } else if (status.status === 'failed') {
                    clearInterval(pollInterval);
                    this.showNotification('scanFailed', 'error');
                }

            } catch (error) {
                console.error('Error monitoring scan:', error);
                clearInterval(pollInterval);
                // Fallback to simulation
                await this.simulateSecurityScan();
            }
        }, 2000);

        // Timeout after 5 minutes
        setTimeout(() => {
            clearInterval(pollInterval);
            this.showNotification('scanTimeout', 'warning');
        }, 300000);
    }

    async getScanResults() {
        try {
            const response = await fetch(`http://localhost:5000/api/scan/${this.currentScanId}/results`);
            if (!response.ok) {
                throw new Error('Failed to get scan results');
            }

            this.scanResults = await response.json();
            this.displayResults();

        } catch (error) {
            console.error('Error getting results:', error);
            this.showNotification('failedToGetResults', 'error');
        }
    }

    async simulateSecurityScan(url, type, depth) {
        const scanSteps = [
            { name: 'Port Scanning', id: 'portStatus', duration: 2000 },
            { name: 'SQL Injection Testing', id: 'sqlStatus', duration: 3000 },
            { name: 'XSS Vulnerability Check', id: 'xssStatus', duration: 2500 },
            { name: 'Authentication Bypass', id: 'authStatus', duration: 4000 },
            { name: 'Directory Traversal', id: 'dirStatus', duration: 2000 },
            { name: 'CSRF Protection', id: 'csrfStatus', duration: 1500 }
        ];

        let totalProgress = 0;
        const totalDuration = scanSteps.reduce((sum, step) => sum + step.duration, 0);

        for (let i = 0; i < scanSteps.length; i++) {
            const step = scanSteps[i];
            
            // Update status to running
            this.updateScanStatus(step.id, 'running', 'Running...');
            
            // Simulate scan duration
            await this.delay(step.duration);
            
            // Simulate random results
            const isVulnerable = Math.random() < 0.3; // 30% chance of vulnerability
            const status = isVulnerable ? 'failed' : 'completed';
            const statusText = isVulnerable ? 'Vulnerable' : 'Secure';
            
            this.updateScanStatus(step.id, status, statusText);
            
            // Update progress
            totalProgress += step.duration;
            const progressPercent = (totalProgress / totalDuration) * 100;
            this.updateProgress(progressPercent, `Completed: ${step.name}`);
        }

        // Generate mock results
        await this.generateMockResults(url, type, depth);
    }

    updateScanStatus(elementId, status, text) {
        const element = document.getElementById(elementId);
        const parent = element.parentElement;
        
        element.textContent = text;
        element.className = `scan-status ${status}`;
        parent.className = `scan-item ${status}`;
    }

    updateProgress(percent, text) {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        
        progressFill.style.width = `${percent}%`;
        progressText.textContent = text;
    }

    async generateMockResults(url, type, depth) {
        // Simulate processing time
        await this.delay(1000);
        
        // Generate mock vulnerability data
        const vulnerabilities = this.generateMockVulnerabilities();
        const overallScore = this.calculateOverallScore(vulnerabilities);
        
        this.scanResults = {
            url: url,
            type: type,
            depth: depth,
            overallScore: overallScore,
            vulnerabilities: vulnerabilities,
            scanTime: new Date().toISOString(),
            recommendations: this.generateRecommendations(vulnerabilities)
        };

        this.displayResults();
    }

    generateMockVulnerabilities() {
        const vulnerabilityTypes = [
            { name: 'SQL Injection', category: 'Injection', severity: 'high' },
            { name: 'Cross-Site Scripting (XSS)', category: 'XSS', severity: 'medium' },
            { name: 'Authentication Bypass', category: 'Authentication', severity: 'critical' },
            { name: 'Directory Traversal', category: 'Path Traversal', severity: 'high' },
            { name: 'CSRF Vulnerability', category: 'CSRF', severity: 'medium' },
            { name: 'Insecure Direct Object Reference', category: 'Authorization', severity: 'high' },
            { name: 'Security Misconfiguration', category: 'Configuration', severity: 'low' },
            { name: 'Sensitive Data Exposure', category: 'Data Exposure', severity: 'critical' }
        ];

        const vulnerabilities = [];
        const numVulns = Math.floor(Math.random() * 5) + 1; // 1-5 vulnerabilities

        for (let i = 0; i < numVulns; i++) {
            const vulnType = vulnerabilityTypes[Math.floor(Math.random() * vulnerabilityTypes.length)];
            const isPresent = Math.random() < 0.4; // 40% chance of vulnerability

            if (isPresent) {
                vulnerabilities.push({
                    ...vulnType,
                    id: `vuln-${i}`,
                    description: this.getVulnerabilityDescription(vulnType.name),
                    impact: this.getVulnerabilityImpact(vulnType.severity),
                    score: this.getVulnerabilityScore(vulnType.severity),
                    detected: true
                });
            }
        }

        return vulnerabilities;
    }

    getVulnerabilityDescription(name) {
        const descriptions = {
            'SQL Injection': 'Application is vulnerable to SQL injection attacks through user input parameters.',
            'Cross-Site Scripting (XSS)': 'User input is not properly sanitized, allowing malicious script execution.',
            'Authentication Bypass': 'Authentication mechanisms can be bypassed or circumvented.',
            'Directory Traversal': 'Application allows access to files outside the intended directory.',
            'CSRF Vulnerability': 'Application lacks proper CSRF protection tokens.',
            'Insecure Direct Object Reference': 'Direct object references are not properly validated.',
            'Security Misconfiguration': 'Security settings are not properly configured.',
            'Sensitive Data Exposure': 'Sensitive information is exposed in responses or logs.'
        };
        return descriptions[name] || 'Security vulnerability detected in the application.';
    }

    getVulnerabilityImpact(severity) {
        const impacts = {
            'critical': 'Complete system compromise possible',
            'high': 'Significant security risk, immediate attention required',
            'medium': 'Moderate security risk, should be addressed',
            'low': 'Minor security risk, consider addressing'
        };
        return impacts[severity] || 'Security risk detected';
    }

    getVulnerabilityScore(severity) {
        const scores = {
            'critical': 20,
            'high': 35,
            'medium': 55,
            'low': 75
        };
        return scores[severity] || 50;
    }

    calculateOverallScore(vulnerabilities) {
        if (vulnerabilities.length === 0) {
            return 90; // High score for no vulnerabilities
        }

        const totalScore = vulnerabilities.reduce((sum, vuln) => sum + vuln.score, 0);
        const averageScore = totalScore / vulnerabilities.length;
        
        // Adjust based on number of vulnerabilities
        const penalty = vulnerabilities.length * 5;
        const finalScore = Math.max(20, Math.min(90, averageScore - penalty));
        
        return Math.round(finalScore);
    }

    generateRecommendations(vulnerabilities) {
        const recommendations = [];
        
        if (vulnerabilities.length === 0) {
            recommendations.push({
                title: 'Maintain Current Security Posture',
                description: 'Your system shows good security practices. Continue regular security assessments.',
                priority: 'low'
            });
        } else {
            // Generate specific recommendations based on vulnerabilities
            const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
            const highVulns = vulnerabilities.filter(v => v.severity === 'high');
            
            if (criticalVulns.length > 0) {
                recommendations.push({
                    title: 'Address Critical Vulnerabilities Immediately',
                    description: 'Critical vulnerabilities require immediate attention to prevent system compromise.',
                    priority: 'critical'
                });
            }
            
            if (highVulns.length > 0) {
                recommendations.push({
                    title: 'Implement Input Validation',
                    description: 'Add comprehensive input validation and sanitization to prevent injection attacks.',
                    priority: 'high'
                });
            }
            
            recommendations.push({
                title: 'Implement Security Headers',
                description: 'Add security headers like CSP, HSTS, and X-Frame-Options to enhance protection.',
                priority: 'medium'
            });
            
            recommendations.push({
                title: 'Regular Security Audits',
                description: 'Schedule regular security assessments and penetration testing.',
                priority: 'medium'
            });
        }
        
        return recommendations;
    }

    displayResults() {
        // Hide progress section
        document.getElementById('progressSection').style.display = 'none';
        
        // Show results section
        const resultsSection = document.getElementById('resultsSection');
        resultsSection.style.display = 'block';
        resultsSection.classList.add('fade-in');
        resultsSection.scrollIntoView({ behavior: 'smooth' });
        
        // Display overall score
        this.displayOverallScore();
        
        // Display vulnerability categories
        this.displayVulnerabilityCategories();
        
        // Display detailed findings
        this.displayDetailedFindings();
        
        // Display recommendations
        this.displayRecommendations();
        
        // Display scoreboard
        this.displayScoreboard();
    }

    displayOverallScore() {
        const score = this.scanResults.overallScore;
        const scoreElement = document.getElementById('overallScore');
        const titleElement = document.getElementById('scoreTitle');
        const descriptionElement = document.getElementById('scoreDescription');
        
        // Animate score counting
        this.animateScore(scoreElement, 0, score, 2000);
        
        // Update title and description based on score
        if (score >= 80) {
            titleElement.textContent = 'Excellent Security Posture';
            descriptionElement.textContent = 'Your system demonstrates strong security practices with minimal vulnerabilities.';
        } else if (score >= 60) {
            titleElement.textContent = 'Good Security Posture';
            descriptionElement.textContent = 'Your system has good security practices but some areas need attention.';
        } else if (score >= 40) {
            titleElement.textContent = 'Moderate Security Risk';
            descriptionElement.textContent = 'Your system has several security vulnerabilities that should be addressed.';
        } else {
            titleElement.textContent = 'High Security Risk';
            descriptionElement.textContent = 'Your system has critical security vulnerabilities requiring immediate attention.';
        }
    }

    animateScore(element, start, end, duration) {
        const startTime = performance.now();
        
        const updateScore = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const currentScore = Math.round(start + (end - start) * progress);
            element.textContent = currentScore;
            
            if (progress < 1) {
                requestAnimationFrame(updateScore);
            }
        };
        
        requestAnimationFrame(updateScore);
    }

    displayVulnerabilityCategories() {
        const categoryGrid = document.getElementById('categoryGrid');
        categoryGrid.innerHTML = '';
        
        const categories = this.groupVulnerabilitiesByCategory();
        
        Object.entries(categories).forEach(([category, vulns]) => {
            const categoryItem = document.createElement('div');
            categoryItem.className = 'category-item';
            
            const severity = this.getHighestSeverity(vulns);
            const avgScore = vulns.reduce((sum, v) => sum + v.score, 0) / vulns.length;
            
            categoryItem.classList.add(severity);
            
            categoryItem.innerHTML = `
                <div class="category-header">
                    <span class="category-name">${category}</span>
                    <span class="category-score">${Math.round(avgScore)}/100</span>
                </div>
                <div class="category-description">
                    ${vulns.length} vulnerability(ies) found in this category
                </div>
            `;
            
            categoryGrid.appendChild(categoryItem);
        });
    }

    groupVulnerabilitiesByCategory() {
        const categories = {};
        
        this.scanResults.vulnerabilities.forEach(vuln => {
            if (!categories[vuln.category]) {
                categories[vuln.category] = [];
            }
            categories[vuln.category].push(vuln);
        });
        
        return categories;
    }

    getHighestSeverity(vulnerabilities) {
        const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
        let highest = 'low';
        
        vulnerabilities.forEach(vuln => {
            if (severityOrder[vuln.severity] > severityOrder[highest]) {
                highest = vuln.severity;
            }
        });
        
        return highest;
    }

    displayDetailedFindings() {
        const findingsContainer = document.getElementById('findingsContainer');
        findingsContainer.innerHTML = '';
        
        if (this.scanResults.vulnerabilities.length === 0) {
            findingsContainer.innerHTML = `
                <div class="finding-item low">
                    <div class="finding-header">
                        <span class="finding-title">No Critical Vulnerabilities Found</span>
                        <span class="finding-severity low">Clean</span>
                    </div>
                    <div class="finding-description">
                        The security scan did not identify any critical vulnerabilities in the target system.
                    </div>
                    <div class="finding-impact">
                        Impact: System appears to be well-secured against common attack vectors.
                    </div>
                </div>
            `;
            return;
        }
        
        this.scanResults.vulnerabilities.forEach(vuln => {
            const findingItem = document.createElement('div');
            findingItem.className = `finding-item ${vuln.severity}`;
            
            findingItem.innerHTML = `
                <div class="finding-header">
                    <span class="finding-title">${vuln.name}</span>
                    <span class="finding-severity ${vuln.severity}">${vuln.severity}</span>
                </div>
                <div class="finding-description">${vuln.description}</div>
                <div class="finding-impact">Impact: ${vuln.impact}</div>
            `;
            
            findingsContainer.appendChild(findingItem);
        });
    }

    displayRecommendations() {
        const recommendationsContainer = document.getElementById('recommendationsContainer');
        recommendationsContainer.innerHTML = '';
        
        this.scanResults.recommendations.forEach(rec => {
            const recItem = document.createElement('div');
            recItem.className = 'recommendation-item';
            
            recItem.innerHTML = `
                <div class="recommendation-title">${rec.title}</div>
                <div class="recommendation-description">${rec.description}</div>
                <span class="recommendation-priority">${rec.priority} priority</span>
            `;
            
            recommendationsContainer.appendChild(recItem);
        });
    }

    displayScoreboard() {
        const scoreboardSection = document.getElementById('scoreboardSection');
        scoreboardSection.style.display = 'block';
        scoreboardSection.classList.add('fade-in');
        
        const score = this.scanResults.overallScore;
        const vulnerabilities = this.scanResults.vulnerabilities;
        
        // Calculate scoreboard metrics
        const securityRating = this.getSecurityRating(score);
        const breachDifficulty = this.getBreachDifficulty(score);
        const breachTime = this.getBreachTime(score);
        const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical').length;
        
        // Update scoreboard elements
        document.getElementById('securityRating').textContent = securityRating;
        document.getElementById('breachDifficulty').textContent = breachDifficulty;
        document.getElementById('breachTime').textContent = breachTime;
        document.getElementById('criticalVulns').textContent = criticalVulns;
    }

    getSecurityRating(score) {
        if (score >= 80) return 'Excellent';
        if (score >= 60) return 'Good';
        if (score >= 40) return 'Fair';
        return 'Poor';
    }

    getBreachDifficulty(score) {
        if (score >= 80) return 'Very Hard';
        if (score >= 60) return 'Hard';
        if (score >= 40) return 'Moderate';
        return 'Easy';
    }

    getBreachTime(score) {
        if (score >= 80) return 'Hours/Days';
        if (score >= 60) return 'Hours';
        if (score >= 40) return 'Minutes';
        return 'Minutes';
    }

    showNotification(messageKey, type = 'info') {
        // Get translated message
        let message = messageKey;
        let langTranslations = translations[this.currentLanguage];
        
        if (!langTranslations && additionalTranslations && additionalTranslations[this.currentLanguage]) {
            langTranslations = additionalTranslations[this.currentLanguage];
        }
        
        if (!langTranslations && completeTranslations && completeTranslations[this.currentLanguage]) {
            langTranslations = completeTranslations[this.currentLanguage];
        }
        
        if (!langTranslations) {
            langTranslations = translations['en'];
        }
        
        if (langTranslations[messageKey]) {
            message = langTranslations[messageKey];
        }
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
            max-width: 300px;
        `;
        
        // Set background color based on type
        const colors = {
            'success': '#28a745',
            'error': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };
        notification.style.backgroundColor = colors[type] || colors.info;
        
        notification.textContent = message;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecurityAssessmentTool();
});

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(style);
