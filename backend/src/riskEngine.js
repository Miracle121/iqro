const logger = require('../config/logger');

/**
 * Risk Scoring Engine
 * Calculates risk scores based on CVSS scores and exposure factors
 */
class RiskEngine {
    constructor() {
        this.exposureFactors = {
            'public': 1.0,      // Publicly accessible (internet-facing)
            'internal': 0.7,    // Internal network
            'local': 0.4,       // Local machine only
            'isolated': 0.2     // Isolated/air-gapped
        };
        
        this.severityWeights = {
            'Critical': 1.0,
            'High': 0.8,
            'Medium': 0.5,
            'Low': 0.2
        };
        
        this.categoryMultipliers = {
            'network_service': 1.2,  // Network services are higher risk
            'system_service': 1.0,   // Standard system services
            'package': 0.8,          // Installed packages
            'library': 0.6           // Libraries and dependencies
        };
        
        logger.info('Risk scoring engine initialized');
    }
    
    /**
     * Calculate overall risk score for a host
     */
    calculateHostRiskScore(vulnerabilities, hostContext = {}) {
        if (!vulnerabilities || vulnerabilities.length === 0) {
            return {
                riskScore: 0,
                riskLevel: 'Low',
                breakdown: {
                    criticalCount: 0,
                    highCount: 0,
                    mediumCount: 0,
                    lowCount: 0,
                    totalScore: 0,
                    weightedScore: 0
                }
            };
        }
        
        logger.debug(`Calculating risk score for ${vulnerabilities.length} vulnerabilities`);
        
        let totalScore = 0;
        let weightedScore = 0;
        const severityCounts = {
            criticalCount: 0,
            highCount: 0,
            mediumCount: 0,
            lowCount: 0
        };
        
        // Process each vulnerability
        for (const vulnerability of vulnerabilities) {
            const vulnScore = this.calculateVulnerabilityScore(vulnerability, hostContext);
            totalScore += vulnScore.baseScore;
            weightedScore += vulnScore.weightedScore;
            
            // Count by severity
            const severity = this.getSeverityFromScore(vulnerability.cvss_score || 0);
            const countKey = `${severity.toLowerCase()}Count`;
            if (severityCounts.hasOwnProperty(countKey)) {
                severityCounts[countKey]++;
            }
        }
        
        // Calculate final risk score (0-100 scale)
        const avgScore = vulnerabilities.length > 0 ? weightedScore / vulnerabilities.length : 0;
        
        // Apply logarithmic scaling to prevent single high-severity vulns from dominating
        const logFactor = Math.log10(vulnerabilities.length + 1) / Math.log10(11); // Max at 10 vulns
        const riskScore = Math.min(100, avgScore * (1 + logFactor * 0.5));
        
        const result = {
            riskScore: Math.round(riskScore * 100) / 100,
            riskLevel: this.getRiskLevel(riskScore),
            breakdown: {
                ...severityCounts,
                totalScore: Math.round(totalScore * 100) / 100,
                weightedScore: Math.round(weightedScore * 100) / 100,
                vulnerabilityCount: vulnerabilities.length,
                averageScore: Math.round(avgScore * 100) / 100
            }
        };
        
        logger.debug('Risk calculation result:', result);
        return result;
    }
    
    /**
     * Calculate score for individual vulnerability
     */
    calculateVulnerabilityScore(vulnerability, hostContext = {}) {
        const cvssScore = vulnerability.cvss_score || 0;
        const severity = this.getSeverityFromScore(cvssScore);
        
        // Base score from CVSS
        let baseScore = cvssScore;
        
        // Apply exposure factor
        const exposureType = this.determineExposureType(vulnerability, hostContext);
        const exposureFactor = this.exposureFactors[exposureType] || 0.7;
        
        // Apply category multiplier
        const category = vulnerability.software_type || 'package';
        const categoryMultiplier = this.categoryMultipliers[category] || 1.0;
        
        // Apply severity weight
        const severityWeight = this.severityWeights[severity] || 0.5;
        
        // Calculate age factor (newer vulnerabilities are typically more dangerous)
        const ageFactor = this.calculateAgeFactor(vulnerability.published_date);
        
        // Apply exploitability factor
        const exploitabilityFactor = this.assessExploitability(vulnerability);
        
        // Final weighted score
        const weightedScore = baseScore * exposureFactor * categoryMultiplier * 
                            severityWeight * ageFactor * exploitabilityFactor;
        
        return {
            baseScore,
            weightedScore: Math.min(10, weightedScore), // Cap at 10
            factors: {
                exposure: exposureFactor,
                category: categoryMultiplier,
                severity: severityWeight,
                age: ageFactor,
                exploitability: exploitabilityFactor
            },
            exposureType,
            severity
        };
    }
    
    /**
     * Determine exposure type based on vulnerability and host context
     */
    determineExposureType(vulnerability, hostContext) {
        // Check if vulnerability is in a network service
        if (vulnerability.software_type === 'network_service' || 
            vulnerability.type === 'network_service') {
            
            // Check port information to determine exposure
            const port = vulnerability.port;
            if (port) {
                // Common internet-facing ports
                const publicPorts = [80, 443, 8080, 8443, 21, 22, 25, 53, 110, 143, 993, 995];
                if (publicPorts.includes(port)) {
                    return 'public';
                }
            }
            
            return 'internal'; // Network service but not obviously public
        }
        
        // Check host context for environment information
        if (hostContext.environment === 'production' && hostContext.hasPublicIP) {
            return 'public';
        } else if (hostContext.environment === 'production') {
            return 'internal';
        } else if (hostContext.isIsolated) {
            return 'isolated';
        }
        
        // Default to local for system packages and services
        return 'local';
    }
    
    /**
     * Calculate age factor for vulnerability
     */
    calculateAgeFactor(publishedDate) {
        if (!publishedDate) return 1.0;
        
        try {
            const published = new Date(publishedDate);
            const now = new Date();
            const ageInDays = (now - published) / (1000 * 60 * 60 * 24);
            
            // Recent vulnerabilities (< 30 days) get higher weight
            if (ageInDays < 30) {
                return 1.2;
            } else if (ageInDays < 90) {
                return 1.1;
            } else if (ageInDays < 365) {
                return 1.0;
            } else if (ageInDays < 1095) { // 3 years
                return 0.9;
            } else {
                return 0.8; // Very old vulnerabilities
            }
        } catch (error) {
            logger.warn('Error calculating age factor:', error);
            return 1.0;
        }
    }
    
    /**
     * Assess exploitability of vulnerability
     */
    assessExploitability(vulnerability) {
        let exploitabilityScore = 1.0;
        
        // Check CVSS vector for exploitability indicators
        const cvssVector = vulnerability.cvss_vector || '';
        
        // Access Vector (AV)
        if (cvssVector.includes('AV:N')) { // Network
            exploitabilityScore *= 1.3;
        } else if (cvssVector.includes('AV:A')) { // Adjacent Network
            exploitabilityScore *= 1.1;
        } else if (cvssVector.includes('AV:L')) { // Local
            exploitabilityScore *= 0.8;
        }
        
        // Access Complexity (AC)
        if (cvssVector.includes('AC:L')) { // Low complexity
            exploitabilityScore *= 1.2;
        } else if (cvssVector.includes('AC:H')) { // High complexity
            exploitabilityScore *= 0.8;
        }
        
        // Authentication Required (Au)
        if (cvssVector.includes('Au:N')) { // No authentication
            exploitabilityScore *= 1.2;
        } else if (cvssVector.includes('Au:M')) { // Multiple authentication
            exploitabilityScore *= 0.7;
        }
        
        // Check for known exploitation indicators
        const description = (vulnerability.description || '').toLowerCase();
        if (description.includes('remote code execution') || 
            description.includes('rce') ||
            description.includes('buffer overflow')) {
            exploitabilityScore *= 1.3;
        }
        
        if (description.includes('denial of service') ||
            description.includes('dos')) {
            exploitabilityScore *= 0.9;
        }
        
        return Math.min(2.0, exploitabilityScore); // Cap at 2x
    }
    
    /**
     * Get severity level from CVSS score
     */
    getSeverityFromScore(cvssScore) {
        if (cvssScore >= 9.0) return 'Critical';
        if (cvssScore >= 7.0) return 'High';
        if (cvssScore >= 4.0) return 'Medium';
        if (cvssScore > 0.0) return 'Low';
        return 'None';
    }
    
    /**
     * Get risk level from calculated risk score
     */
    getRiskLevel(riskScore) {
        if (riskScore >= 80) return 'Critical';
        if (riskScore >= 60) return 'High';
        if (riskScore >= 30) return 'Medium';
        return 'Low';
    }
    
    /**
     * Calculate trend analysis for risk scores
     */
    calculateRiskTrend(historicalScores) {
        if (!historicalScores || historicalScores.length < 2) {
            return { trend: 'stable', change: 0 };
        }
        
        const recent = historicalScores.slice(-5); // Last 5 scores
        const older = historicalScores.slice(-10, -5); // Previous 5 scores
        
        const recentAvg = recent.reduce((sum, score) => sum + score, 0) / recent.length;
        const olderAvg = older.length > 0 ? 
            older.reduce((sum, score) => sum + score, 0) / older.length : recentAvg;
        
        const change = recentAvg - olderAvg;
        const percentChange = olderAvg > 0 ? (change / olderAvg) * 100 : 0;
        
        let trend = 'stable';
        if (Math.abs(percentChange) > 10) {
            trend = change > 0 ? 'increasing' : 'decreasing';
        }
        
        return {
            trend,
            change: Math.round(change * 100) / 100,
            percentChange: Math.round(percentChange * 100) / 100
        };
    }
    
    /**
     * Generate risk recommendations
     */
    generateRecommendations(vulnerabilities, riskScore) {
        const recommendations = [];
        
        if (riskScore >= 80) {
            recommendations.push({
                priority: 'critical',
                action: 'Immediate action required',
                description: 'This host has critical vulnerabilities requiring immediate attention'
            });
        }
        
        // Count high-severity vulnerabilities
        const criticalVulns = vulnerabilities.filter(v => this.getSeverityFromScore(v.cvss_score) === 'Critical');
        if (criticalVulns.length > 0) {
            recommendations.push({
                priority: 'high',
                action: 'Patch critical vulnerabilities',
                description: `Found ${criticalVulns.length} critical vulnerabilities that should be patched immediately`
            });
        }
        
        // Check for network services
        const networkVulns = vulnerabilities.filter(v => 
            v.software_type === 'network_service' || v.type === 'network_service');
        if (networkVulns.length > 0) {
            recommendations.push({
                priority: 'medium',
                action: 'Review network exposure',
                description: 'Consider limiting network access for vulnerable services'
            });
        }
        
        // Check for old vulnerabilities
        const oldVulns = vulnerabilities.filter(v => {
            if (!v.published_date) return false;
            const ageInDays = (new Date() - new Date(v.published_date)) / (1000 * 60 * 60 * 24);
            return ageInDays > 365;
        });
        
        if (oldVulns.length > 0) {
            recommendations.push({
                priority: 'low',
                action: 'Update legacy software',
                description: `Found ${oldVulns.length} vulnerabilities in older software versions`
            });
        }
        
        return recommendations;
    }
}

module.exports = new RiskEngine();