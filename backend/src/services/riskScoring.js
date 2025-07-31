/**
 * Risk Scoring Service
 * Implements CVSS-based risk scoring with exposure and environmental factors
 */

const { Vulnerability } = require('../models');
const logger = require('../utils/logger');

class RiskScoringService {
  constructor() {
    this.cvssWeights = {
      critical: 10,
      high: 7.5,
      medium: 5,
      low: 2.5,
      informational: 1
    };

    this.exploitabilityWeights = {
      high: 2.0,
      functional: 1.5,
      proof_of_concept: 1.2,
      unproven: 1.0
    };

    this.exposureFactors = {
      internet_facing: 2.0,
      internal_network: 1.5,
      isolated_network: 1.0,
      air_gapped: 0.5
    };
  }

  /**
   * Calculate overall risk score for a scan result
   * @param {Object} scanResult - The scan result object
   * @param {Object} options - Additional scoring options
   * @returns {Object} Risk scoring details
   */
  async calculateRiskScore(scanResult, options = {}) {
    try {
      const {
        includeExposure = true,
        includeThreatIntel = true,
        includeBusinessImpact = false,
        exposureLevel = 'internal_network'
      } = options;

      const vulnerabilities = scanResult.vulnerabilities || [];
      
      if (vulnerabilities.length === 0) {
        return this._createRiskScoreResult(0, 0, []);
      }

      // Enrich vulnerabilities with CVE data
      const enrichedVulns = await this._enrichVulnerabilities(vulnerabilities);
      
      // Calculate base scores
      const baseScores = this._calculateBaseScores(enrichedVulns);
      
      // Apply exploitability factors
      const exploitabilityScores = this._calculateExploitabilityScores(enrichedVulns);
      
      // Apply exposure factors
      let exposureScores = [];
      if (includeExposure) {
        exposureScores = this._calculateExposureScores(enrichedVulns, exposureLevel);
      }
      
      // Apply threat intelligence factors
      let threatIntelScores = [];
      if (includeThreatIntel) {
        threatIntelScores = this._calculateThreatIntelligenceScores(enrichedVulns);
      }
      
      // Calculate weighted risk score
      const overallRiskScore = this._calculateWeightedScore(
        baseScores,
        exploitabilityScores,
        exposureScores,
        threatIntelScores
      );

      // Calculate additional metrics
      const riskMetrics = this._calculateRiskMetrics(enrichedVulns);
      
      // Generate risk recommendations
      const recommendations = this._generateRecommendations(enrichedVulns, overallRiskScore);

      return {
        overallRiskScore: Math.min(10, Math.max(0, overallRiskScore)),
        baseScore: this._average(baseScores),
        exploitabilityScore: this._average(exploitabilityScores),
        exposureScore: exposureScores.length > 0 ? this._average(exposureScores) : 0,
        threatIntelScore: threatIntelScores.length > 0 ? this._average(threatIntelScores) : 0,
        riskMetrics,
        recommendations,
        vulnerabilityCount: vulnerabilities.length,
        enrichedVulnerabilities: enrichedVulns
      };

    } catch (error) {
      logger.error('Risk scoring calculation failed:', error);
      throw new Error(`Risk scoring failed: ${error.message}`);
    }
  }

  /**
   * Calculate CVSS temporal score
   * @param {Object} vulnerability - Vulnerability with CVSS data
   * @returns {Number} Temporal score
   */
  calculateTemporalScore(vulnerability) {
    const baseScore = vulnerability.cvssScore || 0;
    
    // Temporal metrics
    const exploitCodeMaturity = this._getExploitCodeMaturity(vulnerability);
    const remediationLevel = this._getRemediationLevel(vulnerability);
    const reportConfidence = 1.0; // Assume confirmed

    const temporalScore = baseScore * exploitCodeMaturity * remediationLevel * reportConfidence;
    return Math.min(10, temporalScore);
  }

  /**
   * Calculate environmental score based on system context
   * @param {Object} vulnerability - Vulnerability data
   * @param {Object} environment - Environmental factors
   * @returns {Number} Environmental score
   */
  calculateEnvironmentalScore(vulnerability, environment = {}) {
    const temporalScore = this.calculateTemporalScore(vulnerability);
    
    const {
      confidentialityRequirement = 'medium',
      integrityRequirement = 'medium',
      availabilityRequirement = 'medium',
      modifiedAttackVector = null,
      modifiedAttackComplexity = null
    } = environment;

    // CIA requirements
    const ciaMultipliers = {
      low: 0.5,
      medium: 1.0,
      high: 1.5
    };

    const confidentialityMultiplier = ciaMultipliers[confidentialityRequirement] || 1.0;
    const integrityMultiplier = ciaMultipliers[integrityRequirement] || 1.0;
    const availabilityMultiplier = ciaMultipliers[availabilityRequirement] || 1.0;

    // Modified base metrics
    let modifiedScore = temporalScore;
    
    if (modifiedAttackVector) {
      const attackVectorMultipliers = {
        network: 1.0,
        adjacent: 0.9,
        local: 0.8,
        physical: 0.7
      };
      modifiedScore *= (attackVectorMultipliers[modifiedAttackVector] || 1.0);
    }

    // Apply CIA requirements
    const ciaImpact = (confidentialityMultiplier + integrityMultiplier + availabilityMultiplier) / 3;
    const environmentalScore = modifiedScore * ciaImpact;

    return Math.min(10, environmentalScore);
  }

  /**
   * Enrich vulnerabilities with CVE database information
   * @private
   */
  async _enrichVulnerabilities(vulnerabilities) {
    const enriched = [];
    
    for (const vuln of vulnerabilities) {
      try {
        let enrichedVuln = { ...vuln };
        
        if (vuln.cveId) {
          const cveData = await Vulnerability.findOne({ cveId: vuln.cveId.toUpperCase() });
          if (cveData) {
            enrichedVuln = {
              ...enrichedVuln,
              title: cveData.title,
              description: cveData.description,
              cvssScore: cveData.cvssScore || vuln.cvssScore,
              cvssVector: cveData.cvssVector,
              exploitability: cveData.exploitability,
              patchInfo: cveData.patchInfo,
              threatIntelligence: cveData.threatIntelligence,
              publishedDate: cveData.publishedDate,
              ageInDays: cveData.ageInDays
            };
          }
        }
        
        enriched.push(enrichedVuln);
      } catch (error) {
        logger.warn(`Failed to enrich vulnerability ${vuln.cveId}:`, error);
        enriched.push(vuln);
      }
    }
    
    return enriched;
  }

  /**
   * Calculate base CVSS scores
   * @private
   */
  _calculateBaseScores(vulnerabilities) {
    return vulnerabilities.map(vuln => {
      const cvssScore = vuln.cvssScore || 0;
      const severityWeight = this.cvssWeights[vuln.severity] || 1;
      
      // Normalize CVSS score and apply severity weighting
      return (cvssScore / 10) * (severityWeight / 10) * 10;
    });
  }

  /**
   * Calculate exploitability scores
   * @private
   */
  _calculateExploitabilityScores(vulnerabilities) {
    return vulnerabilities.map(vuln => {
      let baseScore = vuln.cvssScore || 0;
      
      if (vuln.exploitability?.hasExploit) {
        const maturity = vuln.exploitability.exploitMaturity || 'unproven';
        const multiplier = this.exploitabilityWeights[maturity] || 1.0;
        baseScore *= multiplier;
      }
      
      return Math.min(10, baseScore);
    });
  }

  /**
   * Calculate exposure scores based on network exposure
   * @private
   */
  _calculateExposureScores(vulnerabilities, exposureLevel) {
    const exposureMultiplier = this.exposureFactors[exposureLevel] || 1.0;
    
    return vulnerabilities.map(vuln => {
      let baseScore = vuln.cvssScore || 0;
      
      // Apply exposure multiplier
      baseScore *= exposureMultiplier;
      
      // Additional factors for network-based vulnerabilities
      if (vuln.cvssVector) {
        if (vuln.cvssVector.includes('AV:N')) { // Network attack vector
          baseScore *= 1.2;
        } else if (vuln.cvssVector.includes('AV:A')) { // Adjacent network
          baseScore *= 1.1;
        }
      }
      
      return Math.min(10, baseScore);
    });
  }

  /**
   * Calculate threat intelligence scores
   * @private
   */
  _calculateThreatIntelligenceScores(vulnerabilities) {
    return vulnerabilities.map(vuln => {
      let baseScore = vuln.cvssScore || 0;
      
      if (vuln.threatIntelligence?.inTheWild) {
        baseScore *= 1.5; // Significant increase for active exploitation
      }
      
      if (vuln.threatIntelligence?.malwareFamily?.length > 0) {
        baseScore *= 1.2; // Increase for known malware associations
      }
      
      return Math.min(10, baseScore);
    });
  }

  /**
   * Calculate weighted overall score
   * @private
   */
  _calculateWeightedScore(baseScores, exploitabilityScores, exposureScores, threatIntelScores) {
    if (baseScores.length === 0) return 0;
    
    const weights = {
      base: 0.4,
      exploitability: 0.3,
      exposure: 0.2,
      threatIntel: 0.1
    };
    
    const avgBase = this._average(baseScores);
    const avgExploitability = this._average(exploitabilityScores);
    const avgExposure = exposureScores.length > 0 ? this._average(exposureScores) : avgBase;
    const avgThreatIntel = threatIntelScores.length > 0 ? this._average(threatIntelScores) : avgBase;
    
    return (
      avgBase * weights.base +
      avgExploitability * weights.exploitability +
      avgExposure * weights.exposure +
      avgThreatIntel * weights.threatIntel
    );
  }

  /**
   * Calculate additional risk metrics
   * @private
   */
  _calculateRiskMetrics(vulnerabilities) {
    const total = vulnerabilities.length;
    
    return {
      criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: vulnerabilities.filter(v => v.severity === 'high').length,
      exploitableCount: vulnerabilities.filter(v => v.exploitability?.hasExploit).length,
      unpatchedCount: vulnerabilities.filter(v => !v.patchInfo?.hasPatch).length,
      recentCount: vulnerabilities.filter(v => v.ageInDays <= 30).length,
      averageCvssScore: this._average(vulnerabilities.map(v => v.cvssScore || 0)),
      oldestVulnerability: Math.max(...vulnerabilities.map(v => v.ageInDays || 0)),
      patchAvailabilityRate: total > 0 ? 
        vulnerabilities.filter(v => v.patchInfo?.hasPatch).length / total : 0
    };
  }

  /**
   * Generate risk-based recommendations
   * @private
   */
  _generateRecommendations(vulnerabilities, overallRiskScore) {
    const recommendations = [];
    
    if (overallRiskScore >= 8) {
      recommendations.push({
        priority: 'critical',
        action: 'immediate_patch',
        description: 'Critical vulnerabilities detected. Immediate patching required.'
      });
    }
    
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    if (criticalVulns.length > 0) {
      recommendations.push({
        priority: 'high',
        action: 'patch_critical',
        description: `${criticalVulns.length} critical vulnerabilities require immediate attention.`
      });
    }
    
    const exploitableVulns = vulnerabilities.filter(v => v.exploitability?.hasExploit);
    if (exploitableVulns.length > 0) {
      recommendations.push({
        priority: 'high',
        action: 'patch_exploitable',
        description: `${exploitableVulns.length} vulnerabilities have known exploits.`
      });
    }
    
    const unpatchedVulns = vulnerabilities.filter(v => !v.patchInfo?.hasPatch);
    if (unpatchedVulns.length > vulnerabilities.length * 0.3) {
      recommendations.push({
        priority: 'medium',
        action: 'implement_mitigations',
        description: 'High percentage of unpatched vulnerabilities. Consider implementing compensating controls.'
      });
    }
    
    return recommendations;
  }

  /**
   * Get exploit code maturity score
   * @private
   */
  _getExploitCodeMaturity(vulnerability) {
    if (!vulnerability.exploitability?.hasExploit) return 0.91; // Unproven
    
    const maturityMap = {
      unproven: 0.91,
      proof_of_concept: 0.94,
      functional: 0.97,
      high: 1.0
    };
    
    return maturityMap[vulnerability.exploitability.exploitMaturity] || 0.91;
  }

  /**
   * Get remediation level score
   * @private
   */
  _getRemediationLevel(vulnerability) {
    if (vulnerability.patchInfo?.hasPatch) {
      return 0.87; // Official fix
    } else {
      return 1.0; // No fix available
    }
  }

  /**
   * Calculate average of an array
   * @private
   */
  _average(values) {
    if (values.length === 0) return 0;
    return values.reduce((sum, val) => sum + val, 0) / values.length;
  }

  /**
   * Create standardized risk score result
   * @private
   */
  _createRiskScoreResult(overallScore, baseScore, vulnerabilities) {
    return {
      overallRiskScore: overallScore,
      baseScore: baseScore,
      exploitabilityScore: 0,
      exposureScore: 0,
      threatIntelScore: 0,
      riskMetrics: {
        criticalCount: 0,
        highCount: 0,
        exploitableCount: 0,
        unpatchedCount: 0,
        recentCount: 0,
        averageCvssScore: 0,
        oldestVulnerability: 0,
        patchAvailabilityRate: 0
      },
      recommendations: [],
      vulnerabilityCount: vulnerabilities.length,
      enrichedVulnerabilities: vulnerabilities
    };
  }
}

module.exports = new RiskScoringService();