/**
 * CVE Data Integration Service
 * Integrates with NVD, Vulners, and other vulnerability databases
 */

const axios = require('axios');
const { Vulnerability } = require('../models');
const logger = require('../utils/logger');

class CVEService {
  constructor() {
    this.nvdApiKey = process.env.NVD_API_KEY;
    this.vulnersApiKey = process.env.VULNERS_API_KEY;
    
    this.nvdBaseUrl = 'https://services.nvd.nist.gov/rest/json';
    this.vulnersBaseUrl = 'https://vulners.com/api/v3';
    
    // Rate limiting
    this.nvdRateLimit = 2000; // 2 seconds between requests (with API key)
    this.vulnersRateLimit = 1000; // 1 second between requests
    
    this.lastNvdRequest = 0;
    this.lastVulnersRequest = 0;
  }

  /**
   * Fetch CVE data from NVD
   * @param {string} cveId - CVE identifier
   * @returns {Object} CVE data
   */
  async fetchFromNVD(cveId) {
    try {
      await this._rateLimitNVD();
      
      const url = `${this.nvdBaseUrl}/cves/2.0`;
      const params = {
        cveId: cveId.toUpperCase()
      };
      
      const headers = {
        'User-Agent': 'HBVM-Backend/1.0.0'
      };
      
      if (this.nvdApiKey) {
        headers['apiKey'] = this.nvdApiKey;
      }
      
      logger.debug(`Fetching CVE data from NVD: ${cveId}`);
      
      const response = await axios.get(url, {
        params,
        headers,
        timeout: 30000
      });
      
      if (response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
        return this._parseNVDVulnerability(response.data.vulnerabilities[0]);
      }
      
      return null;
      
    } catch (error) {
      logger.error(`Failed to fetch CVE ${cveId} from NVD:`, error.message);
      throw error;
    }
  }

  /**
   * Fetch CVE data from Vulners
   * @param {string} cveId - CVE identifier
   * @returns {Object} CVE data
   */
  async fetchFromVulners(cveId) {
    try {
      await this._rateLimitVulners();
      
      const url = `${this.vulnersBaseUrl}/search/id/`;
      const data = {
        id: cveId.toUpperCase(),
        apiKey: this.vulnersApiKey
      };
      
      logger.debug(`Fetching CVE data from Vulners: ${cveId}`);
      
      const response = await axios.post(url, data, {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'HBVM-Backend/1.0.0'
        },
        timeout: 30000
      });
      
      if (response.data.result === 'OK' && response.data.data.documents) {
        const documents = Object.values(response.data.data.documents);
        if (documents.length > 0) {
          return this._parseVulnersVulnerability(documents[0]);
        }
      }
      
      return null;
      
    } catch (error) {
      logger.error(`Failed to fetch CVE ${cveId} from Vulners:`, error.message);
      throw error;
    }
  }

  /**
   * Enrich vulnerability data with CVE information
   * @param {string} cveId - CVE identifier
   * @returns {Object} Enriched vulnerability data
   */
  async enrichVulnerability(cveId) {
    try {
      // Check if we already have this CVE in our database
      let vulnerability = await Vulnerability.findOne({ cveId: cveId.toUpperCase() });
      
      if (vulnerability && this._isRecentlyUpdated(vulnerability)) {
        logger.debug(`Using cached CVE data for ${cveId}`);
        return vulnerability;
      }
      
      // Fetch from external sources
      let nvdData = null;
      let vulnersData = null;
      
      try {
        nvdData = await this.fetchFromNVD(cveId);
      } catch (error) {
        logger.warn(`NVD fetch failed for ${cveId}:`, error.message);
      }
      
      try {
        if (this.vulnersApiKey) {
          vulnersData = await this.fetchFromVulners(cveId);
        }
      } catch (error) {
        logger.warn(`Vulners fetch failed for ${cveId}:`, error.message);
      }
      
      // Merge data from sources
      const mergedData = this._mergeVulnerabilityData(nvdData, vulnersData);
      
      if (!mergedData) {
        logger.warn(`No vulnerability data found for ${cveId}`);
        return null;
      }
      
      // Save or update in database
      if (vulnerability) {
        Object.assign(vulnerability, mergedData);
        vulnerability.lastUpdated = new Date();
        await vulnerability.save();
      } else {
        vulnerability = new Vulnerability(mergedData);
        await vulnerability.save();
      }
      
      logger.info(`Successfully enriched CVE data for ${cveId}`);
      return vulnerability;
      
    } catch (error) {
      logger.error(`Failed to enrich vulnerability ${cveId}:`, error);
      throw error;
    }
  }

  /**
   * Batch enrich multiple vulnerabilities
   * @param {Array} cveIds - Array of CVE identifiers
   * @returns {Array} Array of enriched vulnerabilities
   */
  async batchEnrichVulnerabilities(cveIds) {
    const results = [];
    const batchSize = 5;
    
    for (let i = 0; i < cveIds.length; i += batchSize) {
      const batch = cveIds.slice(i, i + batchSize);
      
      const batchPromises = batch.map(async (cveId) => {
        try {
          return await this.enrichVulnerability(cveId);
        } catch (error) {
          logger.error(`Failed to enrich ${cveId} in batch:`, error.message);
          return null;
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults.filter(result => result !== null));
      
      // Add delay between batches
      if (i + batchSize < cveIds.length) {
        await this._delay(2000);
      }
    }
    
    return results;
  }

  /**
   * Get recent CVE updates from NVD
   * @param {Date} lastUpdated - Last update timestamp
   * @returns {Array} Array of recent CVEs
   */
  async getRecentCVEs(lastUpdated = null) {
    try {
      await this._rateLimitNVD();
      
      const url = `${this.nvdBaseUrl}/cves/2.0`;
      const params = {
        resultsPerPage: 100
      };
      
      if (lastUpdated) {
        params.lastModStartDate = lastUpdated.toISOString();
      } else {
        // Default to last 7 days if no lastUpdated provided
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        params.lastModStartDate = sevenDaysAgo.toISOString();
      }
      
      const headers = {
        'User-Agent': 'HBVM-Backend/1.0.0'
      };
      
      if (this.nvdApiKey) {
        headers['apiKey'] = this.nvdApiKey;
      }
      
      logger.info(`Fetching recent CVEs from NVD since ${params.lastModStartDate}`);
      
      const response = await axios.get(url, {
        params,
        headers,
        timeout: 60000
      });
      
      if (response.data.vulnerabilities) {
        return response.data.vulnerabilities.map(vuln => 
          this._parseNVDVulnerability(vuln)
        );
      }
      
      return [];
      
    } catch (error) {
      logger.error('Failed to fetch recent CVEs from NVD:', error);
      throw error;
    }
  }

  /**
   * Update vulnerability database with recent CVEs
   */
  async updateVulnerabilityDatabase() {
    try {
      logger.info('Starting vulnerability database update...');
      
      // Get the last update timestamp
      const lastVuln = await Vulnerability.findOne()
        .sort({ lastUpdated: -1 })
        .select('lastUpdated');
      
      const lastUpdated = lastVuln ? lastVuln.lastUpdated : null;
      
      // Fetch recent CVEs
      const recentCVEs = await this.getRecentCVEs(lastUpdated);
      
      if (recentCVEs.length === 0) {
        logger.info('No new CVEs to update');
        return { updated: 0, errors: 0 };
      }
      
      logger.info(`Processing ${recentCVEs.length} CVEs...`);
      
      let updated = 0;
      let errors = 0;
      
      for (const cveData of recentCVEs) {
        try {
          await Vulnerability.findOneAndUpdate(
            { cveId: cveData.cveId },
            { ...cveData, lastUpdated: new Date() },
            { upsert: true, new: true }
          );
          updated++;
        } catch (error) {
          logger.error(`Failed to update CVE ${cveData.cveId}:`, error);
          errors++;
        }
      }
      
      logger.info(`Vulnerability database update completed: ${updated} updated, ${errors} errors`);
      return { updated, errors };
      
    } catch (error) {
      logger.error('Vulnerability database update failed:', error);
      throw error;
    }
  }

  /**
   * Parse NVD vulnerability data
   * @private
   */
  _parseNVDVulnerability(nvdVuln) {
    const cve = nvdVuln.cve;
    
    const severity = this._calculateSeverity(cve.metrics);
    const cvssScore = this._extractCVSSScore(cve.metrics);
    const cvssVector = this._extractCVSSVector(cve.metrics);
    
    return {
      cveId: cve.id,
      title: this._extractTitle(cve),
      description: this._extractDescription(cve),
      severity,
      cvssScore,
      cvssVector,
      cvssVersion: this._extractCVSSVersion(cve.metrics),
      cweId: this._extractCWE(cve),
      publishedDate: new Date(cve.published),
      lastModifiedDate: new Date(cve.lastModified),
      affectedSoftware: this._extractAffectedSoftware(cve),
      references: this._extractReferences(cve),
      dataSource: 'nvd',
      lastUpdated: new Date()
    };
  }

  /**
   * Parse Vulners vulnerability data
   * @private
   */
  _parseVulnersVulnerability(vulnersVuln) {
    const exploitData = this._extractVulnersExploitData(vulnersVuln);
    
    return {
      cveId: vulnersVuln.id,
      title: vulnersVuln.title || vulnersVuln.id,
      description: vulnersVuln.description || '',
      severity: this._mapVulnersSeverity(vulnersVuln.cvss?.score),
      cvssScore: vulnersVuln.cvss?.score || 0,
      cvssVector: vulnersVuln.cvss?.vector,
      exploitability: {
        hasExploit: exploitData.hasExploit,
        exploitMaturity: exploitData.maturity,
        exploitSources: exploitData.sources
      },
      threatIntelligence: {
        inTheWild: vulnersVuln.bulletinFamily === 'exploit',
        malwareFamily: vulnersVuln.malware || [],
        threatActors: []
      },
      publishedDate: vulnersVuln.published ? new Date(vulnersVuln.published) : null,
      dataSource: 'vulners',
      lastUpdated: new Date()
    };
  }

  /**
   * Merge vulnerability data from multiple sources
   * @private
   */
  _mergeVulnerabilityData(nvdData, vulnersData) {
    if (!nvdData && !vulnersData) return null;
    
    const merged = nvdData || vulnersData;
    
    if (nvdData && vulnersData) {
      // Merge exploit information from Vulners
      if (vulnersData.exploitability) {
        merged.exploitability = vulnersData.exploitability;
      }
      
      // Merge threat intelligence from Vulners
      if (vulnersData.threatIntelligence) {
        merged.threatIntelligence = vulnersData.threatIntelligence;
      }
      
      // Use the highest CVSS score
      if (vulnersData.cvssScore > merged.cvssScore) {
        merged.cvssScore = vulnersData.cvssScore;
        merged.cvssVector = vulnersData.cvssVector;
      }
      
      merged.dataSource = 'nvd,vulners';
    }
    
    return merged;
  }

  /**
   * Extract CVSS score from NVD metrics
   * @private
   */
  _extractCVSSScore(metrics) {
    if (metrics.cvssMetricV31?.[0]?.cvssData?.baseScore) {
      return metrics.cvssMetricV31[0].cvssData.baseScore;
    }
    if (metrics.cvssMetricV30?.[0]?.cvssData?.baseScore) {
      return metrics.cvssMetricV30[0].cvssData.baseScore;
    }
    if (metrics.cvssMetricV2?.[0]?.cvssData?.baseScore) {
      return metrics.cvssMetricV2[0].cvssData.baseScore;
    }
    return 0;
  }

  /**
   * Calculate severity from CVSS score
   * @private
   */
  _calculateSeverity(metrics) {
    const score = this._extractCVSSScore(metrics);
    
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score > 0) return 'low';
    return 'informational';
  }

  /**
   * Rate limiting for NVD API
   * @private
   */
  async _rateLimitNVD() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastNvdRequest;
    
    if (timeSinceLastRequest < this.nvdRateLimit) {
      const delay = this.nvdRateLimit - timeSinceLastRequest;
      await this._delay(delay);
    }
    
    this.lastNvdRequest = Date.now();
  }

  /**
   * Rate limiting for Vulners API
   * @private
   */
  async _rateLimitVulners() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastVulnersRequest;
    
    if (timeSinceLastRequest < this.vulnersRateLimit) {
      const delay = this.vulnersRateLimit - timeSinceLastRequest;
      await this._delay(delay);
    }
    
    this.lastVulnersRequest = Date.now();
  }

  /**
   * Check if vulnerability was recently updated
   * @private
   */
  _isRecentlyUpdated(vulnerability) {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    return vulnerability.lastUpdated > oneWeekAgo;
  }

  /**
   * Delay utility
   * @private
   */
  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Extract additional data helpers
   * @private
   */
  _extractTitle(cve) {
    return cve.descriptions?.find(d => d.lang === 'en')?.value || cve.id;
  }

  _extractDescription(cve) {
    return cve.descriptions?.find(d => d.lang === 'en')?.value || '';
  }

  _extractCVSSVector(metrics) {
    if (metrics.cvssMetricV31?.[0]?.cvssData?.vectorString) {
      return metrics.cvssMetricV31[0].cvssData.vectorString;
    }
    if (metrics.cvssMetricV30?.[0]?.cvssData?.vectorString) {
      return metrics.cvssMetricV30[0].cvssData.vectorString;
    }
    if (metrics.cvssMetricV2?.[0]?.cvssData?.vectorString) {
      return metrics.cvssMetricV2[0].cvssData.vectorString;
    }
    return null;
  }

  _extractCVSSVersion(metrics) {
    if (metrics.cvssMetricV31?.[0]) return '3.1';
    if (metrics.cvssMetricV30?.[0]) return '3.0';
    if (metrics.cvssMetricV2?.[0]) return '2.0';
    return '3.1';
  }

  _extractCWE(cve) {
    const weakness = cve.weaknesses?.[0]?.description?.[0];
    return weakness?.value?.replace('CWE-', '') || null;
  }

  _extractAffectedSoftware(cve) {
    const configs = cve.configurations?.[0]?.nodes || [];
    const software = [];
    
    for (const node of configs) {
      if (node.cpeMatch) {
        for (const match of node.cpeMatch) {
          if (match.vulnerable && match.criteria) {
            const parts = match.criteria.split(':');
            if (parts.length >= 5) {
              software.push({
                vendor: parts[3],
                product: parts[4],
                version: parts[5] || '*',
                versionStartIncluding: match.versionStartIncluding,
                versionStartExcluding: match.versionStartExcluding,
                versionEndIncluding: match.versionEndIncluding,
                versionEndExcluding: match.versionEndExcluding
              });
            }
          }
        }
      }
    }
    
    return software;
  }

  _extractReferences(cve) {
    return (cve.references || []).map(ref => ({
      url: ref.url,
      name: ref.url,
      refsource: ref.source || 'unknown',
      tags: ref.tags || []
    }));
  }

  _extractVulnersExploitData(vulnersVuln) {
    const hasExploit = vulnersVuln.bulletinFamily === 'exploit' || 
                      (vulnersVuln.exploit && vulnersVuln.exploit.length > 0);
    
    let maturity = 'unproven';
    const sources = [];
    
    if (hasExploit) {
      if (vulnersVuln.exploit) {
        sources.push(...vulnersVuln.exploit);
        maturity = 'functional'; // Assume functional if exploits exist
      }
    }
    
    return { hasExploit, maturity, sources };
  }

  _mapVulnersSeverity(score) {
    if (!score) return 'informational';
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score > 0) return 'low';
    return 'informational';
  }
}

module.exports = new CVEService();