const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const logger = require('../config/logger');
const Host = require('../models/Host');
const riskEngine = require('../src/riskEngine');

// Middleware for API key validation
const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
    
    if (!apiKey) {
        logger.security('Scan request without API key', { ip: req.ip });
        return res.status(401).json({
            error: 'API key required',
            message: 'Please provide a valid API key in X-API-Key header or Authorization header'
        });
    }
    
    // In production, validate against database
    const validApiKey = process.env.AGENT_API_KEY || 'default-api-key';
    if (apiKey !== validApiKey) {
        logger.security('Invalid API key used', { ip: req.ip, providedKey: apiKey.substring(0, 8) + '...' });
        return res.status(403).json({
            error: 'Invalid API key',
            message: 'The provided API key is not valid'
        });
    }
    
    next();
};

// Validation rules for scan data
const scanValidation = [
    body('host_id').notEmpty().isString().trim(),
    body('timestamp').notEmpty().isISO8601(),
    body('agent_version').optional().isString(),
    body('os').optional().isObject(),
    body('ports').optional().isArray(),
    body('services').optional().isArray(),
    body('packages').optional().isArray(),
    body('cves').optional().isArray()
];

/**
 * POST /api/scan
 * Receive scan data from agents
 */
router.post('/', validateApiKey, scanValidation, async (req, res) => {
    try {
        // Check validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn('Invalid scan data received', { errors: errors.array(), ip: req.ip });
            return res.status(400).json({
                error: 'Validation failed',
                details: errors.array()
            });
        }
        
        const scanData = req.body;
        const { host_id, timestamp, agent_version } = scanData;
        
        logger.info(`Processing scan data for host: ${host_id}`, {
            timestamp,
            dataSize: JSON.stringify(scanData).length
        });
        
        // Find or create host record
        let host = await Host.findOne({ hostId: host_id });
        const isNewHost = !host;
        
        if (!host) {
            logger.info(`Creating new host record: ${host_id}`);
            host = new Host({
                hostId: host_id,
                hostname: scanData.os?.hostname || host_id,
                createdAt: new Date()
            });
        }
        
        // Update basic host information
        await updateHostInfo(host, scanData);
        
        // Process vulnerabilities and calculate risk score
        const vulnerabilities = scanData.cves || [];
        const hostContext = {
            environment: host.environment,
            hasPublicIP: hasPublicExposure(scanData.ports || []),
            isIsolated: false // Could be determined from network info
        };
        
        const riskAssessment = riskEngine.calculateHostRiskScore(vulnerabilities, hostContext);
        
        // Update host with risk information
        host.riskScore = riskAssessment.riskScore;
        host.riskLevel = riskAssessment.riskLevel;
        
        // Update vulnerability counts
        host.vulnerabilities = {
            total: vulnerabilities.length,
            critical: riskAssessment.breakdown.criticalCount,
            high: riskAssessment.breakdown.highCount,
            medium: riskAssessment.breakdown.mediumCount,
            low: riskAssessment.breakdown.lowCount,
            lastScanDate: new Date(timestamp),
            lastUpdated: new Date()
        };
        
        // Update agent information
        host.agentInfo = {
            version: agent_version || 'unknown',
            lastSeen: new Date(),
            status: 'online'
        };
        
        // Save host record
        await host.save();
        
        // Store detailed scan results (could be in separate collection for large data)
        await storeScanResults(host_id, scanData, riskAssessment);
        
        // Generate response
        const response = {
            message: 'Scan data processed successfully',
            scan_id: generateScanId(host_id, timestamp),
            host_id: host_id,
            risk_assessment: {
                score: riskAssessment.riskScore,
                level: riskAssessment.riskLevel,
                vulnerability_count: vulnerabilities.length
            },
            recommendations: riskEngine.generateRecommendations(vulnerabilities, riskAssessment.riskScore),
            processed_at: new Date().toISOString()
        };
        
        logger.info(`Scan processed successfully`, {
            hostId: host_id,
            riskScore: riskAssessment.riskScore,
            vulnerabilityCount: vulnerabilities.length,
            isNewHost
        });
        
        res.status(200).json(response);
        
    } catch (error) {
        logger.error('Error processing scan data:', {
            error: error.message,
            stack: error.stack,
            hostId: req.body?.host_id,
            ip: req.ip
        });
        
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to process scan data'
        });
    }
});

/**
 * POST /api/heartbeat
 * Receive heartbeat from agents
 */
router.post('/heartbeat', validateApiKey, async (req, res) => {
    try {
        const { host_id, timestamp, status, agent_version } = req.body;
        
        if (!host_id) {
            return res.status(400).json({
                error: 'Missing host_id'
            });
        }
        
        // Update agent status
        const host = await Host.findOne({ hostId: host_id });
        if (host) {
            await host.updateAgentStatus(status || 'online', agent_version);
            logger.debug(`Heartbeat received from ${host_id}`);
        }
        
        res.status(200).json({
            message: 'Heartbeat received',
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        logger.error('Error processing heartbeat:', error);
        res.status(500).json({
            error: 'Failed to process heartbeat'
        });
    }
});

/**
 * Helper function to update host information from scan data
 */
async function updateHostInfo(host, scanData) {
    // Update OS information
    if (scanData.os) {
        host.osInfo = {
            distribution: scanData.os.distribution || scanData.os.system,
            version: scanData.os.version,
            kernel: scanData.os.kernel_version || scanData.os.release,
            architecture: scanData.os.architecture?.[0] || scanData.os.machine,
            platform: scanData.os.platform
        };
        
        if (scanData.os.hostname) {
            host.hostname = scanData.os.hostname;
        }
    }
    
    // Update network information
    const ports = scanData.ports || [];
    host.network = {
        openPorts: ports.map(port => ({
            port: port.port,
            protocol: port.protocol,
            service: port.service,
            version: port.version
        }))
    };
    
    // Update software information
    const packages = scanData.packages || [];
    const services = scanData.services || [];
    
    host.software = {
        packages: packages.slice(0, 100).map(pkg => ({ // Limit to first 100 packages
            name: pkg.name,
            version: pkg.version,
            packageManager: pkg.package_manager
        })),
        services: services.slice(0, 50).map(svc => ({ // Limit to first 50 services
            name: svc.name,
            version: svc.version,
            status: svc.status,
            port: svc.port
        })),
        lastInventoryDate: new Date()
    };
}

/**
 * Check if host has public exposure based on open ports
 */
function hasPublicExposure(ports) {
    const publicPorts = [80, 443, 8080, 8443, 21, 22, 25, 53, 110, 143, 993, 995];
    return ports.some(port => publicPorts.includes(port.port));
}

/**
 * Store detailed scan results
 */
async function storeScanResults(hostId, scanData, riskAssessment) {
    // This could store to a separate ScanResults collection for detailed history
    // For now, we'll just log the key metrics
    
    logger.audit('Scan results stored', {
        hostId,
        timestamp: scanData.timestamp,
        vulnerabilityCount: (scanData.cves || []).length,
        riskScore: riskAssessment.riskScore,
        packageCount: (scanData.packages || []).length,
        serviceCount: (scanData.services || []).length,
        portCount: (scanData.ports || []).length
    });
}

/**
 * Generate unique scan ID
 */
function generateScanId(hostId, timestamp) {
    const crypto = require('crypto');
    const data = `${hostId}-${timestamp}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

module.exports = router;