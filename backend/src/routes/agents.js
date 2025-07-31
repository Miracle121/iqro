const express = require('express');
const { body, param, query } = require('express-validator');
const { Agent } = require('../models');
const { authenticateAgent, requirePermission } = require('../middleware/auth');
const { validateRequest } = require('../middleware/validation');
const logger = require('../utils/logger');
const crypto = require('crypto');

const router = express.Router();

/**
 * @swagger
 * /api/v1/agents/register:
 *   post:
 *     summary: Register a new agent
 *     tags: [Agents]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - hostname
 *               - agentVersion
 *             properties:
 *               hostname:
 *                 type: string
 *               osInfo:
 *                 type: object
 *               systemInfo:
 *                 type: object
 *               agentVersion:
 *                 type: string
 *               capabilities:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: Agent registered successfully
 *       409:
 *         description: Agent already exists
 */
router.post('/register',
  [
    body('hostname').notEmpty().trim().isLength({ min: 1, max: 255 }),
    body('agentVersion').notEmpty().trim(),
    body('osInfo').optional().isObject(),
    body('systemInfo').optional().isObject(),
    body('capabilities').optional().isArray()
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { hostname, osInfo, systemInfo, agentVersion, capabilities } = req.body;
      
      // Check if agent already exists
      let agent = await Agent.findOne({ hostname });
      
      if (agent) {
        // Update existing agent
        agent.osInfo = osInfo || agent.osInfo;
        agent.systemInfo = systemInfo || agent.systemInfo;
        agent.agentVersion = agentVersion;
        agent.capabilities = capabilities || agent.capabilities;
        agent.lastHeartbeat = new Date();
        agent.status = 'active';
        agent.ipAddress = req.ip;
        agent.userAgent = req.get('User-Agent');
        
        await agent.save();
        
        logger.audit('agent_updated', null, 'agent', {
          agentId: agent.agentId,
          hostname: agent.hostname,
          ip: req.ip
        });
        
        return res.status(200).json({
          message: 'Agent updated successfully',
          agent_id: agent.agentId,
          hostname: agent.hostname
        });
      }
      
      // Create new agent
      const agentId = `agent_${crypto.randomUUID()}`;
      
      agent = new Agent({
        agentId,
        hostname,
        osInfo,
        systemInfo,
        agentVersion,
        capabilities: capabilities || ['vulnerability_scan'],
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      await agent.save();
      
      logger.audit('agent_registered', null, 'agent', {
        agentId: agent.agentId,
        hostname: agent.hostname,
        ip: req.ip
      });
      
      res.status(201).json({
        message: 'Agent registered successfully',
        agent_id: agent.agentId,
        hostname: agent.hostname
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Agent Registration' });
      res.status(500).json({
        error: 'Failed to register agent',
        code: 'REGISTRATION_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents/{agentId}/heartbeat:
 *   post:
 *     summary: Send agent heartbeat
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               timestamp:
 *                 type: string
 *                 format: date-time
 *               status:
 *                 type: string
 *                 enum: [active, maintenance, error]
 *     responses:
 *       200:
 *         description: Heartbeat received
 */
router.post('/:agentId/heartbeat',
  authenticateAgent,
  [
    param('agentId').notEmpty(),
    body('timestamp').optional().isISO8601(),
    body('status').optional().isIn(['active', 'maintenance', 'error'])
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { agentId } = req.params;
      const { status } = req.body;
      
      const agent = await Agent.findOne({ agentId });
      if (!agent) {
        return res.status(404).json({
          error: 'Agent not found',
          code: 'AGENT_NOT_FOUND'
        });
      }
      
      agent.lastHeartbeat = new Date();
      agent.status = status || 'active';
      agent.ipAddress = req.ip;
      
      await agent.save();
      
      res.json({
        message: 'Heartbeat received',
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Agent Heartbeat' });
      res.status(500).json({
        error: 'Failed to process heartbeat',
        code: 'HEARTBEAT_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents:
 *   get:
 *     summary: Get all agents
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, inactive, error, maintenance]
 *       - in: query
 *         name: online
 *         schema:
 *           type: boolean
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *     responses:
 *       200:
 *         description: List of agents
 */
router.get('/',
  authenticateAgent,
  requirePermission('read_agents'),
  [
    query('status').optional().isIn(['active', 'inactive', 'error', 'maintenance']),
    query('online').optional().isBoolean(),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('offset').optional().isInt({ min: 0 })
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { status, online, limit = 50, offset = 0 } = req.query;
      
      let filter = {};
      
      if (status) {
        filter.status = status;
      }
      
      if (online !== undefined) {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        if (online === 'true') {
          filter.lastHeartbeat = { $gte: fiveMinutesAgo };
        } else {
          filter.lastHeartbeat = { $lt: fiveMinutesAgo };
        }
      }
      
      const agents = await Agent.find(filter)
        .sort({ lastHeartbeat: -1 })
        .limit(parseInt(limit))
        .skip(parseInt(offset))
        .select('-__v');
      
      const total = await Agent.countDocuments(filter);
      
      res.json({
        agents,
        pagination: {
          total,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: offset + limit < total
        }
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Get Agents' });
      res.status(500).json({
        error: 'Failed to fetch agents',
        code: 'FETCH_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents/{agentId}:
 *   get:
 *     summary: Get agent by ID
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Agent details
 *       404:
 *         description: Agent not found
 */
router.get('/:agentId',
  authenticateAgent,
  requirePermission('read_agents'),
  [param('agentId').notEmpty()],
  validateRequest,
  async (req, res) => {
    try {
      const { agentId } = req.params;
      
      const agent = await Agent.findOne({ agentId }).select('-__v');
      if (!agent) {
        return res.status(404).json({
          error: 'Agent not found',
          code: 'AGENT_NOT_FOUND'
        });
      }
      
      res.json({ agent });
      
    } catch (error) {
      logger.logError(error, { context: 'Get Agent' });
      res.status(500).json({
        error: 'Failed to fetch agent',
        code: 'FETCH_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents/{agentId}/schedule:
 *   get:
 *     summary: Get agent scan schedule
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Agent scan schedule
 */
router.get('/:agentId/schedule',
  authenticateAgent,
  [param('agentId').notEmpty()],
  validateRequest,
  async (req, res) => {
    try {
      const { agentId } = req.params;
      
      const agent = await Agent.findOne({ agentId });
      if (!agent) {
        return res.status(404).json({
          error: 'Agent not found',
          code: 'AGENT_NOT_FOUND'
        });
      }
      
      res.json({
        interval_hours: agent.scanInterval,
        enabled: agent.configuration.scanEnabled,
        last_scan: agent.lastScanTime,
        next_scan: agent.lastScanTime ? 
          new Date(agent.lastScanTime.getTime() + agent.scanInterval * 60 * 60 * 1000) : 
          new Date()
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Get Agent Schedule' });
      res.status(500).json({
        error: 'Failed to fetch schedule',
        code: 'FETCH_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents/{agentId}:
 *   put:
 *     summary: Update agent configuration
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               scanInterval:
 *                 type: integer
 *               configuration:
 *                 type: object
 *               tags:
 *                 type: array
 *     responses:
 *       200:
 *         description: Agent updated successfully
 */
router.put('/:agentId',
  authenticateAgent,
  requirePermission('manage_agents'),
  [
    param('agentId').notEmpty(),
    body('scanInterval').optional().isInt({ min: 1, max: 168 }),
    body('configuration').optional().isObject(),
    body('tags').optional().isArray()
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { agentId } = req.params;
      const updates = req.body;
      
      const agent = await Agent.findOne({ agentId });
      if (!agent) {
        return res.status(404).json({
          error: 'Agent not found',
          code: 'AGENT_NOT_FOUND'
        });
      }
      
      // Update allowed fields
      if (updates.scanInterval) agent.scanInterval = updates.scanInterval;
      if (updates.configuration) {
        agent.configuration = { ...agent.configuration, ...updates.configuration };
      }
      if (updates.tags) agent.tags = updates.tags;
      
      await agent.save();
      
      logger.audit('agent_updated', req.user?.id, 'agent', {
        agentId: agent.agentId,
        updates: Object.keys(updates)
      });
      
      res.json({
        message: 'Agent updated successfully',
        agent: agent
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Update Agent' });
      res.status(500).json({
        error: 'Failed to update agent',
        code: 'UPDATE_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents/{agentId}:
 *   delete:
 *     summary: Delete agent
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Agent deleted successfully
 */
router.delete('/:agentId',
  authenticateAgent,
  requirePermission('manage_agents'),
  [param('agentId').notEmpty()],
  validateRequest,
  async (req, res) => {
    try {
      const { agentId } = req.params;
      
      const agent = await Agent.findOneAndDelete({ agentId });
      if (!agent) {
        return res.status(404).json({
          error: 'Agent not found',
          code: 'AGENT_NOT_FOUND'
        });
      }
      
      logger.audit('agent_deleted', req.user?.id, 'agent', {
        agentId: agent.agentId,
        hostname: agent.hostname
      });
      
      res.json({
        message: 'Agent deleted successfully'
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Delete Agent' });
      res.status(500).json({
        error: 'Failed to delete agent',
        code: 'DELETE_FAILED'
      });
    }
  }
);

/**
 * @swagger
 * /api/v1/agents/stats:
 *   get:
 *     summary: Get agent statistics
 *     tags: [Agents]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Agent statistics
 */
router.get('/stats/overview',
  authenticateAgent,
  requirePermission('read_agents'),
  async (req, res) => {
    try {
      const total = await Agent.countDocuments();
      const online = await Agent.countDocuments({
        lastHeartbeat: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
      });
      const byStatus = await Agent.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]);
      const byOS = await Agent.aggregate([
        { $group: { _id: '$osInfo.name', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);
      
      res.json({
        total,
        online,
        offline: total - online,
        byStatus: byStatus.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byOS: byOS.map(item => ({
          os: item._id || 'Unknown',
          count: item.count
        }))
      });
      
    } catch (error) {
      logger.logError(error, { context: 'Agent Stats' });
      res.status(500).json({
        error: 'Failed to fetch statistics',
        code: 'STATS_FAILED'
      });
    }
  }
);

module.exports = router;