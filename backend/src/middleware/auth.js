const jwt = require('jsonwebtoken');
const { User } = require('../models');
const logger = require('../utils/logger');

/**
 * JWT Authentication Middleware
 */
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        error: 'Access token required',
        code: 'TOKEN_MISSING'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const user = await User.findById(decoded.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({
        error: 'Invalid or inactive user',
        code: 'USER_INVALID'
      });
    }

    req.user = user;
    req.token = token;
    next();

  } catch (error) {
    logger.logSecurity('Invalid JWT token', {
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token',
        code: 'TOKEN_INVALID'
      });
    }

    return res.status(401).json({
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

/**
 * API Key Authentication Middleware
 */
const authenticateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({
        error: 'API key required',
        code: 'API_KEY_MISSING'
      });
    }

    // Find user with this API key
    const users = await User.find({ 'apiKeys.isActive': true });
    let authenticatedUser = null;
    let apiKeyDoc = null;

    for (const user of users) {
      apiKeyDoc = user.validateApiKey(apiKey);
      if (apiKeyDoc) {
        authenticatedUser = user;
        break;
      }
    }

    if (!authenticatedUser || !apiKeyDoc) {
      logger.logSecurity('Invalid API key used', {
        apiKey: apiKey.substring(0, 10) + '...',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(401).json({
        error: 'Invalid API key',
        code: 'API_KEY_INVALID'
      });
    }

    req.user = authenticatedUser;
    req.apiKey = apiKeyDoc;
    next();

  } catch (error) {
    logger.logError(error, { context: 'API Key Authentication' });
    return res.status(500).json({
      error: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Agent Authentication Middleware (for agent endpoints)
 */
const authenticateAgent = async (req, res, next) => {
  try {
    // Try JWT first
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authenticateToken(req, res, next);
    }

    // Try API key
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      return authenticateApiKey(req, res, next);
    }

    return res.status(401).json({
      error: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });

  } catch (error) {
    logger.logError(error, { context: 'Agent Authentication' });
    return res.status(500).json({
      error: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Role-based Authorization Middleware
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    if (!roles.includes(req.user.role)) {
      logger.logSecurity('Unauthorized role access attempt', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: roles,
        resource: req.path,
        method: req.method,
        ip: req.ip
      });

      return res.status(403).json({
        error: 'Insufficient privileges',
        code: 'INSUFFICIENT_PRIVILEGES'
      });
    }

    next();
  };
};

/**
 * Permission-based Authorization Middleware
 */
const requirePermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const hasPermission = permissions.some(permission => 
      req.user.hasPermission(permission)
    );

    if (!hasPermission) {
      logger.logSecurity('Unauthorized permission access attempt', {
        userId: req.user.id,
        userPermissions: req.user.permissions,
        requiredPermissions: permissions,
        resource: req.path,
        method: req.method,
        ip: req.ip
      });

      return res.status(403).json({
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS'
      });
    }

    next();
  };
};

/**
 * Optional Authentication Middleware
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        if (user && user.isActive) {
          req.user = user;
        }
      } catch (error) {
        // Ignore token errors for optional auth
      }
    }

    next();
  } catch (error) {
    // Continue without authentication for optional auth
    next();
  }
};

module.exports = {
  authenticateToken,
  authenticateApiKey,
  authenticateAgent,
  requireRole,
  requirePermission,
  optionalAuth
};