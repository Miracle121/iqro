const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import custom modules
const logger = require('../config/logger');
const database = require('../config/database');

// Import routes
const scanRoutes = require('../routes/scan');
const hostRoutes = require('../routes/hosts');
const vulnerabilityRoutes = require('../routes/vulnerabilities');
const authRoutes = require('../routes/auth');
const analyticsRoutes = require('../routes/analytics');

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration
const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3001'],
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: 15 * 60
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api', limiter);

// Stricter rate limiting for scan endpoint
const scanLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // Limit each IP to 20 scan requests per 5 minutes
    message: {
        error: 'Too many scan requests, please try again later.',
        retryAfter: 5 * 60
    }
});
app.use('/api/scan', scanLimiter);

// Body parsing middleware
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(logger.requestLogger);

// API routes
app.use('/api/scan', scanRoutes);
app.use('/api/hosts', hostRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/analytics', analyticsRoutes);

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        const isDbHealthy = await database.ping();
        const health = {
            status: 'OK',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            database: isDbHealthy ? 'connected' : 'disconnected',
            version: process.env.npm_package_version || '1.0.0',
            environment: process.env.NODE_ENV || 'development'
        };
        
        res.status(isDbHealthy ? 200 : 503).json(health);
    } catch (error) {
        logger.error('Health check failed:', error);
        res.status(503).json({
            status: 'ERROR',
            timestamp: new Date().toISOString(),
            error: 'Health check failed'
        });
    }
});

// API info endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'HBVM Backend API',
        version: '1.0.0',
        description: 'Host-Based Vulnerability Management System Backend',
        endpoints: [
            'POST /api/scan - Submit scan results',
            'GET /api/hosts - List hosts',
            'GET /api/hosts/:id - Get host details',
            'GET /api/vulnerabilities - List vulnerabilities',
            'GET /api/analytics/dashboard - Get dashboard data',
            'POST /api/auth/login - Authenticate user',
            'GET /api/health - Health check'
        ],
        documentation: '/api/docs'
    });
});

// Catch 404 errors
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.originalUrl} not found`,
        timestamp: new Date().toISOString()
    });
});

// Error handling middleware
app.use(logger.errorLogger);

app.use((error, req, res, next) => {
    // Default error response
    let status = error.status || error.statusCode || 500;
    let message = error.message || 'Internal Server Error';
    
    // Handle specific error types
    if (error.name === 'ValidationError') {
        status = 400;
        message = 'Validation Error';
    } else if (error.name === 'CastError') {
        status = 400;
        message = 'Invalid ID format';
    } else if (error.code === 11000) {
        status = 409;
        message = 'Duplicate resource';
    }
    
    // Security: Don't expose internal errors in production
    if (process.env.NODE_ENV === 'production' && status === 500) {
        message = 'Internal Server Error';
    }
    
    const errorResponse = {
        error: message,
        timestamp: new Date().toISOString(),
        path: req.originalUrl,
        method: req.method
    };
    
    // Include stack trace in development
    if (process.env.NODE_ENV === 'development') {
        errorResponse.stack = error.stack;
    }
    
    res.status(status).json(errorResponse);
});

// Graceful shutdown handling
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown(signal) {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    
    // Stop accepting new connections
    server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
            // Close database connection
            await database.disconnect();
            logger.info('Database connection closed');
            
            // Exit process
            process.exit(0);
        } catch (error) {
            logger.error('Error during shutdown:', error);
            process.exit(1);
        }
    });
    
    // Force shutdown after 30 seconds
    setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
    }, 30000);
}

// Start server
async function startServer() {
    try {
        // Connect to database
        await database.connect();
        logger.info('Database connected successfully');
        
        // Start HTTP server
        const server = app.listen(PORT, () => {
            logger.info(`HBVM Backend server running on port ${PORT}`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            logger.info(`API Health: http://localhost:${PORT}/api/health`);
        });
        
        // Handle server errors
        server.on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
            } else {
                logger.error('Server error:', error);
            }
            process.exit(1);
        });
        
        // Store server reference for graceful shutdown
        global.server = server;
        
        return server;
        
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server if this file is run directly
if (require.main === module) {
    startServer();
}

module.exports = app;