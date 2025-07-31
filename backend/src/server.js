require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const database = require('./utils/database');
const logger = require('./utils/logger');
const { sanitizeInput } = require('./middleware/validation');

// Import routes
const agentsRoutes = require('./routes/agents');
const scansRoutes = require('./routes/scans');
const authRoutes = require('./routes/auth');
const healthRoutes = require('./routes/health');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Global error handler
const errorHandler = (err, req, res, next) => {
  logger.logError(err, {
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'Internal server error',
    code: err.code || 'INTERNAL_ERROR',
    ...(isDevelopment && { stack: err.stack })
  });
};

// 404 handler
const notFoundHandler = (req, res) => {
  res.status(404).json({
    error: 'Resource not found',
    code: 'NOT_FOUND',
    path: req.path
  });
};

async function startServer() {
  try {
    // Connect to database
    await database.connect();
    await database.ensureIndexes();
    
    // Security middleware
    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"]
        }
      },
      crossOriginEmbedderPolicy: false
    }));

    // CORS configuration
    const corsOptions = {
      origin: function (origin, callback) {
        const allowedOrigins = process.env.CORS_ORIGIN 
          ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
          : ['http://localhost:3001'];
        
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
    };
    
    app.use(cors(corsOptions));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: process.env.RATE_LIMIT_MAX || 100, // limit each IP to 100 requests per windowMs
      message: {
        error: 'Too many requests from this IP',
        code: 'RATE_LIMIT_EXCEEDED'
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        logger.logSecurity('Rate limit exceeded', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          url: req.url
        });
        
        res.status(429).json({
          error: 'Too many requests from this IP',
          code: 'RATE_LIMIT_EXCEEDED'
        });
      }
    });
    
    app.use(limiter);

    // Body parsing middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Compression
    app.use(compression());

    // Request logging
    app.use(morgan('combined', { stream: logger.stream }));

    // Trust proxy (for correct IP addresses behind load balancers)
    app.set('trust proxy', 1);

    // Input sanitization
    app.use(sanitizeInput);

    // Health check endpoint (before auth)
    app.use('/health', healthRoutes);

    // API routes
    app.use('/api/v1/auth', authRoutes);
    app.use('/api/v1/agents', agentsRoutes);
    app.use('/api/v1/scans', scansRoutes);

    // Swagger documentation (in development)
    if (process.env.NODE_ENV === 'development' && process.env.ENABLE_SWAGGER === 'true') {
      const swaggerUi = require('swagger-ui-express');
      const swaggerJsdoc = require('swagger-jsdoc');
      
      const swaggerOptions = {
        definition: {
          openapi: '3.0.0',
          info: {
            title: 'HBVM Backend API',
            version: '1.0.0',
            description: 'Host-Based Vulnerability Management System API',
          },
          servers: [
            {
              url: `http://localhost:${PORT}`,
              description: 'Development server',
            },
          ],
          components: {
            securitySchemes: {
              bearerAuth: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
              },
              apiKeyAuth: {
                type: 'apiKey',
                in: 'header',
                name: 'X-API-Key',
              },
            },
          },
        },
        apis: ['./src/routes/*.js'],
      };
      
      const specs = swaggerJsdoc(swaggerOptions);
      app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));
      
      logger.info('Swagger documentation available at /api-docs');
    }

    // Error handlers (must be last)
    app.use(notFoundHandler);
    app.use(errorHandler);

    // Start server
    const server = app.listen(PORT, HOST, () => {
      logger.info(`HBVM Backend server started`, {
        port: PORT,
        host: HOST,
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid
      });
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      logger.info(`Received ${signal}, starting graceful shutdown...`);
      
      server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
          await database.disconnect();
          logger.info('Database connection closed');
          process.exit(0);
        } catch (error) {
          logger.error('Error during shutdown:', error);
          process.exit(1);
        }
      });
      
      // Force close after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled rejection:', { reason, promise });
      gracefulShutdown('unhandledRejection');
    });

    return server;

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };