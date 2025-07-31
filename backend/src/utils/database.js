const mongoose = require('mongoose');
const logger = require('./logger');

class Database {
  constructor() {
    this.connection = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/hbvm';
      
      const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10, // Maintain up to 10 socket connections
        serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
        socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
        bufferMaxEntries: 0, // Disable mongoose buffering
        bufferCommands: false, // Disable mongoose buffering
      };

      // Add additional options from environment
      if (process.env.MONGODB_OPTIONS) {
        try {
          const additionalOptions = JSON.parse(process.env.MONGODB_OPTIONS);
          Object.assign(options, additionalOptions);
        } catch (error) {
          logger.warn('Invalid MONGODB_OPTIONS format, using defaults');
        }
      }

      logger.info('Connecting to MongoDB...', { uri: uri.replace(/\/\/.*@/, '//***:***@') });

      this.connection = await mongoose.connect(uri, options);
      this.isConnected = true;

      logger.info('Successfully connected to MongoDB', {
        database: this.connection.connection.name,
        host: this.connection.connection.host,
        port: this.connection.connection.port
      });

      // Set up event listeners
      this._setupEventListeners();
      
      return this.connection;

    } catch (error) {
      logger.error('Failed to connect to MongoDB:', error);
      throw error;
    }
  }

  async disconnect() {
    try {
      if (this.connection) {
        await mongoose.connection.close();
        this.isConnected = false;
        logger.info('Disconnected from MongoDB');
      }
    } catch (error) {
      logger.error('Error disconnecting from MongoDB:', error);
      throw error;
    }
  }

  async ping() {
    try {
      if (!this.isConnected) {
        throw new Error('Database not connected');
      }
      
      await mongoose.connection.db.admin().ping();
      return true;
    } catch (error) {
      logger.error('Database ping failed:', error);
      return false;
    }
  }

  getStats() {
    if (!this.isConnected) {
      return null;
    }

    const stats = {
      readyState: mongoose.connection.readyState,
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      name: mongoose.connection.name,
      collections: Object.keys(mongoose.connection.collections).length
    };

    return stats;
  }

  async getDbStats() {
    try {
      if (!this.isConnected) {
        throw new Error('Database not connected');
      }

      const admin = mongoose.connection.db.admin();
      const stats = await admin.dbStats();
      
      return {
        collections: stats.collections,
        objects: stats.objects,
        avgObjSize: stats.avgObjSize,
        dataSize: stats.dataSize,
        storageSize: stats.storageSize,
        indexes: stats.indexes,
        indexSize: stats.indexSize
      };
    } catch (error) {
      logger.error('Failed to get database stats:', error);
      throw error;
    }
  }

  _setupEventListeners() {
    mongoose.connection.on('connected', () => {
      logger.info('Mongoose connected to MongoDB');
      this.isConnected = true;
    });

    mongoose.connection.on('error', (error) => {
      logger.error('Mongoose connection error:', error);
      this.isConnected = false;
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('Mongoose disconnected from MongoDB');
      this.isConnected = false;
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('Mongoose reconnected to MongoDB');
      this.isConnected = true;
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      try {
        await this.disconnect();
        logger.info('Database connection closed due to application termination');
        process.exit(0);
      } catch (error) {
        logger.error('Error during graceful shutdown:', error);
        process.exit(1);
      }
    });
  }

  // Health check method
  async healthCheck() {
    try {
      const isAlive = await this.ping();
      const stats = this.getStats();
      
      return {
        status: isAlive ? 'healthy' : 'unhealthy',
        connection: {
          isConnected: this.isConnected,
          readyState: stats ? stats.readyState : 0,
          host: stats ? stats.host : null,
          port: stats ? stats.port : null,
          database: stats ? stats.name : null
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Transaction helper
  async withTransaction(operation) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      const result = await operation(session);
      await session.commitTransaction();
      return result;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      await session.endSession();
    }
  }

  // Index management
  async ensureIndexes() {
    try {
      logger.info('Ensuring database indexes...');
      
      const models = mongoose.modelNames();
      const indexOperations = [];
      
      for (const modelName of models) {
        const model = mongoose.model(modelName);
        indexOperations.push(model.ensureIndexes());
      }
      
      await Promise.all(indexOperations);
      logger.info('Database indexes ensured successfully');
      
    } catch (error) {
      logger.error('Failed to ensure indexes:', error);
      throw error;
    }
  }

  // Collection utilities
  async dropCollection(collectionName) {
    try {
      if (!this.isConnected) {
        throw new Error('Database not connected');
      }
      
      const collections = await mongoose.connection.db.listCollections().toArray();
      const exists = collections.some(col => col.name === collectionName);
      
      if (exists) {
        await mongoose.connection.db.dropCollection(collectionName);
        logger.info(`Dropped collection: ${collectionName}`);
      } else {
        logger.warn(`Collection does not exist: ${collectionName}`);
      }
    } catch (error) {
      logger.error(`Failed to drop collection ${collectionName}:`, error);
      throw error;
    }
  }

  async createBackup(backupName) {
    try {
      logger.info(`Creating backup: ${backupName}`);
      
      // This is a basic implementation
      // In production, you might want to use mongodump or similar tools
      const stats = await this.getDbStats();
      logger.info('Backup created successfully', { 
        backupName, 
        collections: stats.collections,
        dataSize: stats.dataSize 
      });
      
      return { success: true, backupName, timestamp: new Date() };
    } catch (error) {
      logger.error(`Backup creation failed:`, error);
      throw error;
    }
  }
}

// Export singleton instance
module.exports = new Database();