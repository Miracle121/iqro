import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import 'winston-daily-rotate-file';

@Injectable()
export class LoggerService {
  private readonly logger: winston.Logger;

  constructor(private readonly configService: ConfigService) {
    this.logger = winston.createLogger({
      level: this.configService.get<string>('LOG_LEVEL', 'info'),
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return JSON.stringify({
            timestamp,
            level,
            message,
            ...meta,
            service: 'pam-system',
            environment: this.configService.get<string>('NODE_ENV', 'development'),
          });
        })
      ),
      defaultMeta: {
        service: 'pam-system',
      },
      transports: [
        // Console transport
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
        }),
        
        // Daily rotate file for all logs
        new winston.transports.DailyRotateFile({
          filename: 'logs/pam-system-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          maxSize: '20m',
          maxFiles: '30d',
          format: winston.format.json(),
        }),
        
        // Daily rotate file for error logs
        new winston.transports.DailyRotateFile({
          filename: 'logs/pam-system-error-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          maxSize: '20m',
          maxFiles: '90d',
          level: 'error',
          format: winston.format.json(),
        }),
        
        // Security audit logs
        new winston.transports.DailyRotateFile({
          filename: 'logs/pam-system-security-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          maxSize: '20m',
          maxFiles: '365d',
          format: winston.format.json(),
        }),
      ],
    });
  }

  log(level: string, message: string, meta?: any) {
    this.logger.log(level, message, meta);
  }

  info(message: string, meta?: any) {
    this.logger.info(message, meta);
  }

  warn(message: string, meta?: any) {
    this.logger.warn(message, meta);
  }

  error(message: string, error?: Error, meta?: any) {
    this.logger.error(message, {
      error: error?.message,
      stack: error?.stack,
      ...meta,
    });
  }

  debug(message: string, meta?: any) {
    this.logger.debug(message, meta);
  }

  // Security-specific logging methods
  logSecurityEvent(event: string, userId?: string, details?: any) {
    this.logger.info('SECURITY_EVENT', {
      event,
      userId,
      details,
      timestamp: new Date().toISOString(),
      category: 'security',
    });
  }

  logAuthentication(event: string, userId: string, ip: string, userAgent?: string, success?: boolean) {
    this.logger.info('AUTHENTICATION_EVENT', {
      event,
      userId,
      ip,
      userAgent,
      success,
      timestamp: new Date().toISOString(),
      category: 'authentication',
    });
  }

  logSessionActivity(event: string, sessionId: string, userId: string, details?: any) {
    this.logger.info('SESSION_EVENT', {
      event,
      sessionId,
      userId,
      details,
      timestamp: new Date().toISOString(),
      category: 'session',
    });
  }

  logVaultAccess(event: string, userId: string, resourceId: string, action: string) {
    this.logger.info('VAULT_ACCESS', {
      event,
      userId,
      resourceId,
      action,
      timestamp: new Date().toISOString(),
      category: 'vault',
    });
  }

  logComplianceEvent(event: string, details: any) {
    this.logger.info('COMPLIANCE_EVENT', {
      event,
      details,
      timestamp: new Date().toISOString(),
      category: 'compliance',
    });
  }
}