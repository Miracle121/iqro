import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';

// Configuration
import { DatabaseConfig } from './config/database.config';
import { RedisConfig } from './config/redis.config';

// Feature Modules
import { AuthModule } from './auth/auth.module';
import { SessionModule } from './session/session.module';
import { VaultModule } from './vault/vault.module';
import { RbacModule } from './rbac/rbac.module';
import { AuditModule } from './audit/audit.module';
import { SiemModule } from './siem/siem.module';
import { CommonModule } from './common/common.module';

// Health Check
import { HealthController } from './health.controller';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
      cache: true,
    }),
    
    // Database
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => DatabaseConfig(configService),
    }),
    
    // Rate Limiting
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        ttl: configService.get<number>('RATE_LIMIT_TTL', 60),
        limit: configService.get<number>('RATE_LIMIT_LIMIT', 100),
      }),
    }),
    
    // Scheduler for background tasks
    ScheduleModule.forRoot(),
    
    // Common utilities
    CommonModule,
    
    // Feature modules
    AuthModule,
    SessionModule,
    VaultModule,
    RbacModule,
    AuditModule,
    SiemModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}