import { Module, Global } from '@nestjs/common';
import { EncryptionService } from './services/encryption.service';
import { LoggerService } from './services/logger.service';
import { RedisService } from './services/redis.service';

@Global()
@Module({
  providers: [
    EncryptionService,
    LoggerService,
    RedisService,
  ],
  exports: [
    EncryptionService,
    LoggerService,
    RedisService,
  ],
})
export class CommonModule {}