import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { User } from '../../auth/entities/user.entity';

export enum SessionStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  TERMINATED = 'terminated',
  EXPIRED = 'expired',
}

export enum SessionType {
  SSH = 'ssh',
  RDP = 'rdp',
  TELNET = 'telnet',
  HTTP = 'http',
  HTTPS = 'https',
  DATABASE = 'database',
  CUSTOM = 'custom',
}

@Entity('sessions')
@Index(['user_id'])
@Index(['status'])
@Index(['start_time'])
@Index(['target_system'])
export class Session {
  @ApiProperty({ description: 'Session ID' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'User ID' })
  @Column({ name: 'user_id' })
  userId: string;

  @ApiProperty({ description: 'User who initiated the session' })
  @ManyToOne(() => User, { eager: true })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ApiProperty({ description: 'Target system name', example: 'prod-web-01' })
  @Column({ name: 'target_system', length: 255 })
  targetSystem: string;

  @ApiProperty({ description: 'Target host address', example: '192.168.1.100' })
  @Column({ name: 'target_host', length: 255 })
  targetHost: string;

  @ApiProperty({ description: 'Target port', example: 22 })
  @Column({ name: 'target_port', nullable: true })
  targetPort?: number;

  @ApiProperty({ description: 'Target username', example: 'root' })
  @Column({ name: 'target_username', length: 100, nullable: true })
  targetUsername?: string;

  @ApiProperty({ description: 'Session type', enum: SessionType })
  @Column({
    name: 'session_type',
    type: 'enum',
    enum: SessionType,
    default: SessionType.SSH,
  })
  sessionType: SessionType;

  @ApiProperty({ description: 'Session status', enum: SessionStatus })
  @Column({
    type: 'enum',
    enum: SessionStatus,
    default: SessionStatus.ACTIVE,
  })
  status: SessionStatus;

  @ApiProperty({ description: 'Session start time' })
  @Column({ name: 'start_time', default: () => 'CURRENT_TIMESTAMP' })
  startTime: Date;

  @ApiProperty({ description: 'Session end time' })
  @Column({ name: 'end_time', nullable: true })
  endTime?: Date;

  @ApiProperty({ description: 'Session duration in seconds' })
  @Column({ name: 'duration_seconds', nullable: true })
  durationSeconds?: number;

  @ApiProperty({ description: 'Client IP address' })
  @Column({ name: 'client_ip', nullable: true })
  clientIp?: string;

  @ApiProperty({ description: 'Session recording file path' })
  @Column({ name: 'recording_path', nullable: true })
  recordingPath?: string;

  @ApiProperty({ description: 'Associated approval ID' })
  @Column({ name: 'approval_id', nullable: true })
  approvalId?: string;

  @ApiProperty({ description: 'Additional session metadata' })
  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @ApiProperty({ description: 'Creation timestamp' })
  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  // Virtual properties
  @ApiProperty({ description: 'Is session currently active' })
  get isActive(): boolean {
    return this.status === SessionStatus.ACTIVE;
  }

  @ApiProperty({ description: 'Session duration in human-readable format' })
  get duration(): string {
    if (!this.durationSeconds) return 'N/A';
    
    const hours = Math.floor(this.durationSeconds / 3600);
    const minutes = Math.floor((this.durationSeconds % 3600) / 60);
    const seconds = this.durationSeconds % 60;
    
    return `${hours}h ${minutes}m ${seconds}s`;
  }

  @ApiProperty({ description: 'Has session recording' })
  get hasRecording(): boolean {
    return !!this.recordingPath;
  }

  @ApiProperty({ description: 'Session target identifier' })
  get targetIdentifier(): string {
    return this.targetUsername ? 
      `${this.targetUsername}@${this.targetHost}:${this.targetPort || 22}` :
      `${this.targetHost}:${this.targetPort || 22}`;
  }
}