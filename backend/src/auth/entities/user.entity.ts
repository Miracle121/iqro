import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export enum UserRole {
  ADMIN = 'admin',
  AUDITOR = 'auditor',
  USER = 'user',
  VENDOR = 'vendor',
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  LOCKED = 'locked',
}

@Entity('users')
@Index(['email'], { unique: true })
@Index(['username'], { unique: true })
export class User {
  @ApiProperty({ description: 'User ID' })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ description: 'Username', example: 'john.doe' })
  @Column({ unique: true, length: 50 })
  username: string;

  @ApiProperty({ description: 'Email address', example: 'john.doe@company.com' })
  @Column({ unique: true, length: 255 })
  email: string;

  @Exclude()
  @Column()
  passwordHash: string;

  @ApiProperty({ description: 'First name', example: 'John' })
  @Column({ length: 100 })
  firstName: string;

  @ApiProperty({ description: 'Last name', example: 'Doe' })
  @Column({ length: 100 })
  lastName: string;

  @ApiProperty({ description: 'User role', enum: UserRole })
  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  role: UserRole;

  @ApiProperty({ description: 'User status', enum: UserStatus })
  @Column({
    type: 'enum',
    enum: UserStatus,
    default: UserStatus.ACTIVE,
  })
  status: UserStatus;

  @ApiProperty({ description: 'Phone number', example: '+1-555-0123' })
  @Column({ nullable: true, length: 20 })
  phoneNumber?: string;

  @ApiProperty({ description: 'Department', example: 'IT Security' })
  @Column({ nullable: true, length: 100 })
  department?: string;

  @ApiProperty({ description: 'Job title', example: 'Security Administrator' })
  @Column({ nullable: true, length: 100 })
  jobTitle?: string;

  @ApiProperty({ description: 'Manager ID' })
  @Column({ nullable: true })
  managerId?: string;

  // MFA Settings
  @Exclude()
  @Column({ nullable: true })
  mfaSecret?: string;

  @ApiProperty({ description: 'MFA enabled status' })
  @Column({ default: false })
  mfaEnabled: boolean;

  @ApiProperty({ description: 'MFA backup codes' })
  @Exclude()
  @Column('text', { array: true, nullable: true })
  mfaBackupCodes?: string[];

  // Security Settings
  @ApiProperty({ description: 'Require password change' })
  @Column({ default: false })
  requirePasswordChange: boolean;

  @ApiProperty({ description: 'Password last changed' })
  @Column({ nullable: true })
  passwordLastChanged?: Date;

  @ApiProperty({ description: 'Account locked until' })
  @Column({ nullable: true })
  lockedUntil?: Date;

  @ApiProperty({ description: 'Failed login attempts' })
  @Column({ default: 0 })
  failedLoginAttempts: number;

  @ApiProperty({ description: 'Last login IP' })
  @Column({ nullable: true, length: 45 })
  lastLoginIp?: string;

  @ApiProperty({ description: 'Last login time' })
  @Column({ nullable: true })
  lastLoginAt?: Date;

  @ApiProperty({ description: 'Last activity time' })
  @Column({ nullable: true })
  lastActivityAt?: Date;

  // Compliance and Audit
  @ApiProperty({ description: 'Account expires at' })
  @Column({ nullable: true })
  expiresAt?: Date;

  @ApiProperty({ description: 'Must complete training' })
  @Column({ default: false })
  requiresTraining: boolean;

  @ApiProperty({ description: 'Training completed at' })
  @Column({ nullable: true })
  trainingCompletedAt?: Date;

  @ApiProperty({ description: 'Background check status' })
  @Column({ nullable: true, length: 50 })
  backgroundCheckStatus?: string;

  @ApiProperty({ description: 'Security clearance level' })
  @Column({ nullable: true, length: 50 })
  securityClearance?: string;

  // Metadata
  @ApiProperty({ description: 'Additional user metadata' })
  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @ApiProperty({ description: 'User tags for categorization' })
  @Column('text', { array: true, nullable: true })
  tags?: string[];

  @ApiProperty({ description: 'User notes' })
  @Column('text', { nullable: true })
  notes?: string;

  @ApiProperty({ description: 'Created by user ID' })
  @Column({ nullable: true })
  createdBy?: string;

  @ApiProperty({ description: 'Updated by user ID' })
  @Column({ nullable: true })
  updatedBy?: string;

  @ApiProperty({ description: 'Creation timestamp' })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn()
  updatedAt: Date;

  // Virtual fields
  @ApiProperty({ description: 'Full name' })
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }

  @ApiProperty({ description: 'Is account locked' })
  get isLocked(): boolean {
    return this.lockedUntil ? new Date() < this.lockedUntil : false;
  }

  @ApiProperty({ description: 'Is account expired' })
  get isExpired(): boolean {
    return this.expiresAt ? new Date() > this.expiresAt : false;
  }

  @ApiProperty({ description: 'Is account active' })
  get isActive(): boolean {
    return (
      this.status === UserStatus.ACTIVE &&
      !this.isLocked &&
      !this.isExpired
    );
  }
}