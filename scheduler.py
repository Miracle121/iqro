#!/usr/bin/env python3
"""
Scheduler module for the Vulnerability Scanner Agent
Provides advanced scheduling capabilities including cron-like scheduling
"""

import time
import threading
import logging
import schedule
from datetime import datetime, timedelta
from typing import Callable, Optional, Dict, Any


class ScannerScheduler:
    """Advanced scheduler for vulnerability scans"""
    
    def __init__(self, scanner_instance):
        self.scanner = scanner_instance
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.schedule_thread = None
        self.config = scanner_instance.config
        
    def start(self):
        """Start the scheduler"""
        if self.is_running:
            self.logger.warning("Scheduler is already running")
            return
        
        self.logger.info("Starting vulnerability scanner scheduler")
        self.is_running = True
        
        # Set up scheduled scans based on configuration
        self._setup_schedules()
        
        # Start the scheduler thread
        self.schedule_thread = threading.Thread(target=self._run_schedule_loop, daemon=True)
        self.schedule_thread.start()
        
        self.logger.info("Scheduler started successfully")
    
    def stop(self):
        """Stop the scheduler"""
        if not self.is_running:
            return
        
        self.logger.info("Stopping vulnerability scanner scheduler")
        self.is_running = False
        
        # Clear all scheduled jobs
        schedule.clear()
        
        if self.schedule_thread and self.schedule_thread.is_alive():
            self.schedule_thread.join(timeout=5)
        
        self.logger.info("Scheduler stopped")
    
    def _setup_schedules(self):
        """Set up scan schedules based on configuration"""
        schedule_config = self.config.get('schedule', {})
        
        # Default hourly scan
        if not schedule_config:
            interval = self.config.get('scan_interval', 3600) // 60  # Convert to minutes
            schedule.every(interval).minutes.do(self._run_scheduled_scan)
            self.logger.info(f"Scheduled scan every {interval} minutes")
            return
        
        # Cron-like scheduling
        if schedule_config.get('cron_expression'):
            self._setup_cron_schedule(schedule_config['cron_expression'])
        
        # Simple interval scheduling
        elif schedule_config.get('interval_minutes'):
            minutes = schedule_config['interval_minutes']
            schedule.every(minutes).minutes.do(self._run_scheduled_scan)
            self.logger.info(f"Scheduled scan every {minutes} minutes")
        
        elif schedule_config.get('interval_hours'):
            hours = schedule_config['interval_hours']
            schedule.every(hours).hours.do(self._run_scheduled_scan)
            self.logger.info(f"Scheduled scan every {hours} hours")
        
        # Daily scheduling
        elif schedule_config.get('daily_at'):
            time_str = schedule_config['daily_at']
            schedule.every().day.at(time_str).do(self._run_scheduled_scan)
            self.logger.info(f"Scheduled daily scan at {time_str}")
        
        # Weekly scheduling
        elif schedule_config.get('weekly'):
            day = schedule_config['weekly'].get('day', 'monday')
            time_str = schedule_config['weekly'].get('time', '02:00')
            getattr(schedule.every(), day.lower()).at(time_str).do(self._run_scheduled_scan)
            self.logger.info(f"Scheduled weekly scan on {day} at {time_str}")
        
        # Multiple schedules
        elif schedule_config.get('multiple_schedules'):
            for sched in schedule_config['multiple_schedules']:
                self._setup_single_schedule(sched)
    
    def _setup_single_schedule(self, sched_config: Dict[str, Any]):
        """Set up a single schedule configuration"""
        if sched_config.get('type') == 'interval':
            if 'minutes' in sched_config:
                schedule.every(sched_config['minutes']).minutes.do(self._run_scheduled_scan)
            elif 'hours' in sched_config:
                schedule.every(sched_config['hours']).hours.do(self._run_scheduled_scan)
        
        elif sched_config.get('type') == 'daily':
            time_str = sched_config.get('time', '02:00')
            schedule.every().day.at(time_str).do(self._run_scheduled_scan)
        
        elif sched_config.get('type') == 'weekly':
            day = sched_config.get('day', 'monday')
            time_str = sched_config.get('time', '02:00')
            getattr(schedule.every(), day.lower()).at(time_str).do(self._run_scheduled_scan)
    
    def _setup_cron_schedule(self, cron_expression: str):
        """Set up cron-like scheduling (simplified implementation)"""
        # This is a simplified cron parser - for production use a proper cron library
        try:
            parts = cron_expression.split()
            if len(parts) == 5:  # minute hour day month weekday
                minute, hour, day, month, weekday = parts
                
                if minute.isdigit() and hour.isdigit():
                    time_str = f"{hour.zfill(2)}:{minute.zfill(2)}"
                    
                    if day == '*' and month == '*' and weekday == '*':
                        # Daily
                        schedule.every().day.at(time_str).do(self._run_scheduled_scan)
                        self.logger.info(f"Scheduled daily scan at {time_str}")
                    elif weekday.isdigit():
                        # Weekly on specific day
                        days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
                        day_name = days[int(weekday)]
                        getattr(schedule.every(), day_name).at(time_str).do(self._run_scheduled_scan)
                        self.logger.info(f"Scheduled weekly scan on {day_name} at {time_str}")
        
        except Exception as e:
            self.logger.error(f"Failed to parse cron expression '{cron_expression}': {e}")
            # Fallback to hourly
            schedule.every().hour.do(self._run_scheduled_scan)
    
    def _run_schedule_loop(self):
        """Main scheduler loop"""
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in scheduler loop: {e}")
                time.sleep(60)
    
    def _run_scheduled_scan(self):
        """Run a scheduled scan"""
        self.logger.info("Starting scheduled vulnerability scan")
        
        try:
            # Check if a scan is already running
            if hasattr(self.scanner, '_scan_in_progress') and self.scanner._scan_in_progress:
                self.logger.warning("Scan already in progress, skipping scheduled scan")
                return
            
            # Mark scan as in progress
            self.scanner._scan_in_progress = True
            
            # Run the scan
            result = self.scanner.run_scan_cycle()
            
            if result:
                self.logger.info(f"Scheduled scan completed successfully: {result['scan_id']}")
            else:
                self.logger.error("Scheduled scan failed")
        
        except Exception as e:
            self.logger.error(f"Error during scheduled scan: {e}")
        
        finally:
            # Mark scan as completed
            self.scanner._scan_in_progress = False
    
    def schedule_immediate_scan(self):
        """Schedule an immediate scan"""
        self.logger.info("Scheduling immediate scan")
        
        def immediate_scan():
            time.sleep(1)  # Small delay to avoid conflicts
            self._run_scheduled_scan()
        
        thread = threading.Thread(target=immediate_scan, daemon=True)
        thread.start()
    
    def get_next_run_time(self) -> Optional[datetime]:
        """Get the next scheduled run time"""
        jobs = schedule.jobs
        if not jobs:
            return None
        
        next_run = min(job.next_run for job in jobs)
        return next_run
    
    def get_schedule_info(self) -> Dict[str, Any]:
        """Get information about current schedules"""
        jobs = schedule.jobs
        
        schedule_info = {
            'active_schedules': len(jobs),
            'next_run': self.get_next_run_time(),
            'schedules': []
        }
        
        for job in jobs:
            schedule_info['schedules'].append({
                'job_func': str(job.job_func),
                'next_run': job.next_run,
                'interval': job.interval,
                'unit': job.unit
            })
        
        return schedule_info


class CronScheduler:
    """A more robust cron-like scheduler implementation"""
    
    def __init__(self, scanner_instance):
        self.scanner = scanner_instance
        self.logger = logging.getLogger(__name__)
        self.jobs = []
        self.is_running = False
        self.scheduler_thread = None
    
    def add_cron_job(self, cron_expression: str, scan_type: str = 'full'):
        """Add a cron job
        
        Cron format: minute hour day month weekday
        Examples:
        - "0 2 * * *" - Daily at 2:00 AM
        - "0 */6 * * *" - Every 6 hours
        - "0 9 * * 1" - Every Monday at 9:00 AM
        """
        job = {
            'cron': cron_expression,
            'scan_type': scan_type,
            'next_run': self._calculate_next_run(cron_expression)
        }
        self.jobs.append(job)
        self.logger.info(f"Added cron job: {cron_expression} for {scan_type} scan")
    
    def _calculate_next_run(self, cron_expression: str) -> datetime:
        """Calculate next run time for cron expression"""
        # This is a simplified implementation
        # For production, use a proper cron library like croniter
        
        try:
            parts = cron_expression.split()
            if len(parts) != 5:
                raise ValueError("Invalid cron expression format")
            
            minute, hour, day, month, weekday = parts
            
            now = datetime.now()
            next_run = now.replace(second=0, microsecond=0)
            
            # Simple case: daily at specific time
            if minute.isdigit() and hour.isdigit() and day == '*' and month == '*' and weekday == '*':
                target_time = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
                if target_time <= now:
                    target_time += timedelta(days=1)
                return target_time
            
            # Default to next hour if parsing fails
            return now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        
        except Exception as e:
            self.logger.error(f"Error calculating next run for cron expression '{cron_expression}': {e}")
            return datetime.now() + timedelta(hours=1)
    
    def start(self):
        """Start the cron scheduler"""
        if self.is_running:
            return
        
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_cron_loop, daemon=True)
        self.scheduler_thread.start()
        self.logger.info("Cron scheduler started")
    
    def stop(self):
        """Stop the cron scheduler"""
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.logger.info("Cron scheduler stopped")
    
    def _run_cron_loop(self):
        """Main cron scheduler loop"""
        while self.is_running:
            try:
                now = datetime.now()
                
                for job in self.jobs:
                    if now >= job['next_run']:
                        self.logger.info(f"Running cron job: {job['cron']}")
                        
                        # Run the scan
                        self.scanner._run_scheduled_scan()
                        
                        # Calculate next run time
                        job['next_run'] = self._calculate_next_run(job['cron'])
                
                time.sleep(60)  # Check every minute
            
            except Exception as e:
                self.logger.error(f"Error in cron scheduler loop: {e}")
                time.sleep(60)