# gui/jobs_system.py
"""
Unified Jobs System for JASMIN GUI - Updated for GUI Integration
Properly integrates with existing JASMIN scan and payload systems
"""

import os
import sys
import time
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import json

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, QTimer

class JobStatus(Enum):
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class JobType(Enum):
    SCAN_TCP = "scan_tcp"
    SCAN_FULL = "scan_full"
    SCAN_WEB = "scan_web"
    SCAN_UDP = "scan_udp"
    SCAN_SCRIPT = "scan_script"
    PAYLOAD_GENERATE = "payload_generate"

@dataclass
class Job:
    """Individual job representation"""
    id: str
    name: str
    job_type: JobType
    status: JobStatus
    progress: int = 0
    artifact: Optional[Path] = None
    log_path: Optional[Path] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class JobSignals(QObject):
    """Qt signals for job events"""
    job_started = pyqtSignal(str)  # job_id
    job_progress = pyqtSignal(str, int)  # job_id, progress
    job_completed = pyqtSignal(str, str)  # job_id, artifact_path
    job_failed = pyqtSignal(str, str)  # job_id, error_message
    job_cancelled = pyqtSignal(str)  # job_id

class JobWorker(QRunnable):
    """Worker thread for executing jobs"""
    
    def __init__(self, job: Job, execute_func: Callable, signals: JobSignals):
        super().__init__()
        self.job = job
        self.execute_func = execute_func
        self.signals = signals
        self.is_cancelled = False
        self.process = None  # For subprocess management
    
    def run(self):
        """Execute the job"""
        if self.is_cancelled:
            return
        
        try:
            # Mark job as started
            self.job.status = JobStatus.RUNNING
            self.job.started_at = datetime.now()
            self.signals.job_started.emit(self.job.id)
            
            # Execute the job with progress callback
            success = self.execute_func(self.job, self.update_progress, self.set_process)
            
            if self.is_cancelled:
                self.job.status = JobStatus.CANCELLED
                self.signals.job_cancelled.emit(self.job.id)
            elif success:
                self.job.status = JobStatus.COMPLETED
                self.job.completed_at = datetime.now()
                self.job.progress = 100
                artifact_path = str(self.job.artifact) if self.job.artifact else ""
                self.signals.job_completed.emit(self.job.id, artifact_path)
            else:
                self.job.status = JobStatus.FAILED
                self.job.completed_at = datetime.now()
                error_msg = self.job.error_message or "Job failed"
                self.signals.job_failed.emit(self.job.id, error_msg)
                
        except Exception as e:
            self.job.status = JobStatus.FAILED
            self.job.completed_at = datetime.now()
            self.job.error_message = str(e)
            self.signals.job_failed.emit(self.job.id, str(e))
    
    def update_progress(self, progress: int):
        """Update job progress"""
        if not self.is_cancelled:
            self.job.progress = min(100, max(0, progress))
            self.signals.job_progress.emit(self.job.id, self.job.progress)
    
    def set_process(self, process):
        """Set subprocess for cancellation"""
        self.process = process
    
    def cancel(self):
        """Cancel the job"""
        self.is_cancelled = True
        if self.process:
            try:
                self.process.terminate()
                # Give it a moment to terminate gracefully
                threading.Timer(3.0, lambda: self.process.kill() if self.process.poll() is None else None).start()
            except Exception:
                pass

class JobsManager(QObject):
    """Central job management system for JASMIN GUI"""
    
    # Qt signals for GUI updates
    job_added = pyqtSignal(str)  # job_id
    job_updated = pyqtSignal(str)  # job_id
    job_removed = pyqtSignal(str)  # job_id
    
    def __init__(self, env: Dict[str, Any], max_concurrent_jobs: int = 3):
        super().__init__()
        self.env = env
        self.jobs: Dict[str, Job] = {}
        self.workers: Dict[str, JobWorker] = {}
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(max_concurrent_jobs)
        
        # Job signals
        self.signals = JobSignals()
        self.signals.job_started.connect(self._on_job_started)
        self.signals.job_progress.connect(self._on_job_progress)
        self.signals.job_completed.connect(self._on_job_completed)
        self.signals.job_failed.connect(self._on_job_failed)
        self.signals.job_cancelled.connect(self._on_job_cancelled)
        
        # Session info
        self.outdir = Path(env.get("OUTDIR", "."))
        self.target_name = env.get("BOXNAME", "unknown")
        self.target_ip = env.get("IP", "0.0.0.0")
        
        # Load existing jobs
        self._load_jobs()
        
        # Periodic cleanup timer
        self.cleanup_timer = QTimer()
        self.cleanup_timer.timeout.connect(self._cleanup_old_jobs)
        self.cleanup_timer.start(60000)  # Every minute
        
        print(f"[+] Jobs manager initialized for {self.target_name} ({self.target_ip})")
    
    def _generate_job_id(self, job_type: JobType) -> str:
        """Generate unique job ID"""
        timestamp = int(datetime.now().timestamp() * 1000)
        return f"{job_type.value}_{timestamp}"
    
    def _get_jobs_file(self) -> Path:
        """Get jobs persistence file"""
        return self.outdir / "jobs.json"
    
    def _save_jobs(self):
        """Save jobs to disk"""
        try:
            jobs_data = {}
            for job_id, job in self.jobs.items():
                jobs_data[job_id] = {
                    'id': job.id,
                    'name': job.name,
                    'job_type': job.job_type.value,
                    'status': job.status.value,
                    'progress': job.progress,
                    'artifact': str(job.artifact) if job.artifact else None,
                    'log_path': str(job.log_path) if job.log_path else None,
                    'error_message': job.error_message,
                    'created_at': job.created_at.isoformat(),
                    'started_at': job.started_at.isoformat() if job.started_at else None,
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                    'metadata': job.metadata
                }
            
            with open(self._get_jobs_file(), 'w') as f:
                json.dump(jobs_data, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save jobs: {e}")
    
    def _load_jobs(self):
        """Load jobs from disk"""
        try:
            jobs_file = self._get_jobs_file()
            if not jobs_file.exists():
                return
            
            with open(jobs_file, 'r') as f:
                jobs_data = json.load(f)
            
            for job_id, data in jobs_data.items():
                job = Job(
                    id=data['id'],
                    name=data['name'],
                    job_type=JobType(data['job_type']),
                    status=JobStatus(data['status']),
                    progress=data['progress'],
                    artifact=Path(data['artifact']) if data['artifact'] else None,
                    log_path=Path(data['log_path']) if data['log_path'] else None,
                    error_message=data['error_message'],
                    created_at=datetime.fromisoformat(data['created_at']),
                    started_at=datetime.fromisoformat(data['started_at']) if data['started_at'] else None,
                    completed_at=datetime.fromisoformat(data['completed_at']) if data['completed_at'] else None,
                    metadata=data['metadata']
                )
                self.jobs[job_id] = job
        except Exception as e:
            print(f"[!] Failed to load jobs: {e}")
    
    # === Job Creation Methods ===
    
    def start_scan(self, scan_type: str, target: str = None) -> str:
        """Start a scan job (main entry point from GUI)"""
        if target is None:
            target = self.target_ip
            
        scan_type = scan_type.lower()
        
        if scan_type == "tcp":
            return self.start_tcp_scan(target)
        elif scan_type in ["fs", "full"]:
            return self.start_full_scan(target)
        elif scan_type == "web":
            return self.start_web_scan(target)
        elif scan_type == "udp":
            return self.start_udp_scan(target)
        elif scan_type == "script":
            return self.start_script_scan(target)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
    
    def start_tcp_scan(self, target: str) -> str:
        """Start TCP scan job"""
        job_id = self._generate_job_id(JobType.SCAN_TCP)
        
        artifact_path = self.outdir / f"{self.target_name}_tcp.nmap"
        log_path = self.outdir / f"{job_id}.log"
        
        job = Job(
            id=job_id,
            name=f"TCP Scan - {target}",
            job_type=JobType.SCAN_TCP,
            status=JobStatus.PENDING,
            artifact=artifact_path,
            log_path=log_path,
            metadata={'target': target, 'scan_type': 'tcp'}
        )
        
        worker = JobWorker(job, self._execute_scan, self.signals)
        return self._submit_job(job, worker)
    
    def start_full_scan(self, target: str) -> str:
        """Start full scan job"""
        job_id = self._generate_job_id(JobType.SCAN_FULL)
        
        artifact_path = self.outdir / f"{self.target_name}_full.nmap"
        log_path = self.outdir / f"{job_id}.log"
        
        job = Job(
            id=job_id,
            name=f"Full Scan - {target}",
            job_type=JobType.SCAN_FULL,
            status=JobStatus.PENDING,
            artifact=artifact_path,
            log_path=log_path,
            metadata={'target': target, 'scan_type': 'fs'}
        )
        
        worker = JobWorker(job, self._execute_scan, self.signals)
        return self._submit_job(job, worker)
    
    def start_web_scan(self, target: str) -> str:
        """Start web scan job"""
        job_id = self._generate_job_id(JobType.SCAN_WEB)
        
        artifact_path = self.outdir / f"{self.target_name}_web.txt"
        log_path = self.outdir / f"{job_id}.log"
        
        job = Job(
            id=job_id,
            name=f"Web Scan - {target}",
            job_type=JobType.SCAN_WEB,
            status=JobStatus.PENDING,
            artifact=artifact_path,
            log_path=log_path,
            metadata={'target': target, 'scan_type': 'web'}
        )
        
        worker = JobWorker(job, self._execute_scan, self.signals)
        return self._submit_job(job, worker)
    
    def start_udp_scan(self, target: str) -> str:
        """Start UDP scan job"""
        job_id = self._generate_job_id(JobType.SCAN_UDP)
        
        artifact_path = self.outdir / f"{self.target_name}_udp.nmap"
        log_path = self.outdir / f"{job_id}.log"
        
        job = Job(
            id=job_id,
            name=f"UDP Scan - {target}",
            job_type=JobType.SCAN_UDP,
            status=JobStatus.PENDING,
            artifact=artifact_path,
            log_path=log_path,
            metadata={'target': target, 'scan_type': 'udp'}
        )
        
        worker = JobWorker(job, self._execute_scan, self.signals)
        return self._submit_job(job, worker)
    
    def start_script_scan(self, target: str) -> str:
        """Start script scan job"""
        job_id = self._generate_job_id(JobType.SCAN_SCRIPT)
        
        artifact_path = self.outdir / f"{self.target_name}_script.nmap"
        log_path = self.outdir / f"{job_id}.log"
        
        job = Job(
            id=job_id,
            name=f"Script Scan - {target}",
            job_type=JobType.SCAN_SCRIPT,
            status=JobStatus.PENDING,
            artifact=artifact_path,
            log_path=log_path,
            metadata={'target': target, 'scan_type': 'script'}
        )
        
        worker = JobWorker(job, self._execute_scan, self.signals)
        return self._submit_job(job, worker)
    
    def _submit_job(self, job: Job, worker: JobWorker) -> str:
        """Submit job to thread pool"""
        self.jobs[job.id] = job
        self.workers[job.id] = worker
        
        # Create directories
        if job.artifact:
            job.artifact.parent.mkdir(parents=True, exist_ok=True)
        if job.log_path:
            job.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.thread_pool.start(worker)
        self.job_added.emit(job.id)
        self._save_jobs()
        
        return job.id
    
    # === Job Execution Methods ===
    
    def _execute_scan(self, job: Job, progress_callback: Callable, process_callback: Callable) -> bool:
        """Execute scan using JASMIN's command system"""
        try:
            target = job.metadata['target']
            scan_type = job.metadata['scan_type']
            
            progress_callback(10)
            
            # Set up environment
            env = os.environ.copy()
            env.update(self.env)
            
            # Find jasmin.py - try multiple locations based on common project structures
            possible_paths = [
                # Current working directory
                Path.cwd() / "jasmin.py",
                # clinterface subdirectory (common structure)
                Path.cwd() / "clinterface" / "jasmin.py", 
                # Parent of current directory
                Path.cwd().parent / "jasmin.py",
                # Parent's clinterface
                Path.cwd().parent / "clinterface" / "jasmin.py",
                # Relative to jobs_system.py location
                Path(__file__).parent / "jasmin.py",
                Path(__file__).parent.parent / "jasmin.py",
                Path(__file__).parent / "clinterface" / "jasmin.py",
                Path(__file__).parent.parent / "clinterface" / "jasmin.py",
                # Common JASMIN locations
                Path.home() / "JASMIN" / "jasmin.py",
                Path.home() / "JASMIN" / "clinterface" / "jasmin.py",
                Path.home() / "Documents" / "JASMIN" / "jasmin.py",
                Path.home() / "Documents" / "JASMIN" / "clinterface" / "jasmin.py",
            ]
            
            jasmin_path = None
            for path in possible_paths:
                if path.exists() and path.is_file():
                    jasmin_path = path
                    print(f"[*] Found jasmin.py at: {jasmin_path}")
                    break
                    
            if not jasmin_path:
                # List what we tried for debugging
                tried_paths = "\n".join(f"  - {p}" for p in possible_paths)
                job.error_message = f"Could not find jasmin.py. Tried:\n{tried_paths}\n\nMake sure jasmin.py is in your project directory."
                return False
            
            progress_callback(25)
            
            # Build command to call jasmin.py directly
            cmd = [sys.executable, str(jasmin_path), scan_type]
            
            # Add target if different from default
            if target != self.target_ip:
                cmd.extend(["-t", target])
            
            progress_callback(40)
            
            print(f"[*] Executing command: {' '.join(cmd)}")
            print(f"[*] Working directory: {self.outdir}")
            print(f"[*] Environment BOXNAME: {env.get('BOXNAME', 'NOT_SET')}")
            print(f"[*] Environment IP: {env.get('IP', 'NOT_SET')}")
            
            # Create log file for detailed output
            if job.log_path:
                job.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(job.log_path, 'w') as f:
                    f.write(f"JASMIN {scan_type} scan log\n")
                    f.write(f"Started: {datetime.now().isoformat()}\n")
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Working directory: {self.outdir}\n")
                    f.write(f"Target: {target}\n")
                    f.write(f"Found jasmin.py at: {jasmin_path}\n")
                    f.write("=" * 50 + "\n\n")
            
            progress_callback(50)
            
            # Execute with progress monitoring
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                    cwd=str(self.outdir)
                )
                
                process_callback(process)  # Allow cancellation
                
                progress_callback(75)
                
                # Wait for completion with timeout
                try:
                    stdout, stderr = process.communicate(timeout=1800)  # 30 minute timeout
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    job.error_message = "Scan timed out after 30 minutes"
                    return False
                
                progress_callback(90)
                
                # Log all output
                if job.log_path:
                    with open(job.log_path, 'a') as f:
                        f.write("STDOUT:\n")
                        f.write(stdout or "(no stdout)\n")
                        f.write("\nSTDERR:\n") 
                        f.write(stderr or "(no stderr)\n")
                        f.write(f"\nReturn code: {process.returncode}\n")
                        f.write(f"Completed: {datetime.now().isoformat()}\n")
                
                # Check results
                if process.returncode == 0:
                    progress_callback(100)
                    
                    # ADDITIONAL CHECK: Verify scan actually produced output
                    if job.artifact and not job.artifact.exists():
                        # Job "succeeded" but no scan file was created
                        # This indicates the scan didn't actually run (invalid target, etc.)
                        job.error_message = (
                            f"Scan completed with no errors but no output file was created.\n"
                            f"Expected: {job.artifact}\n"
                            f"This usually means:\n"
                            f"- Invalid target IP (0.0.0.0, localhost, etc.)\n"
                            f"- Target not reachable\n"
                            f"- JASMIN framework loaded but scan didn't execute\n\n"
                            f"Check the log above for the actual JASMIN output."
                        )
                        print(f"[!] Scan validation failed: No output file created for {scan_type}")
                        return False
                    
                    print(f"[+] Scan completed successfully: {scan_type}")
                    return True
                else:
                    error_msg = f"Scan failed with return code {process.returncode}"
                    if stderr:
                        error_msg += f"\nSTDERR: {stderr.strip()}"
                    if stdout and "error" in stdout.lower():
                        error_msg += f"\nSTDOUT: {stdout.strip()[:500]}"
                    job.error_message = error_msg
                    print(f"[!] Scan failed: {error_msg}")
                    return False
                    
            except FileNotFoundError:
                job.error_message = f"Python interpreter not found: {sys.executable}"
                return False
            except PermissionError:
                job.error_message = f"Permission denied executing: {jasmin_path}"
                return False
            except Exception as e:
                job.error_message = f"Subprocess error: {str(e)}"
                return False
                
        except Exception as e:
            job.error_message = f"Job execution error: {str(e)}"
            print(f"[!] Job execution error: {e}")
            return False
    
    # === Job Management ===
    
    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        return self.jobs.get(job_id)
    
    def get_all_jobs(self) -> List[Job]:
        """Get all jobs"""
        return list(self.jobs.values())
    
    def get_active_jobs(self) -> List[Job]:
        """Get running jobs"""
        return [job for job in self.jobs.values() 
                if job.status in [JobStatus.PENDING, JobStatus.RUNNING]]
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a job"""
        if job_id in self.workers:
            self.workers[job_id].cancel()
            return True
        return False
    
    def clear_completed_jobs(self):
        """Clear completed/failed jobs"""
        to_remove = []
        for job_id, job in self.jobs.items():
            if job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
                to_remove.append(job_id)
        
        for job_id in to_remove:
            del self.jobs[job_id]
            if job_id in self.workers:
                del self.workers[job_id]
            self.job_removed.emit(job_id)
        
        self._save_jobs()
    
    def _cleanup_old_jobs(self):
        """Clean up old jobs periodically"""
        # Remove jobs older than 24 hours if completed
        cutoff = datetime.now().timestamp() - (24 * 60 * 60)
        
        to_remove = []
        for job_id, job in self.jobs.items():
            if (job.status in [JobStatus.COMPLETED, JobStatus.FAILED] and 
                job.completed_at and job.completed_at.timestamp() < cutoff):
                to_remove.append(job_id)
        
        for job_id in to_remove:
            del self.jobs[job_id]
            if job_id in self.workers:
                del self.workers[job_id]
            self.job_removed.emit(job_id)
        
        if to_remove:
            self._save_jobs()
    
    # === Signal Handlers ===
    
    def _on_job_started(self, job_id: str):
        """Handle job started signal"""
        self.job_updated.emit(job_id)
        self._save_jobs()
    
    def _on_job_progress(self, job_id: str, progress: int):
        """Handle job progress signal"""
        self.job_updated.emit(job_id)
    
    def _on_job_completed(self, job_id: str, artifact_path: str):
        """Handle job completed signal"""
        print(f"[+] Job completed: {job_id} -> {artifact_path}")
        self.job_updated.emit(job_id)
        self._save_jobs()
    
    def _on_job_failed(self, job_id: str, error_message: str):
        """Handle job failed signal"""
        print(f"[!] Job failed: {job_id} - {error_message}")
        self.job_updated.emit(job_id)
        self._save_jobs()
    
    def _on_job_cancelled(self, job_id: str):
        """Handle job cancelled signal"""
        print(f"[*] Job cancelled: {job_id}")
        self.job_updated.emit(job_id)
        self._save_jobs()

# Convenience function
def create_jobs_manager(env: Dict[str, Any]) -> JobsManager:
    """Create configured JobsManager for JASMIN GUI"""
    return JobsManager(env)