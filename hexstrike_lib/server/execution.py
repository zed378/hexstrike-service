"""HexStrike execution core (dipisah dari hexstrike_server.py).

Berisi: infra proses/cache/telemetry, EnhancedCommandExecutor, dan fungsi
execute_command / execute_command_with_recovery + singleton runtime. Ini "unlock"
yang memutus circular import: modul lain meng-import execute_command dari sini.
"""

import base64  # noqa: F401
import hashlib  # noqa: F401
import json  # noqa: F401
import logging
import os  # noqa: F401
import queue  # noqa: F401
import signal  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import threading
import time  # noqa: F401
import traceback  # noqa: F401
import venv  # noqa: F401
from collections import OrderedDict  # noqa: F401
from concurrent.futures import ThreadPoolExecutor  # noqa: F401
from datetime import datetime  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any, Dict, List, Optional, Set, Tuple, Union  # noqa: F401

import psutil  # noqa: F401

from .visual import ModernVisualEngine
from .models import ErrorContext, ErrorType, RecoveryAction  # noqa: F401
from .errors import GracefulDegradation, IntelligentErrorHandler

logger = logging.getLogger(__name__)

# --- config constants ---
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

# --- infra classes ---
class ProcessPool:
    """Intelligent process pool with auto-scaling capabilities"""

    def __init__(self, min_workers=2, max_workers=20, scale_threshold=0.8):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_threshold = scale_threshold
        self.workers = []
        self.task_queue = queue.Queue()
        self.results = {}
        self.pool_lock = threading.Lock()
        self.active_tasks = {}
        self.performance_metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_task_time": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0
        }

        # Initialize minimum workers
        self._scale_up(self.min_workers)

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()

    def submit_task(self, task_id: str, func, *args, **kwargs) -> str:
        """Submit a task to the process pool"""
        task = {
            "id": task_id,
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "submitted_at": time.time(),
            "status": "queued"
        }

        with self.pool_lock:
            self.active_tasks[task_id] = task
            self.task_queue.put(task)

        logger.info(f"📋 Task submitted to pool: {task_id}")
        return task_id

    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of a submitted task"""
        with self.pool_lock:
            if task_id in self.results:
                return self.results[task_id]
            elif task_id in self.active_tasks:
                return {"status": self.active_tasks[task_id]["status"], "result": None}
            else:
                return {"status": "not_found", "result": None}

    def _worker_thread(self, worker_id: int):
        """Worker thread that processes tasks"""
        logger.info(f"🔧 Process pool worker {worker_id} started")

        while True:
            try:
                # Get task from queue with timeout
                task = self.task_queue.get(timeout=30)
                if task is None:  # Shutdown signal
                    break

                task_id = task["id"]
                start_time = time.time()

                # Update task status
                with self.pool_lock:
                    if task_id in self.active_tasks:
                        self.active_tasks[task_id]["status"] = "running"
                        self.active_tasks[task_id]["worker_id"] = worker_id
                        self.active_tasks[task_id]["started_at"] = start_time

                try:
                    # Execute task
                    result = task["func"](*task["args"], **task["kwargs"])

                    # Store result
                    execution_time = time.time() - start_time
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "completed",
                            "result": result,
                            "execution_time": execution_time,
                            "worker_id": worker_id,
                            "completed_at": time.time()
                        }

                        # Update performance metrics
                        self.performance_metrics["tasks_completed"] += 1
                        self.performance_metrics["avg_task_time"] = (
                            (self.performance_metrics["avg_task_time"] * (self.performance_metrics["tasks_completed"] - 1) + execution_time) /
                            self.performance_metrics["tasks_completed"]
                        )

                        # Remove from active tasks
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]

                    logger.info(f"✅ Task completed: {task_id} in {execution_time:.2f}s")

                except Exception as e:
                    # Handle task failure
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "failed",
                            "error": str(e),
                            "execution_time": time.time() - start_time,
                            "worker_id": worker_id,
                            "failed_at": time.time()
                        }

                        self.performance_metrics["tasks_failed"] += 1

                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]

                    logger.error(f"❌ Task failed: {task_id} - {str(e)}")

                self.task_queue.task_done()

            except queue.Empty:
                # No tasks available, continue waiting
                continue
            except Exception as e:
                logger.error(f"💥 Worker {worker_id} error: {str(e)}")

    def _monitor_performance(self):
        """Monitor pool performance and auto-scale"""
        while True:
            try:
                time.sleep(10)  # Monitor every 10 seconds

                with self.pool_lock:
                    queue_size = self.task_queue.qsize()
                    active_workers = len([w for w in self.workers if w.is_alive()])
                    active_tasks_count = len(self.active_tasks)

                # Calculate load metrics
                if active_workers > 0:
                    load_ratio = (active_tasks_count + queue_size) / active_workers
                else:
                    load_ratio = float('inf')

                # Auto-scaling logic
                if load_ratio > self.scale_threshold and active_workers < self.max_workers:
                    # Scale up
                    new_workers = min(2, self.max_workers - active_workers)
                    self._scale_up(new_workers)
                    logger.info(f"📈 Scaled up process pool: +{new_workers} workers (total: {active_workers + new_workers})")

                elif load_ratio < 0.3 and active_workers > self.min_workers:
                    # Scale down
                    workers_to_remove = min(1, active_workers - self.min_workers)
                    self._scale_down(workers_to_remove)
                    logger.info(f"📉 Scaled down process pool: -{workers_to_remove} workers (total: {active_workers - workers_to_remove})")

                # Update performance metrics
                try:
                    cpu_percent = psutil.cpu_percent()
                    memory_info = psutil.virtual_memory()

                    with self.pool_lock:
                        self.performance_metrics["cpu_usage"] = cpu_percent
                        self.performance_metrics["memory_usage"] = memory_info.percent

                except Exception:
                    pass  # Ignore psutil errors

            except Exception as e:
                logger.error(f"💥 Pool monitor error: {str(e)}")

    def _scale_up(self, count: int):
        """Add workers to the pool"""
        with self.pool_lock:
            for i in range(count):
                worker_id = len(self.workers)
                worker = threading.Thread(target=self._worker_thread, args=(worker_id,), daemon=True)
                worker.start()
                self.workers.append(worker)

    def _scale_down(self, count: int):
        """Remove workers from the pool"""
        with self.pool_lock:
            for _ in range(count):
                if len(self.workers) > self.min_workers:
                    # Signal worker to shutdown by putting None in queue
                    self.task_queue.put(None)
                    # Remove from workers list (worker will exit naturally)
                    if self.workers:
                        self.workers.pop()

    def get_pool_stats(self) -> Dict[str, Any]:
        """Get current pool statistics"""
        with self.pool_lock:
            active_workers = len([w for w in self.workers if w.is_alive()])
            return {
                "active_workers": active_workers,
                "queue_size": self.task_queue.qsize(),
                "active_tasks": len(self.active_tasks),
                "performance_metrics": self.performance_metrics.copy(),
                "min_workers": self.min_workers,
                "max_workers": self.max_workers
            }

class AdvancedCache:
    """Advanced caching system with intelligent TTL and LRU eviction"""

    def __init__(self, max_size=1000, default_ttl=3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.ttl_times = {}
        self.cache_lock = threading.RLock()
        self.hit_count = 0
        self.miss_count = 0

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()

    def get(self, key: str) -> Any:
        """Get value from cache"""
        with self.cache_lock:
            current_time = time.time()

            # Check if key exists and is not expired
            if key in self.cache and (key not in self.ttl_times or self.ttl_times[key] > current_time):
                # Update access time for LRU
                self.access_times[key] = current_time
                self.hit_count += 1
                return self.cache[key]

            # Cache miss or expired
            if key in self.cache:
                # Remove expired entry
                self._remove_key(key)

            self.miss_count += 1
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Set value in cache with optional TTL"""
        with self.cache_lock:
            current_time = time.time()

            # Use default TTL if not specified
            if ttl is None:
                ttl = self.default_ttl

            # Check if we need to evict entries
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_lru()

            # Set the value
            self.cache[key] = value
            self.access_times[key] = current_time
            self.ttl_times[key] = current_time + ttl

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self.cache_lock:
            if key in self.cache:
                self._remove_key(key)
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries"""
        with self.cache_lock:
            self.cache.clear()
            self.access_times.clear()
            self.ttl_times.clear()

    def _remove_key(self, key: str) -> None:
        """Remove key and associated metadata"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.ttl_times.pop(key, None)

    def _evict_lru(self) -> None:
        """Evict least recently used entry"""
        if not self.access_times:
            return

        # Find least recently used key
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self._remove_key(lru_key)
        logger.debug(f"🗑️ Evicted LRU cache entry: {lru_key}")

    def _cleanup_expired(self) -> None:
        """Cleanup expired entries periodically"""
        while True:
            try:
                time.sleep(60)  # Cleanup every minute
                current_time = time.time()
                expired_keys = []

                with self.cache_lock:
                    for key, expiry_time in self.ttl_times.items():
                        if expiry_time <= current_time:
                            expired_keys.append(key)

                    for key in expired_keys:
                        self._remove_key(key)

                if expired_keys:
                    logger.debug(f"🧹 Cleaned up {len(expired_keys)} expired cache entries")

            except Exception as e:
                logger.error(f"💥 Cache cleanup error: {str(e)}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.cache_lock:
            total_requests = self.hit_count + self.miss_count
            hit_rate = (self.hit_count / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_count": self.hit_count,
                "miss_count": self.miss_count,
                "hit_rate": hit_rate,
                "utilization": (len(self.cache) / self.max_size * 100)
            }

class EnhancedProcessManager:
    """Advanced process management with intelligent resource allocation"""

    def __init__(self):
        self.process_pool = ProcessPool(min_workers=4, max_workers=32)
        self.cache = AdvancedCache(max_size=2000, default_ttl=1800)  # 30 minutes default TTL
        self.resource_monitor = ResourceMonitor()
        self.process_registry = {}
        self.registry_lock = threading.RLock()
        self.performance_dashboard = PerformanceDashboard()

        # Process termination and recovery
        self.termination_handlers = {}
        self.recovery_strategies = {}

        # Auto-scaling configuration
        self.auto_scaling_enabled = True
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0,
            "disk_high": 95.0,
            "load_high": 0.8
        }

        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()

    def execute_command_async(self, command: str, context: Dict[str, Any] = None) -> str:
        """Execute command asynchronously using process pool"""
        task_id = f"cmd_{int(time.time() * 1000)}_{hash(command) % 10000}"

        # Check cache first
        cache_key = f"cmd_result_{hash(command)}"
        cached_result = self.cache.get(cache_key)
        if cached_result and context and context.get("use_cache", True):
            logger.info(f"📋 Using cached result for command: {command[:50]}...")
            return cached_result

        # Submit to process pool
        self.process_pool.submit_task(
            task_id,
            self._execute_command_internal,
            command,
            context or {}
        )

        return task_id

    def _execute_command_internal(self, command: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Internal command execution with enhanced monitoring"""
        start_time = time.time()

        try:
            # Resource-aware execution
            resource_usage = self.resource_monitor.get_current_usage()

            # Adjust command based on resource availability
            if resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"]:
                # Add nice priority for CPU-intensive commands
                if not command.startswith("nice"):
                    command = f"nice -n 10 {command}"

            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )

            # Register process
            with self.registry_lock:
                self.process_registry[process.pid] = {
                    "command": command,
                    "process": process,
                    "start_time": start_time,
                    "context": context,
                    "status": "running"
                }

            # Monitor process execution
            stdout, stderr = process.communicate()
            execution_time = time.time() - start_time

            result = {
                "success": process.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": process.returncode,
                "execution_time": execution_time,
                "pid": process.pid,
                "resource_usage": self.resource_monitor.get_process_usage(process.pid)
            }

            # Cache successful results
            if result["success"] and context.get("cache_result", True):
                cache_key = f"cmd_result_{hash(command)}"
                cache_ttl = context.get("cache_ttl", 1800)  # 30 minutes default
                self.cache.set(cache_key, result, cache_ttl)

            # Update performance metrics
            self.performance_dashboard.record_execution(command, result)

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            error_result = {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": execution_time,
                "error": str(e)
            }

            self.performance_dashboard.record_execution(command, error_result)
            return error_result

        finally:
            # Cleanup process registry
            with self.registry_lock:
                if hasattr(process, 'pid') and process.pid in self.process_registry:
                    del self.process_registry[process.pid]

    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of async task"""
        return self.process_pool.get_task_result(task_id)

    def terminate_process_gracefully(self, pid: int, timeout: int = 30) -> bool:
        """Terminate process with graceful degradation"""
        try:
            with self.registry_lock:
                if pid not in self.process_registry:
                    return False

                process_info = self.process_registry[pid]
                process = process_info["process"]

                # Try graceful termination first
                process.terminate()

                # Wait for graceful termination
                try:
                    process.wait(timeout=timeout)
                    process_info["status"] = "terminated_gracefully"
                    logger.info(f"✅ Process {pid} terminated gracefully")
                    return True
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    process.kill()
                    process_info["status"] = "force_killed"
                    logger.warning(f"⚠️ Process {pid} force killed after timeout")
                    return True

        except Exception as e:
            logger.error(f"💥 Error terminating process {pid}: {str(e)}")
            return False

    def _monitor_system(self):
        """Monitor system resources and auto-scale"""
        while True:
            try:
                time.sleep(15)  # Monitor every 15 seconds

                # Get current resource usage
                resource_usage = self.resource_monitor.get_current_usage()

                # Auto-scaling based on resource usage
                if self.auto_scaling_enabled:
                    self._auto_scale_based_on_resources(resource_usage)

                # Update performance dashboard
                self.performance_dashboard.update_system_metrics(resource_usage)

            except Exception as e:
                logger.error(f"💥 System monitoring error: {str(e)}")

    def _auto_scale_based_on_resources(self, resource_usage: Dict[str, float]):
        """Auto-scale process pool based on resource usage"""
        pool_stats = self.process_pool.get_pool_stats()
        current_workers = pool_stats["active_workers"]

        # Scale down if resources are constrained
        if (resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"] or
            resource_usage["memory_percent"] > self.resource_thresholds["memory_high"]):

            if current_workers > self.process_pool.min_workers:
                self.process_pool._scale_down(1)
                logger.info(f"📉 Auto-scaled down due to high resource usage: CPU {resource_usage['cpu_percent']:.1f}%, Memory {resource_usage['memory_percent']:.1f}%")

        # Scale up if resources are available and there's demand
        elif (resource_usage["cpu_percent"] < 60 and
              resource_usage["memory_percent"] < 70 and
              pool_stats["queue_size"] > 2):

            if current_workers < self.process_pool.max_workers:
                self.process_pool._scale_up(1)
                logger.info(f"📈 Auto-scaled up due to available resources and demand")

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive system and process statistics"""
        return {
            "process_pool": self.process_pool.get_pool_stats(),
            "cache": self.cache.get_stats(),
            "resource_usage": self.resource_monitor.get_current_usage(),
            "active_processes": len(self.process_registry),
            "performance_dashboard": self.performance_dashboard.get_summary(),
            "auto_scaling_enabled": self.auto_scaling_enabled,
            "resource_thresholds": self.resource_thresholds
        }

class ResourceMonitor:
    """Advanced resource monitoring with historical tracking"""

    def __init__(self, history_size=100):
        self.history_size = history_size
        self.usage_history = []
        self.history_lock = threading.Lock()

    def get_current_usage(self) -> Dict[str, float]:
        """Get current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            usage = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }

            # Add to history
            with self.history_lock:
                self.usage_history.append(usage)
                if len(self.usage_history) > self.history_size:
                    self.usage_history.pop(0)

            return usage

        except Exception as e:
            logger.error(f"💥 Error getting resource usage: {str(e)}")
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "memory_available_gb": 0,
                "disk_percent": 0,
                "disk_free_gb": 0,
                "network_bytes_sent": 0,
                "network_bytes_recv": 0,
                "timestamp": time.time()
            }

    def get_process_usage(self, pid: int) -> Dict[str, Any]:
        """Get resource usage for specific process"""
        try:
            process = psutil.Process(pid)
            return {
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent(),
                "memory_rss_mb": process.memory_info().rss / (1024**2),
                "num_threads": process.num_threads(),
                "status": process.status()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}

    def get_usage_trends(self) -> Dict[str, Any]:
        """Get resource usage trends"""
        with self.history_lock:
            if len(self.usage_history) < 2:
                return {}

            recent = self.usage_history[-10:]  # Last 10 measurements

            cpu_trend = sum(u["cpu_percent"] for u in recent) / len(recent)
            memory_trend = sum(u["memory_percent"] for u in recent) / len(recent)

            return {
                "cpu_avg_10": cpu_trend,
                "memory_avg_10": memory_trend,
                "measurements": len(self.usage_history),
                "trend_period_minutes": len(recent) * 15 / 60  # 15 second intervals
            }

class PerformanceDashboard:
    """Real-time performance monitoring dashboard"""

    def __init__(self):
        self.execution_history = []
        self.system_metrics = []
        self.dashboard_lock = threading.Lock()
        self.max_history = 1000

    def record_execution(self, command: str, result: Dict[str, Any]):
        """Record command execution for performance tracking"""
        with self.dashboard_lock:
            execution_record = {
                "command": command[:100],  # Truncate long commands
                "success": result.get("success", False),
                "execution_time": result.get("execution_time", 0),
                "return_code": result.get("return_code", -1),
                "timestamp": time.time()
            }

            self.execution_history.append(execution_record)
            if len(self.execution_history) > self.max_history:
                self.execution_history.pop(0)

    def update_system_metrics(self, metrics: Dict[str, Any]):
        """Update system metrics for dashboard"""
        with self.dashboard_lock:
            self.system_metrics.append(metrics)
            if len(self.system_metrics) > self.max_history:
                self.system_metrics.pop(0)

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        with self.dashboard_lock:
            if not self.execution_history:
                return {"executions": 0}

            recent_executions = self.execution_history[-100:]  # Last 100 executions

            total_executions = len(recent_executions)
            successful_executions = sum(1 for e in recent_executions if e["success"])
            avg_execution_time = sum(e["execution_time"] for e in recent_executions) / total_executions

            return {
                "total_executions": len(self.execution_history),
                "recent_executions": total_executions,
                "success_rate": (successful_executions / total_executions * 100) if total_executions > 0 else 0,
                "avg_execution_time": avg_execution_time,
                "system_metrics_count": len(self.system_metrics)
            }


active_processes = {}  # pid -> process info
process_lock = threading.Lock()

class ProcessManager:
    """Enhanced process manager for command termination and monitoring"""

    @staticmethod
    def register_process(pid, command, process_obj):
        """Register a new active process"""
        with process_lock:
            active_processes[pid] = {
                "pid": pid,
                "command": command,
                "process": process_obj,
                "start_time": time.time(),
                "status": "running",
                "progress": 0.0,
                "last_output": "",
                "bytes_processed": 0
            }
            logger.info(f"🆔 REGISTERED: Process {pid} - {command[:50]}...")

    @staticmethod
    def update_process_progress(pid, progress, last_output="", bytes_processed=0):
        """Update process progress and stats"""
        with process_lock:
            if pid in active_processes:
                active_processes[pid]["progress"] = progress
                active_processes[pid]["last_output"] = last_output
                active_processes[pid]["bytes_processed"] = bytes_processed
                runtime = time.time() - active_processes[pid]["start_time"]

                # Calculate ETA if progress > 0
                eta = 0
                if progress > 0:
                    eta = (runtime / progress) * (1.0 - progress)

                active_processes[pid]["runtime"] = runtime
                active_processes[pid]["eta"] = eta

    @staticmethod
    def terminate_process(pid):
        """Terminate a specific process"""
        with process_lock:
            if pid in active_processes:
                process_info = active_processes[pid]
                try:
                    process_obj = process_info["process"]
                    if process_obj and process_obj.poll() is None:
                        process_obj.terminate()
                        time.sleep(1)  # Give it a chance to terminate gracefully
                        if process_obj.poll() is None:
                            process_obj.kill()  # Force kill if still running

                        active_processes[pid]["status"] = "terminated"
                        logger.warning(f"🛑 TERMINATED: Process {pid} - {process_info['command'][:50]}...")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error terminating process {pid}: {str(e)}")
                    return False
            return False

    @staticmethod
    def cleanup_process(pid):
        """Remove process from active registry"""
        with process_lock:
            if pid in active_processes:
                process_info = active_processes.pop(pid)
                logger.info(f"🧹 CLEANUP: Process {pid} removed from registry")
                return process_info
            return None

    @staticmethod
    def get_process_status(pid):
        """Get status of a specific process"""
        with process_lock:
            return active_processes.get(pid, None)

    @staticmethod
    def list_active_processes():
        """List all active processes"""
        with process_lock:
            return dict(active_processes)

    @staticmethod
    def pause_process(pid):
        """Pause a specific process (SIGSTOP)"""
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGSTOP)
                        active_processes[pid]["status"] = "paused"
                        logger.info(f"⏸️  PAUSED: Process {pid}")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error pausing process {pid}: {str(e)}")
            return False

    @staticmethod
    def resume_process(pid):
        """Resume a paused process (SIGCONT)"""
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGCONT)
                        active_processes[pid]["status"] = "running"
                        logger.info(f"▶️  RESUMED: Process {pid}")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error resuming process {pid}: {str(e)}")
            return False

# Enhanced color codes and visual elements for modern terminal output
# All color references consolidated to ModernVisualEngine.COLORS for consistency
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Text effects
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'

class PythonEnvironmentManager:
    """Manage Python virtual environments and dependencies"""

    def __init__(self, base_dir: str = "/tmp/hexstrike_envs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def create_venv(self, env_name: str) -> Path:
        """Create a new virtual environment"""
        env_path = self.base_dir / env_name
        if not env_path.exists():
            logger.info(f"🐍 Creating virtual environment: {env_name}")
            venv.create(env_path, with_pip=True)
        return env_path

    def install_package(self, env_name: str, package: str) -> bool:
        """Install a package in the specified environment"""
        env_path = self.create_venv(env_name)
        pip_path = env_path / "bin" / "pip"

        try:
            result = subprocess.run([str(pip_path), "install", package],
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                logger.info(f"📦 Installed package {package} in {env_name}")
                return True
            else:
                logger.error(f"❌ Failed to install {package}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"💥 Error installing package {package}: {e}")
            return False

    def get_python_path(self, env_name: str) -> str:
        """Get Python executable path for environment"""
        env_path = self.create_venv(env_name)
        return str(env_path / "bin" / "python")

# Global environment manager

class HexStrikeCache:
    """Advanced caching system for command results"""

    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.ttl

    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        key = self._generate_key(command, params)

        if key in self.cache:
            timestamp, data = self.cache[key]
            if not self._is_expired(timestamp):
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                logger.info(f"💾 Cache HIT for command: {command}")
                return data
            else:
                # Remove expired entry
                del self.cache[key]

        self.stats["misses"] += 1
        logger.info(f"🔍 Cache MISS for command: {command}")
        return None

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
        key = self._generate_key(command, params)

        # Remove oldest entries if cache is full
        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.stats["evictions"] += 1

        self.cache[key] = (time.time(), result)
        logger.info(f"💾 Cached result for command: {command}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"]
        }

# Global cache instance

class TelemetryCollector:
    """Collect and manage system telemetry"""

    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }

    def record_execution(self, success: bool, execution_time: float):
        """Record command execution statistics"""
        self.stats["commands_executed"] += 1
        if success:
            self.stats["successful_commands"] += 1
        else:
            self.stats["failed_commands"] += 1
        self.stats["total_execution_time"] += execution_time

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        uptime = time.time() - self.stats["start_time"]
        success_rate = (self.stats["successful_commands"] / self.stats["commands_executed"] * 100) if self.stats["commands_executed"] > 0 else 0
        avg_execution_time = (self.stats["total_execution_time"] / self.stats["commands_executed"]) if self.stats["commands_executed"] > 0 else 0

        return {
            "uptime_seconds": uptime,
            "commands_executed": self.stats["commands_executed"],
            "success_rate": f"{success_rate:.1f}%",
            "average_execution_time": f"{avg_execution_time:.2f}s",
            "system_metrics": self.get_system_metrics()
        }

# Global telemetry collector

class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None

    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    # Real-time output display
                    logger.info(f"📤 STDOUT: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")

    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    # Real-time error output display
                    logger.warning(f"📥 STDERR: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
        if duration > 2:  # Show progress for commands taking more than 2 seconds
            progress_chars = ModernVisualEngine.PROGRESS_STYLES['dots']
            start = time.time()
            i = 0
            while self.process and self.process.poll() is None:
                elapsed = time.time() - start
                char = progress_chars[i % len(progress_chars)]

                # Calculate progress percentage (rough estimate)
                progress_percent = min((elapsed / self.timeout) * 100, 99.9)
                progress_fraction = progress_percent / 100

                # Calculate ETA
                eta = 0
                if progress_percent > 5:  # Only show ETA after 5% progress
                    eta = ((elapsed / progress_percent) * 100) - elapsed

                # Calculate speed
                bytes_processed = len(self.stdout_data) + len(self.stderr_data)
                speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"

                # Update process manager with progress
                ProcessManager.update_process_progress(
                    self.process.pid,
                    progress_fraction,
                    f"Running for {elapsed:.1f}s",
                    bytes_processed
                )

                # Create beautiful progress bar using ModernVisualEngine
                progress_bar = ModernVisualEngine.render_progress_bar(
                    progress_fraction,
                    width=30,
                    style='cyber',
                    label=f"⚡ PROGRESS {char}",
                    eta=eta,
                    speed=speed
                )

                logger.info(f"{progress_bar} | {elapsed:.1f}s | PID: {self.process.pid}")
                time.sleep(0.8)
                i += 1
                if elapsed > self.timeout:
                    break

    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
        self.start_time = time.time()

        logger.info(f"🚀 EXECUTING: {self.command}")
        logger.info(f"⏱️  TIMEOUT: {self.timeout}s | PID: Starting...")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            pid = self.process.pid
            logger.info(f"🆔 PROCESS: PID {pid} started")

            # Register process with ProcessManager (v5.0 enhancement)
            ProcessManager.register_process(pid, self.command, self.process)

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Start progress tracking in a separate thread
            progress_thread = threading.Thread(target=self._show_progress, args=(self.timeout,))
            progress_thread.daemon = True
            progress_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.end_time = time.time()

                # Process completed, join the threads
                self.stdout_thread.join(timeout=1)
                self.stderr_thread.join(timeout=1)

                execution_time = self.end_time - self.start_time

                # Cleanup process from registry (v5.0 enhancement)
                ProcessManager.cleanup_process(pid)

                if self.return_code == 0:
                    logger.info(f"✅ SUCCESS: Command completed | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(True, execution_time)
                else:
                    logger.warning(f"⚠️  WARNING: Command completed with errors | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(False, execution_time)

            except subprocess.TimeoutExpired:
                self.end_time = time.time()
                execution_time = self.end_time - self.start_time

                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"⏰ TIMEOUT: Command timed out after {self.timeout}s | Terminating PID {self.process.pid}")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()

                self.return_code = -1
                telemetry.record_execution(False, execution_time)

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            # Log enhanced final results with summary using ModernVisualEngine
            output_size = len(self.stdout_data) + len(self.stderr_data)
            execution_time = self.end_time - self.start_time if self.end_time else 0

            # Create status summary
            status_icon = "✅" if success else "❌"
            status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']
            timeout_status = f" {ModernVisualEngine.COLORS['WARNING']}[TIMEOUT]{ModernVisualEngine.COLORS['RESET']}" if self.timed_out else ""

            # Create beautiful results summary
            results_summary = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📊 FINAL RESULTS {status_icon}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Command:{ModernVisualEngine.COLORS['RESET']} {self.command[:55]}{'...' if len(self.command) > 55 else ''}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f}s{timeout_status}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}📊 Output Size:{ModernVisualEngine.COLORS['RESET']} {output_size} bytes
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🔢 Exit Code:{ModernVisualEngine.COLORS['RESET']} {self.return_code}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📈 Status:{ModernVisualEngine.COLORS['RESET']} {'SUCCESS' if success else 'FAILED'} | Cached: Yes
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

            # Log the beautiful summary
            for line in results_summary.strip().split('\n'):
                if line.strip():
                    logger.info(line)

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "execution_time": self.end_time - self.start_time if self.end_time else 0,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0

            logger.error(f"💥 ERROR: Command execution failed: {str(e)}")
            logger.error(f"🔍 TRACEBACK: {traceback.format_exc()}")
            telemetry.record_execution(False, execution_time)

            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }

# ============================================================================
# DUPLICATE CLASSES REMOVED - Using the first definitions above
# ============================================================================

# ============================================================================
# AI-POWERED EXPLOIT GENERATION SYSTEM (v6.0 ENHANCEMENT)
# ============================================================================
#
# This section contains advanced AI-powered exploit generation capabilities
# for automated vulnerability exploitation and proof-of-concept development.
#
# Features:
# - Automated exploit template generation from CVE data
# - Multi-architecture support (x86, x64, ARM)
# - Evasion technique integration
# - Custom payload generation
# - Exploit effectiveness scoring
#
# ============================================================================




# --- runtime singletons (dependency order) ---
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()
enhanced_process_manager = EnhancedProcessManager()
env_manager = PythonEnvironmentManager()
cache = HexStrikeCache()
telemetry = TelemetryCollector()

# --- execute_command core ---
def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute a shell command with enhanced features

    Args:
        command: The command to execute
        use_cache: Whether to use caching for this command

    Returns:
        A dictionary containing the stdout, stderr, return code, and metadata
    """

    # Check cache first
    if use_cache:
        cached_result = cache.get(command, {})
        if cached_result:
            return cached_result

    # Execute command
    executor = EnhancedCommandExecutor(command)
    result = executor.execute()

    # Cache successful results
    if use_cache and result.get("success", False):
        cache.set(command, {}, result)

    return result

def execute_command_with_recovery(tool_name: str, command: str, parameters: Dict[str, Any] = None,
                                 use_cache: bool = True, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Execute a command with intelligent error handling and recovery

    Args:
        tool_name: Name of the tool being executed
        command: The command to execute
        parameters: Tool parameters for context
        use_cache: Whether to use caching
        max_attempts: Maximum number of recovery attempts

    Returns:
        A dictionary containing execution results with recovery information
    """
    if parameters is None:
        parameters = {}

    attempt_count = 0
    last_error = None
    recovery_history = []

    while attempt_count < max_attempts:
        attempt_count += 1

        try:
            # Execute the command
            result = execute_command(command, use_cache)

            # Check if execution was successful
            if result.get("success", False):
                # Add recovery information to successful result
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history
                }
                return result

            # Command failed, determine if we should attempt recovery
            error_message = result.get("stderr", "Unknown error")
            exception = Exception(error_message)

            # Create context for error handler
            context = {
                "target": parameters.get("target", "unknown"),
                "parameters": parameters,
                "attempt_count": attempt_count,
                "command": command
            }

            # Get recovery strategy from error handler
            recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)
            recovery_history.append({
                "attempt": attempt_count,
                "error": error_message,
                "recovery_action": recovery_strategy.action.value,
                "timestamp": datetime.now().isoformat()
            })

            # Apply recovery strategy
            if recovery_strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
                delay = recovery_strategy.parameters.get("initial_delay", 5)
                backoff = recovery_strategy.parameters.get("max_delay", 60)
                actual_delay = min(delay * (recovery_strategy.backoff_multiplier ** (attempt_count - 1)), backoff)

                retry_info = f'Retrying in {actual_delay}s (attempt {attempt_count}/{max_attempts})'
                logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', retry_info)}")
                time.sleep(actual_delay)
                continue

            elif recovery_strategy.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
                # Adjust parameters to reduce scope
                adjusted_params = error_handler.auto_adjust_parameters(
                    tool_name,
                    error_handler.classify_error(error_message, exception),
                    parameters
                )

                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with reduced scope")
                continue

            elif recovery_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                # Get alternative tool
                alternative_tool = error_handler.get_alternative_tool(tool_name, recovery_strategy.parameters)

                if alternative_tool:
                    switch_info = f'Switching to alternative: {alternative_tool}'
                    logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', switch_info)}")
                    # This would require the calling function to handle tool switching
                    result["alternative_tool_suggested"] = alternative_tool
                    result["recovery_info"] = {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "tool_switch_suggested"
                    }
                    return result
                else:
                    logger.warning(f"⚠️  No alternative tool found for {tool_name}")

            elif recovery_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
                # Adjust parameters based on error type
                error_type = error_handler.classify_error(error_message, exception)
                adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, parameters)

                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with adjusted parameters")
                continue

            elif recovery_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
                # Create error context for escalation
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=error_handler.classify_error(error_message, exception),
                    error_message=error_message,
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace="",
                    system_resources=error_handler._get_system_resources()
                )

                escalation_data = error_handler.escalate_to_human(
                    error_context,
                    recovery_strategy.parameters.get("urgency", "medium")
                )

                result["human_escalation"] = escalation_data
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "human_escalation"
                }
                return result

            elif recovery_strategy.action == RecoveryAction.GRACEFUL_DEGRADATION:
                # Apply graceful degradation
                operation = _determine_operation_type(tool_name)
                degraded_result = degradation_manager.handle_partial_failure(
                    operation,
                    result,
                    [tool_name]
                )

                degraded_result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "graceful_degradation"
                }
                return degraded_result

            elif recovery_strategy.action == RecoveryAction.ABORT_OPERATION:
                logger.error(f"🛑 Aborting {tool_name} operation after {attempt_count} attempts")
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "operation_aborted"
                }
                return result

            last_error = exception

        except Exception as e:
            last_error = e
            logger.error(f"💥 Unexpected error in recovery attempt {attempt_count}: {str(e)}")

            # If this is the last attempt, escalate to human
            if attempt_count >= max_attempts:
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=ErrorType.UNKNOWN,
                    error_message=str(e),
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace=traceback.format_exc(),
                    system_resources=error_handler._get_system_resources()
                )

                escalation_data = error_handler.escalate_to_human(error_context, "high")

                return {
                    "success": False,
                    "error": str(e),
                    "human_escalation": escalation_data,
                    "recovery_info": {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "human_escalation_after_failure"
                    }
                }

    # All attempts exhausted
    logger.error(f"🚫 All recovery attempts exhausted for {tool_name}")
    return {
        "success": False,
        "error": f"All recovery attempts exhausted: {str(last_error)}",
        "recovery_info": {
            "attempts_made": attempt_count,
            "recovery_applied": True,
            "recovery_history": recovery_history,
            "final_action": "all_attempts_exhausted"
        }
    }

def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    # This is a simplified implementation - in practice, you'd need tool-specific logic
    # For now, we'll just append new parameters
    additional_args = []

    for key, value in new_params.items():
        if key == "timeout" and tool_name in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and tool_name in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and tool_name in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and tool_name == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and tool_name == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and tool_name == "nuclei":
            additional_args.append(f"-rl {value}")

    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"

    return original_command

def _determine_operation_type(tool_name: str) -> str:
    """Determine operation type based on tool name"""
    operation_mapping = {
        "nmap": "network_discovery",
        "rustscan": "network_discovery",
        "masscan": "network_discovery",
        "gobuster": "web_discovery",
        "feroxbuster": "web_discovery",
        "dirsearch": "web_discovery",
        "ffuf": "web_discovery",
        "nuclei": "vulnerability_scanning",
        "jaeles": "vulnerability_scanning",
        "nikto": "vulnerability_scanning",
        "subfinder": "subdomain_enumeration",
        "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration",
        "arjun": "parameter_discovery",
        "paramspider": "parameter_discovery",
        "x8": "parameter_discovery"
    }

    return operation_mapping.get(tool_name, "unknown_operation")

# File Operations Manager
