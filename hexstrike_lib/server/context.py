"""Registry singleton (non-execution). Blueprint meng-import dari sini via deps.

Singleton yang direferensikan secara internal oleh method modul lain (ctf_manager,
ctf_tools, ctf_automator, ctf_coordinator, parameter_optimizer) dimiliki oleh
modulnya sendiri dan di-import di sini agar instance-nya TUNGGAL (bukan duplikat).
"""

from .decision_engine import IntelligentDecisionEngine, parameter_optimizer  # noqa: F401
from .cve_intel import CVEIntelligenceManager
from .exploits import AIExploitGenerator
from .correlator import VulnerabilityCorrelator
from .file_ops import FileOperationsManager
from .http_framework import HTTPTestingFramework
from .browser_agent import BrowserAgent
from .payload_generator import AIPayloadGenerator
from .ctf import ctf_manager, ctf_tools, ctf_automator, ctf_coordinator  # noqa: F401
from .bugbounty import BugBountyWorkflowManager, FileUploadTestingFramework
from .analyzers import (
    TechnologyDetector, RateLimitDetector, FailureRecoverySystem, PerformanceMonitor,
)

decision_engine = IntelligentDecisionEngine()
cve_intelligence = CVEIntelligenceManager()
exploit_generator = AIExploitGenerator()
vulnerability_correlator = VulnerabilityCorrelator()
file_manager = FileOperationsManager()
http_framework = HTTPTestingFramework()
browser_agent = BrowserAgent()
ai_payload_generator = AIPayloadGenerator()
bugbounty_manager = BugBountyWorkflowManager()
fileupload_framework = FileUploadTestingFramework()
tech_detector = TechnologyDetector()
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()
performance_monitor = PerformanceMonitor()
