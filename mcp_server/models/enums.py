"""Enumerations for severity, finding categories, and analysis phases."""

from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels, aligned with CVSS qualitative ratings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Categories of security findings, based on OWASP Mobile Top 10."""

    HARDCODED_SECRET = "hardcoded_secret"
    EXPORTED_COMPONENT = "exported_component"
    INSECURE_DATA_STORAGE = "insecure_data_storage"
    INSECURE_COMMUNICATION = "insecure_communication"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    CODE_INJECTION = "code_injection"
    IMPROPER_AUTHENTICATION = "improper_authentication"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    NATIVE_CODE_ISSUE = "native_code_issue"
    CONFIGURATION_ISSUE = "configuration_issue"
    OTHER = "other"


class AnalysisPhase(str, Enum):
    """Phases of an Android penetration test methodology."""

    RECON = "recon"
    STATIC = "static"
    NATIVE = "native"
    DYNAMIC_SETUP = "dynamic_setup"
    RUNTIME = "runtime"
    TRAFFIC = "traffic"
    STORAGE = "storage"
    REPORTING = "reporting"
