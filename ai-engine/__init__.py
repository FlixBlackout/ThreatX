# AI Engine package initialization
"""
ThreatX AI Engine Package
Main package for AI-powered cybersecurity threat detection.
"""

# Import main components for easier package-level access
try:
    from .src.enhanced_threat_detector import EnhancedThreatDetector
    from .src.dataset_manager import DatasetManager
    __all__ = ['EnhancedThreatDetector', 'DatasetManager']
except ImportError:
    # Graceful fallback if imports fail
    __all__ = []

__version__ = "1.0.0"