# AI Engine Source Module
"""
ThreatX AI Engine Source Module
Provides enhanced threat detection capabilities with dataset integration.
"""

# Import main components for easier access
try:
    from .enhanced_threat_detector import EnhancedThreatDetector
    from .dataset_manager import DatasetManager
    from .data_preprocessor import DataPreprocessor
    __all__ = ['EnhancedThreatDetector', 'DatasetManager', 'DataPreprocessor']
except ImportError:
    # Fallback for direct execution
    __all__ = []

__version__ = "1.0.0"