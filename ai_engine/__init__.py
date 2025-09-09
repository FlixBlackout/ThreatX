# AI Engine package initialization with underscore naming for Python import compatibility
"""
ThreatX AI Engine Package
Main package for AI-powered cybersecurity threat detection.
This module provides Python-compatible naming (ai_engine) for the ai-engine directory.
"""

import sys
import os

# Add the actual ai-engine directory to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
ai_engine_actual_path = os.path.join(os.path.dirname(current_dir), 'ai-engine')
ai_engine_src_path = os.path.join(ai_engine_actual_path, 'src')

# Add paths if they exist
for path in [ai_engine_src_path, ai_engine_actual_path]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

# Import main components for easier package-level access
try:
    # Import from the actual ai-engine/src directory
    import sys
    import importlib.util
    
    # Load enhanced_threat_detector
    enhanced_detector_path = os.path.join(ai_engine_src_path, 'enhanced_threat_detector.py')
    if os.path.exists(enhanced_detector_path):
        spec = importlib.util.spec_from_file_location("enhanced_threat_detector", enhanced_detector_path)
        enhanced_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(enhanced_module)
        EnhancedThreatDetector = enhanced_module.EnhancedThreatDetector
    else:
        EnhancedThreatDetector = None
    
    # Load dataset_manager  
    dataset_manager_path = os.path.join(ai_engine_src_path, 'dataset_manager.py')
    if os.path.exists(dataset_manager_path):
        spec = importlib.util.spec_from_file_location("dataset_manager", dataset_manager_path)
        dataset_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dataset_module)
        DatasetManager = dataset_module.DatasetManager
    else:
        DatasetManager = None
    
    __all__ = ['EnhancedThreatDetector', 'DatasetManager']
    
except ImportError:
    # Graceful fallback if imports fail
    EnhancedThreatDetector = None
    DatasetManager = None
    __all__ = []

__version__ = "1.0.0"