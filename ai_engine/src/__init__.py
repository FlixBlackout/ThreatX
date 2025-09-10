# AI Engine Source Module with Python-compatible naming
"""
ThreatX AI Engine Source Module
Provides enhanced threat detection capabilities with dataset integration.
This is a compatibility module that bridges to the actual ai-engine/src directory.
"""

import sys
import os

# Add the actual ai-engine/src directory to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
ai_engine_src_actual_path = os.path.join(os.path.dirname(current_dir), 'ai-engine', 'src')

# Add path if it exists
if os.path.exists(ai_engine_src_actual_path) and ai_engine_src_actual_path not in sys.path:
    sys.path.insert(0, ai_engine_src_actual_path)

# Import main components using dynamic loading for compatibility
try:
    import importlib.util
    
    # Load enhanced_threat_detector
    enhanced_detector_path = os.path.join(ai_engine_src_actual_path, 'enhanced_threat_detector.py')
    if os.path.exists(enhanced_detector_path):
        spec = importlib.util.spec_from_file_location("enhanced_threat_detector", enhanced_detector_path)
        # Add null check for both spec and spec.loader to fix the type error
        if spec is not None and spec.loader is not None:
            enhanced_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(enhanced_module)
            
            # Make the class available at module level
            EnhancedThreatDetector = enhanced_module.EnhancedThreatDetector
            globals()['EnhancedThreatDetector'] = EnhancedThreatDetector
        else:
            EnhancedThreatDetector = None
    else:
        EnhancedThreatDetector = None
    
    __all__ = ['EnhancedThreatDetector']
    
except ImportError:
    # Fallback for direct execution
    EnhancedThreatDetector = None
    __all__ = []

__version__ = "1.0.0"