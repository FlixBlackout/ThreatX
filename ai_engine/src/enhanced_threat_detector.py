#!/usr/bin/env python3
"""
Enhanced Threat Detector Bridge Module
This module provides a bridge to the actual enhanced_threat_detector.py in ai-engine/src/
for Python import compatibility (ai_engine vs ai-engine naming).
"""

import sys
import os
import importlib.util

# Add the actual ai-engine/src directory to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
ai_engine_src_actual_path = os.path.join(os.path.dirname(os.path.dirname(current_dir)), 'ai-engine', 'src')

# Add path if it exists
if os.path.exists(ai_engine_src_actual_path) and ai_engine_src_actual_path not in sys.path:
    sys.path.insert(0, ai_engine_src_actual_path)

# Load the actual enhanced_threat_detector module
enhanced_detector_path = os.path.join(ai_engine_src_actual_path, 'enhanced_threat_detector.py')

if os.path.exists(enhanced_detector_path):
    # Load the module dynamically
    spec = importlib.util.spec_from_file_location("enhanced_threat_detector_actual", enhanced_detector_path)
    # Add comprehensive null checks to fix type error
    if spec is not None and spec.loader is not None:
        enhanced_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(enhanced_module)
        
        # Export the EnhancedThreatDetector class
        EnhancedThreatDetector = enhanced_module.EnhancedThreatDetector
        
        # Export any other classes or functions from the original module
        for attr_name in dir(enhanced_module):
            if not attr_name.startswith('_'):
                globals()[attr_name] = getattr(enhanced_module, attr_name)
    else:
        raise ImportError(f"Could not create module spec for {enhanced_detector_path}")
else:
    raise ImportError(f"Could not find enhanced_threat_detector.py at {enhanced_detector_path}")