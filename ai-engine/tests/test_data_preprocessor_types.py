import unittest
import pandas as pd
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_preprocessor import DataPreprocessor

class TestDataPreprocessorTypes(unittest.TestCase):
    """Test cases for data preprocessor type checking"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.preprocessor = DataPreprocessor()
    
    def test_process_batch_returns_dataframe(self):
        """Test that process_batch always returns a DataFrame"""
        # Test with multiple entries
        log_batch = [
            {
                'timestamp': '2024-01-15 14:30:00',
                'ip_address': '192.168.1.100',
                'user_id': 'test_user',
                'event_type': 'login',
                'failed_login_attempts': 0,
                'total_login_attempts': 1,
                'bytes_transferred': 1024,
                'session_count': 1
            },
            {
                'timestamp': '2024-01-15 14:35:00',
                'ip_address': '192.168.1.101',
                'user_id': 'test_user2',
                'event_type': 'login',
                'failed_login_attempts': 1,
                'total_login_attempts': 2,
                'bytes_transferred': 2048,
                'session_count': 1
            }
        ]
        
        result = self.preprocessor.process_batch(log_batch)
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), 2)
    
    def test_process_batch_single_entry_returns_dataframe(self):
        """Test that process_batch with single entry returns a DataFrame"""
        # Test with single entry
        log_batch = [
            {
                'timestamp': '2024-01-15 14:30:00',
                'ip_address': '192.168.1.100',
                'user_id': 'test_user',
                'event_type': 'login',
                'failed_login_attempts': 0,
                'total_login_attempts': 1,
                'bytes_transferred': 1024,
                'session_count': 1
            }
        ]
        
        result = self.preprocessor.process_batch(log_batch)
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), 1)
    
    def test_process_batch_empty_returns_dataframe(self):
        """Test that process_batch with empty list returns a DataFrame"""
        # Test with empty list
        log_batch = []
        
        result = self.preprocessor.process_batch(log_batch)
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), 0)

if __name__ == '__main__':
    unittest.main(verbosity=2)