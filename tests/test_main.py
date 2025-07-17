import sys
import os
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.main import main

class TestMain(unittest.TestCase):

    def test_main(self):
        """
        This is a simple test to ensure that the main function runs without errors.
        """
        # We are not checking the output of the main function, just that it runs.
        main()

if __name__ == '__main__':
    unittest.main()
