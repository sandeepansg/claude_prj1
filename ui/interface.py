"""
User interface for the Chebyshev cryptosystem.
Coordinates all user interaction and display components.
"""
from .input_handler import InputHandler
from .display_handler import DisplayHandler
from .analysis_display import AnalysisDisplay


class UserInterface:
    """
    Facade class for all UI operations.
    Integrates input, display, and analysis components.
    """
    
    def __init__(self):
        """Initialize the user interface components."""
        self.input_handler = InputHandler()
        self.display_handler = DisplayHandler()
        self.analysis_display = AnalysisDisplay()
    
    def show_header(self):
        """Display the application header."""
        self.display_handler.show_header()
    
    def get_private_key_length(self):
        """Get private key length from user input."""
        return self.input_handler.get_private_key_length()
    
    def get_test_count(self):
        """Get consistent test count for all security property tests."""
        return
