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
        return self.input_handler.get_test_count()
    
    def get_feistel_params(self):
        """Get Feistel cipher parameters from user input."""
        return self.input_handler.get_feistel_params()
    
    def get_sbox_params(self):
        """Get S-box parameters from user input."""
        return self.input_handler.get_sbox_params()
    
    def get_entropy(self):
        """Get optional entropy for key generation."""
        return self.input_handler.get_entropy()
    
    def get_sample_message(self):
        """Get a sample message to encrypt."""
        return self.input_handler.get_sample_message()
    
    def show_param_info(self, params):
        """Display derived security parameters."""
        self.display_handler.show_param_info(params)
    
    def show_system_info(self, system_info, init_time):
        """Display system initialization information."""
        self.display_handler.show_system_info(system_info, init_time)
    
    def show_feistel_params(self, cipher_info):
        """Display Feistel cipher parameters."""
        self.display_handler.show_feistel_params(cipher_info)
    
    def show_exchange_results(self, results, time_taken):
        """Display key exchange results."""
        self.display_handler.show_exchange_results(results, time_taken)
    
    def show_semigroup_test(self, results):
        """Display detailed semigroup property test results."""
        self.analysis_display.show_semigroup_test(results)
    
    def show_commutative_test(self, results):
        """Display detailed commutativity property test results."""
        self.analysis_display.show_commutative_test(results)
    
    def show_sbox_info(self, sbox, properties, time_taken):
        """Display information about the generated S-box."""
        self.analysis_display.show_sbox_info(sbox, properties, time_taken)
    
    def show_encryption_results(self, plaintext, ciphertext, decrypted, time_taken, feistel_properties):
        """Display encryption and decryption results along with Feistel properties analysis."""
        self.analysis_display.show_encryption_results(plaintext, ciphertext, decrypted, time_taken, feistel_properties)
