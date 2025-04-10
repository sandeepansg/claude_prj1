"""
Main entry point for the Chebyshev cryptosystem application.
"""
import time
import sys
import traceback
from chebyshev.security import SecurityParams
from crypto.dh import ChebyshevDH
from crypto.tester import SecurityTester
from crypto.property_verifier import PropertyVerifier
from crypto.feistel import FeistelCipher
from crypto.sbox import SBoxGenerator
from ui.interface import UserInterface
from crypto.key_store import KeyStore


def run_demo():
    """Run a complete demonstration of the secure Chebyshev DH exchange."""
    ui = UserInterface()

    try:
        # Display header
        ui.show_header()

        # Get private key length (now returns default if not provided)
        private_bits = ui.get_private_key_length()

        # Show calculated security parameters
        params = SecurityParams.get_secure_params(private_bits)
        ui.show_param_info(params)

        # Get test parameters
        test_count = ui.get_test_count()

        # Get Feistel cipher parameters (rounds and block size)
        feistel_rounds, feistel_block_size = ui.get_feistel_params()

        # Get S-box size
        sbox_size = ui.get_sbox_params()

        # Get entropy
        entropy = ui.get_entropy()

        try:
            # Initialize system with security enforcement
            start_time = time.time()
            dh = ChebyshevDH(private_bits)
            init_time = time.time() - start_time

            # Initialize UI testers with DH instance
            ui.initialize_testers(dh)

            # Display system info
            system_info = dh.get_system_info()
            ui.show_system_info(system_info, init_time)
        except Exception as e:
            print(f"\nError initializing cryptosystem: {str(e)}")
            return

        try:
            # Get key input method (generate new or load from file)
            key_method = ui.get_key_input_method()
            
            if key_method == 'generate':
                # Perform key exchange with new keys
                start_time = time.time()
                exchange = dh.simulate_exchange(entropy, entropy + "_bob")
                exchange_time = time.time() - start_time
                
                # Ask if user wants to save generated keys
                if ui.get_key_save_preference():
                    alice_name, bob_name = ui.get_key_owner_names()
                    ui.save_generated_keys(
                        exchange["alice_private"], 
                        exchange["bob_private"],
                        alice_name,
                        bob_name,
                        system_info
                    )
            else:
                # Load keys from files
                alice_file = ui.get_key_file_path("Alice")
                if not alice_file:
                    print("Generating a new key for Alice instead.")
                    alice_key = None
                else:
                    try:
                        alice_key_data = KeyStore.load_private_key(alice_file)
                        alice_key = alice_key_data['private_key']
                        ui.show_key_file_info(alice_key_data)
                    except Exception as e:
                        print(f"Error loading Alice's key: {str(e)}")
                        print("Generating a new key for Alice instead.")
                        alice_key = None
                
                bob_file = ui.get_key_file_path("Bob")
                if not bob_file:
                    print("Generating a new key for Bob instead.")
                    bob_key = None
                else:
                    try:
                        bob_key_data = KeyStore.load_private_key(bob_file)
                        bob_key = bob_key_data['private_key']
                        ui.show_key_file_info(bob_key_data)
                    except Exception as e:
                        print(f"Error loading Bob's key: {str(e)}")
                        print("Generating a new key for Bob instead.")
                        bob_key = None
                
                # Perform key exchange with loaded keys
                start_time = time.time()
                exchange = dh.simulate_exchange(
                    entropy if alice_key is None else None,
                    entropy + "_bob" if bob_key is None else None,
                    alice_private=alice_key,
                    bob_private=bob_key
                )
                exchange_time = time.time() - start_time
                
                # If one or both keys were generated, ask if user wants to save them
                if alice_key is None or bob_key is None:
                    if ui.get_key_save_preference():
                        # Only save keys that were generated
                        alice_name, bob_name = ui.get_key_owner_names()
                        
                        if alice_key is None and bob_key is None:
                            ui.save_generated_keys(
                                exchange["alice_private"], 
                                exchange["bob_private"],
                                alice_name,
                                bob_name,
                                system_info
                            )
                        elif alice_key is None:
                            KeyStore.save_private_key(
                                exchange["alice_private"],
                                alice_name,
                                {"system_parameters": system_info}
                            )
                            print(f"\nAlice's key saved successfully.")
                        elif bob_key is None:
                            KeyStore.save_private_key(
                                exchange["bob_private"],
                                bob_name,
                                {"system_parameters": system_info}
                            )
                            print(f"\nBob's key saved successfully.")
            
            ui.show_exchange_results(exchange, exchange_time)
        except Exception as e:
            print(f"\nError during key exchange: {str(e)}")
            traceback.print_exc()  # More detailed error info
            return

        try:
            # Verify mathematical properties for security
            a_priv, b_priv = exchange["alice_private"], exchange["bob_private"]

            # Test essential properties with consistent test count
            semigroup_results = ui.test_and_show_semigroup(a_priv, b_priv, test_count)
            commutative_results = ui.test_and_show_commutative(a_priv, b_priv, test_count)
        except Exception as e:
            print(f"\nError testing cryptographic properties: {str(e)}")
            traceback.print_exc()  # More detailed error info

        try:
            # Generate S-box from shared secret
            start_time = time.time()
            sbox_gen = SBoxGenerator(exchange["alice_shared"], box_size=sbox_size)
            sbox = sbox_gen.generate()
            sbox_time = time.time() - start_time

            # Test S-box properties with consistent test count
            sbox_properties = ui.test_sbox_properties(sbox, test_samples=test_count)
            ui.show_sbox_info(sbox, sbox_properties, sbox_time)
        except Exception as e:
            print(f"\nError during S-box generation or analysis: {str(e)}")
            return

        try:
            # Demo Feistel encryption
            start_time = time.time()
            cipher = FeistelCipher(sbox, rounds=feistel_rounds, block_size=feistel_block_size)
            
            # Show Feistel cipher parameters
            cipher_info = cipher.get_cipher_info()
            ui.show_feistel_params(cipher_info)

            # Get sample message
            message = ui.get_sample_message()

            # Encrypt and decrypt
            ciphertext = cipher.encrypt(message.encode())
            decrypted = cipher.decrypt(ciphertext)
            
            # Test Feistel cipher properties with consistent test count
            feistel_properties = ui.test_feistel_properties(cipher, iterations=test_count)
            
            encryption_time = time.time() - start_time
            ui.show_encryption_results(message, ciphertext, decrypted, encryption_time, feistel_properties)
        except Exception as e:
            print(f"\nError during encryption/decryption demo: {str(e)}")
            traceback.print_exc()  # More detailed error info

    except KeyboardInterrupt:
        print("\nDemo aborted by user.")
    except Exception as e:
        print(f"\nUnexpected error occurred: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    run_demo()
