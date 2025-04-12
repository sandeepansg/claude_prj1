"""
Main entry point for the Chebyshev cryptosystem application.
"""
import time
import sys
import traceback
import base64
from chebyshev.security import SecurityParams
from crypto.dh import ChebyshevDH
from crypto.tester import SecurityTester
from crypto.feistel import FeistelCipher
from crypto.sbox import SBoxGenerator
from ui.interface import UserInterface


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

            # Display system info
            system_info = dh.get_system_info()
            ui.show_system_info(system_info, init_time)
        except Exception as e:
            print(f"\nError initializing cryptosystem: {str(e)}")
            return

        try:
            # Get user's key exchange preference (now returns 1-4 integer)
            key_choice = ui.get_manual_key_choice()

            # Handle manual key entry options
            alice_private = None
            bob_private = None
            alice_b64 = None
            bob_b64 = None

            if key_choice == 2 or key_choice == 4:  # Manual Alice key
                # Generate a default key for display purposes
                default_alice, _, _ = dh.generate_keypair(entropy)
                encoded_alice = dh.encode_private_key(default_alice)
                alice_private = ui.get_manual_private_key("Alice", default_alice, encoded_alice)
                # Handle base64 encoded key case
                if isinstance(alice_private, str):
                    alice_b64 = alice_private
                    alice_private = dh.decode_private_key(alice_private)

            if key_choice == 3 or key_choice == 4:  # Manual Bob key
                # Generate a default key for display purposes
                default_bob, _, _ = dh.generate_keypair(entropy + "_bob")
                encoded_bob = dh.encode_private_key(default_bob)
                bob_private = ui.get_manual_private_key("Bob", default_bob, encoded_bob)
                # Handle base64 encoded key case
                if isinstance(bob_private, str):
                    bob_b64 = bob_private
                    bob_private = dh.decode_private_key(bob_private)

            # Perform key exchange
            start_time = time.time()
            exchange = dh.simulate_exchange(entropy, entropy + "_bob", alice_private, bob_private)
            exchange_time = time.time() - start_time

            # If we used manual keys but didn't keep the base64 representation, encode them now
            if alice_private is not None and alice_b64 is None:
                alice_b64 = dh.encode_private_key(alice_private)
            if bob_private is not None and bob_b64 is None:
                bob_b64 = dh.encode_private_key(bob_private)

            # Show the results of the exchange
            exchange_success = ui.show_exchange_results(exchange, exchange_time, alice_b64, bob_b64)

            # If the exchange failed, exit early
            if not exchange_success:
                return

        except Exception as e:
            print(f"\nError during key exchange: {str(e)}")
            traceback.print_exc()
            return

        try:
            # Verify mathematical properties for security
            tester = SecurityTester(dh)
            a_priv, b_priv = exchange["alice_private"], exchange["bob_private"]

            # Test essential properties with consistent test count
            semigroup_results = tester.test_semigroup(test_count, a_priv, b_priv)
            ui.show_semigroup_test(semigroup_results)

            commutative_results = tester.test_commutative(test_count, a_priv, b_priv)
            ui.show_commutative_test(commutative_results)
        except Exception as e:
            print(f"\nError testing cryptographic properties: {str(e)}")
            traceback.print_exc()  # More detailed error info

        try:
            # Allow user to choose between shared key and manual key entry
            shared_secret = exchange["alice_shared"]
            encryption_key, key_source = ui.get_encryption_key_choice(shared_secret)

            # Generate S-box from chosen key
            start_time = time.time()
            sbox_gen = SBoxGenerator(encryption_key, box_size=sbox_size)
            sbox = sbox_gen.generate()
            sbox_time = time.time() - start_time

            # Test S-box properties with consistent test count
            sbox_properties = tester.test_sbox_properties(sbox, test_samples=test_count)
            ui.show_sbox_info(sbox, sbox_properties, sbox_time)
        except Exception as e:
            print(f"\nError during S-box generation or analysis: {str(e)}")
            traceback.print_exc()
            return

        try:
            # Demo Feistel encryption with the chosen parameters
            start_time = time.time()
            cipher = FeistelCipher(sbox, rounds=feistel_rounds, block_size=feistel_block_size)

            # Show Feistel cipher parameters
            cipher_info = cipher.get_cipher_info()
            ui.show_feistel_params(cipher_info)

            # Get sample message
            message = ui.get_sample_message()

            # Encrypt and decrypt with chosen parameters
            try:
                ciphertext = cipher.encrypt(message.encode())
                decrypted = cipher.decrypt(ciphertext)
            except Exception as e:
                print(f"\nError during encryption/decryption process: {str(e)}")
                traceback.print_exc()
                return

            # Test Feistel cipher properties with consistent test count
            feistel_properties = tester.test_feistel_properties(cipher, iterations=test_count)

            encryption_time = time.time() - start_time
            ui.show_encryption_results(message, ciphertext, decrypted, encryption_time, feistel_properties,
                                      encryption_key if key_source == 2 else None)
        except Exception as e:
            print(f"\nError during encryption/decryption demo: {str(e)}")
            traceback.print_exc()

    except KeyboardInterrupt:
        print("\nDemo aborted by user.")
    except Exception as e:
        print(f"\nUnexpected error occurred: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    run_demo()
