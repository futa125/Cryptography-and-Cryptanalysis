#!/usr/bin/env python3

import pickle
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from messengerClient import MessengerClient


def generate_p384_key_pair():
    secret_key = ec.generate_private_key(ec.SECP384R1())
    public_key = secret_key.public_key()
    return secret_key, public_key


def sign_with_ecdsa(secret_key, data):
    signature = secret_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


class TestMessenger(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Par ključeva koji će CA koji će se koristiti za potpisivanje i verificiranje
        # generiranih certifikacijskih objekata. CA će potpisati svaki generirani
        # certifikacijski objekt prije nego što ga proslijedi drugim klijentima
        # koji će ga onda verificirati.
        cls.ca_sk, cls.ca_pk = generate_p384_key_pair()

    def test_import_certificate_without_error(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

    def test_send_message_without_error(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

        message = 'Hi Bob!'
        alice.send_message('Bob', message)

    def test_encrypted_message_can_be_decrypted(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

        plaintext = 'Hi Bob!'
        message = alice.send_message('Bob', plaintext)

        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

    def test_user_can_send_stream_of_messages_without_response(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

        plaintext = 'Hi Bob!'
        message = alice.send_message('Bob', plaintext)

        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

        plaintext = 'What are you doing today?'
        message = alice.send_message('Bob', plaintext)

        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

        plaintext = 'Bob?'
        message = alice.send_message('Bob', plaintext)

        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

    def test_conversation(self):
        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

        plaintext = 'Hi Bob!'
        message = alice.send_message('Bob', plaintext)

        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

        plaintext = 'Hey Alice!'
        message = bob.send_message('Alice', plaintext)

        result = alice.receive_message('Bob', message)
        self.assertEqual(plaintext, result)

        plaintext = 'Are you studying for the exam tomorrow?'
        message = bob.send_message('Alice', plaintext)

        result = alice.receive_message('Bob', message)
        self.assertEqual(plaintext, result)

        plaintext = 'Yes. How about you?'
        message = alice.send_message('Bob', plaintext)

        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

    def test_conversation_between_multiple_users(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)
        eve = MessengerClient('Eve', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()
        eve_cert = eve.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))
        eve_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(eve_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        alice.receive_certificate(eve_cert, eve_cert_sign)

        bob.receive_certificate(alice_cert, alice_cert_sign)
        bob.receive_certificate(eve_cert, eve_cert_sign)

        eve.receive_certificate(alice_cert, alice_cert_sign)
        eve.receive_certificate(bob_cert, bob_cert_sign)

        plaintext = 'Hi Alice!'
        message = bob.send_message('Alice', plaintext)
        result = alice.receive_message('Bob', message)
        self.assertEqual(plaintext, result)

        plaintext = 'Hello Bob'
        message = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

        plaintext = 'What are you doing?'
        message = bob.send_message('Alice', plaintext)
        result = alice.receive_message('Bob', message)
        self.assertEqual(plaintext, result)

        plaintext = "I'm woking on my homework"
        message = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

        plaintext = 'Alice is doing her homework. What are you doing Eve?'
        message = bob.send_message('Eve', plaintext)
        result = eve.receive_message('Bob', message)
        self.assertEqual(plaintext, result)

        plaintext = "Hi Bob! I'm studying for the exam"
        message = eve.send_message('Bob', plaintext)
        result = bob.receive_message('Eve', message)
        self.assertEqual(plaintext, result)

        plaintext = "How's the homework going Alice"
        message = eve.send_message('Alice', plaintext)
        result = alice.receive_message('Eve', message)
        self.assertEqual(plaintext, result)

        plaintext = "I just finished it"
        message = alice.send_message('Eve', plaintext)
        result = eve.receive_message('Alice', message)
        self.assertEqual(plaintext, result)

    def test_user_can_send_stream_of_messages_with_infrequent_responses(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

        for i in range(0, 2):
            for j in range(0, 4):
                plaintext = f'{j}) Hi Bob!'
                message = alice.send_message('Bob', plaintext)
                result = bob.receive_message('Alice', message)
                self.assertEqual(plaintext, result)

            plaintext = f'{i}) Hello Alice!'
            message = bob.send_message('Alice', plaintext)
            result = alice.receive_message('Bob', message)
            self.assertEqual(plaintext, result)

    def test_reject_message_from_unknown_user(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        _bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        bob.receive_certificate(alice_cert, alice_cert_sign)

        plaintext = 'Hi Alice!'
        message = bob.send_message('Alice', plaintext)
        self.assertRaises(Exception, alice.receive_message, 'Bob', message)

    def test_replay_attacks_are_detected(self):

        alice = MessengerClient('Alice', self.ca_pk)
        bob = MessengerClient('Bob', self.ca_pk)

        alice_cert = alice.generate_certificate()
        bob_cert = bob.generate_certificate()

        alice_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(alice_cert))
        bob_cert_sign = sign_with_ecdsa(self.ca_sk, pickle.dumps(bob_cert))

        alice.receive_certificate(bob_cert, bob_cert_sign)
        bob.receive_certificate(alice_cert, alice_cert_sign)

        plaintext = 'Hi Alice!'
        message = bob.send_message('Alice', plaintext)
        alice.receive_message('Bob', message)

        self.assertRaises(Exception, alice.receive_message, 'Bob', message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
