#!/usr/bin/env python3

import os
import unittest

from messengerClient import MessengerClient


class TestMessenger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key1 = os.urandom(32)
        cls.key2 = os.urandom(32)
        cls.key3 = os.urandom(32)
        cls.key4 = os.urandom(32)
        cls.key5 = os.urandom(32)
        cls.key6 = os.urandom(32)

    def test_send_message_without_error(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        alice.add_connection('Bob', self.key1, self.key2)
        bob.add_connection('Alice', self.key2, self.key1)

        alice.send_message('Bob', 'Hi Bob!')

    def test_encrypted_message_can_be_decrypted(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        alice.add_connection('Bob', self.key1, self.key2)
        bob.add_connection('Alice', self.key2, self.key1)

        plaintext = 'Hi Bob!'
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)

        self.assertEqual(plaintext, result)

    def test_conversation_between_multiple_users(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')
        eve = MessengerClient('Eve')

        alice.add_connection('Bob', self.key1, self.key2)
        alice.add_connection('Eve', self.key3, self.key4)

        bob.add_connection('Alice', self.key2, self.key1)
        bob.add_connection('Eve', self.key5, self.key6)

        eve.add_connection('Alice', self.key4, self.key3)
        eve.add_connection('Bob', self.key6, self.key5)

        plaintext = 'Hi Alice!'
        message, header = bob.send_message('Alice', plaintext)
        result = alice.receive_message('Bob', message, header)
        self.assertEqual(plaintext, result)

        plaintext = 'Hello Bob'
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

        plaintext = 'What are you doing?'
        message, header = bob.send_message('Alice', plaintext)
        result = alice.receive_message('Bob', message, header)
        self.assertEqual(plaintext, result)

        plaintext = "I'm working on my homework"
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

        plaintext = 'Alice is doing her homework. What are you doing Eve?'
        message, header = bob.send_message('Eve', plaintext)
        result = eve.receive_message('Bob', message, header)
        self.assertEqual(plaintext, result)

        plaintext = "Hi Bob! I'm studying for the exam"
        message, header = eve.send_message('Bob', plaintext)
        result = bob.receive_message('Eve', message, header)
        self.assertEqual(plaintext, result)

        plaintext = "How's the homework going Alice"
        message, header = eve.send_message('Alice', plaintext)
        result = alice.receive_message('Eve', message, header)
        self.assertEqual(plaintext, result)

        plaintext = "I just finished it"
        message, header = alice.send_message('Eve', plaintext)
        result = eve.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

    def test_user_can_send_stream_of_messages_without_response(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        alice.add_connection('Bob', self.key1, self.key2)
        bob.add_connection('Alice', self.key2, self.key1)

        plaintext = 'Hi Bob!'
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

        plaintext = 'Hi Bob!'
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

        plaintext = 'Hi Bob!'
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

        plaintext = 'Hi Bob!'
        message, header = alice.send_message('Bob', plaintext)
        result = bob.receive_message('Alice', message, header)
        self.assertEqual(plaintext, result)

    def test_user_can_send_stream_of_messages_with_infrequent_responses(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        alice.add_connection('Bob', self.key1, self.key2)
        bob.add_connection('Alice', self.key2, self.key1)

        for i in range(0, 2):
            for j in range(0, 4):
                plaintext = f'{j}) Hi Bob!'
                message, header = alice.send_message('Bob', plaintext)
                result = bob.receive_message('Alice', message, header)
                self.assertEqual(plaintext, result)

            plaintext = f'{i}) Hello Alice!'
            message, header = bob.send_message('Alice', plaintext)
            result = alice.receive_message('Bob', message, header)
            self.assertEqual(plaintext, result)

    def test_reject_message_from_unknown_user(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        bob.add_connection('Alice', self.key1, self.key2)

        plaintext = 'Hi Alice!'
        message, header = bob.send_message('Alice', plaintext)
        self.assertRaises(Exception, alice.receive_message, 'Bob', message, header)

    def test_replay_attacks_are_detected(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        alice.add_connection('Bob', self.key1, self.key2)
        bob.add_connection('Alice', self.key2, self.key1)

        plaintext = 'Hi Alice!'
        message, header = bob.send_message('Alice', plaintext)
        alice.receive_message('Bob', message, header)

        self.assertRaises(Exception, alice.receive_message, 'Bob', message, header)

    def test_out_of_order_messages(self):
        alice = MessengerClient('Alice')
        bob = MessengerClient('Bob')

        alice.add_connection('Bob', self.key1, self.key2)
        bob.add_connection('Alice', self.key2, self.key1)

        plaintext1 = 'Hi Bob!'
        message1, header1 = alice.send_message('Bob', plaintext1)
        plaintext2 = 'Bob?'
        message2, header2 = alice.send_message('Bob', plaintext2)
        plaintext3 = 'BOB'
        message3, header3 = alice.send_message('Bob', plaintext3)

        result = bob.receive_message('Alice', message1, header1)
        self.assertEqual(plaintext1, result)

        result = bob.receive_message('Alice', message3, header3)
        self.assertEqual(plaintext3, result)

        result = bob.receive_message('Alice', message2, header2)
        self.assertEqual(plaintext2, result)

    def test_more_out_of_order_messages(self):
        colonel = MessengerClient('Colonel')
        snake = MessengerClient('Snake')

        colonel.add_connection('Snake', self.key1, self.key2)
        snake.add_connection('Colonel', self.key2, self.key1)

        plaintext1 = 'Snake?'
        message1, header1 = colonel.send_message('Snake', plaintext1)

        plaintext2 = 'Snake!?'
        message2, header2 = colonel.send_message('Snake', plaintext2)

        plaintext3 = 'SNAKE!'
        message3, header3 = colonel.send_message('Snake', plaintext3)

        result = snake.receive_message('Colonel', message3, header3)
        self.assertEqual(plaintext3, result)

        result = snake.receive_message('Colonel', message2, header2)
        self.assertEqual(plaintext2, result)

        result = snake.receive_message('Colonel', message1, header1)
        self.assertEqual(plaintext1, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
