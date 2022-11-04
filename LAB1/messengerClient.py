#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass, field
from os import urandom
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

hkdf_salt = urandom(32)
hkdf_info = b"Ratchet v1.0"


class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- maximum number of message keys that can be skipped in
                          a single chain

        """

        self.username = username
        # Data regarding active connections.
        self.conn: Dict[str, Ratchet] = {}
        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip

    def add_connection(self, username: str, chain_key_send: bytes, chain_key_recv: bytes):
        """ Add a new connection

        Arguments:
        username (str)         -- user that we want to talk to
        chain_key_send (bytes) -- sending chain key (CKs) of the username
        chain_key_recv (bytes) -- receiving chain key (CKr) of the username

        """

        self.conn[username] = Ratchet(chain_key_send, chain_key_recv, self.max_skip)

    def send_message(self, username: str, message: str) -> (bytes, Header):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """

        if username not in self.conn:
            raise UnknownUser(username)

        ciphertext, header = self.conn[username].ratchet_encrypt(str.encode(message))

        return ciphertext, header

    def receive_message(self, username: str, message: bytes, header: Header) -> str:
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str)  -- user who sent the message
        message (bytes) -- a ciphertext
        header (Header) -- header data

        Returns a plaintext (str)

        """

        if username not in self.conn:
            raise UnknownUser(username)

        plaintext = self.conn[username].ratchet_decrypt(message, header)

        return plaintext.decode()


class UnknownUser(Exception):
    def __init__(self, username: str):
        super().__init__(f"unknown user '{username}'")


class MaxMessageSkipExceeded(Exception):
    def __init__(self, max_skip: int, required_skip: int):
        super().__init__(f"maximum message skip exceeded: '{required_skip}' > '{max_skip}'")


class MessageKeyNotFound(Exception):
    def __init__(self, message_index: int):
        super().__init__(f"message key for index '{message_index}' not found")


@dataclass
class Header:
    nonce: bytes
    message_index: int


@dataclass
class Ratchet:
    # Stores current sending and receiving keys for the user
    send_key: bytes
    recv_key: bytes

    # Stores the maximum number of allowed message skips
    max_skip: int

    # Stores the number of ratchet steps for sending and receiving messages
    sent_count: int = 0
    recv_count: int = 0

    # Stores skipped message keys which are indexed using the 'message_index' field in the Header
    # The maximum number of stored values is 'max_skip'
    # Each skipped message key is deleted once used
    skipped_message_keys: Dict[int, bytes] = field(default_factory=dict)

    # HKDF parameters
    key_length: int = 32
    hkdf_hashing_algorithm: HashAlgorithm = hashes.SHA256()
    salt: bytes = hkdf_salt
    info: bytes = hkdf_info

    # AES-GCM parameters
    aes_gcm_nonce_size: int = 12

    def ratchet_encrypt(self, plaintext: bytes) -> (bytes, Header):
        self.send_key, message_key = self._kdf(self.send_key)

        aes = AESGCM(message_key)
        nonce = urandom(self.aes_gcm_nonce_size)

        ciphertext = aes.encrypt(nonce, plaintext, None)
        header = Header(nonce, self.sent_count)

        self.sent_count += 1

        return ciphertext, header

    def ratchet_decrypt(self, ciphertext: bytes, header: Header) -> bytes:
        self._check_max_skip(header)

        if header.message_index < self.recv_count:
            return self._use_previously_generated_message_key(ciphertext, header)

        if header.message_index > self.recv_count:
            self._save_generated_message_keys(header)

        self.recv_key, message_key = self._kdf(self.recv_key)
        self.recv_count += 1

        aes = AESGCM(message_key)
        plaintext = aes.decrypt(header.nonce, ciphertext, None)

        return plaintext

    def _kdf(self, chain_key: bytes) -> (bytes, bytes):
        hkdf = HKDF(
            algorithm=self.hkdf_hashing_algorithm,
            length=2 * self.key_length,
            salt=self.salt,
            info=self.info,
        )

        key: bytes = hkdf.derive(chain_key)
        chain_key: bytes = key[:self.key_length]
        message_key: bytes = key[self.key_length:]

        return chain_key, message_key

    def _check_max_skip(self, header: Header):
        if (header.message_index - self.recv_count) > self.max_skip:
            raise MaxMessageSkipExceeded(self.max_skip, header.message_index - self.recv_count)

    def _use_previously_generated_message_key(self, ciphertext: bytes, header: Header) -> bytes:
        if header.message_index not in self.skipped_message_keys:
            raise MessageKeyNotFound(header.message_index)

        message_key = self.skipped_message_keys[header.message_index]
        del self.skipped_message_keys[header.message_index]

        aes = AESGCM(message_key)
        plaintext = aes.decrypt(header.nonce, ciphertext, None)

        return plaintext

    def _save_generated_message_keys(self, header: Header):
        if len(self.skipped_message_keys) + (header.message_index - self.recv_count) > self.max_skip:
            self._delete_old_message_keys(header)

        for _ in range(header.message_index - self.recv_count):
            self.recv_key, message_key = self._kdf(self.recv_key)
            self.skipped_message_keys[self.recv_count] = message_key
            self.recv_count += 1

    def _delete_old_message_keys(self, header: Header):
        for message_index in sorted(self.skipped_message_keys.keys(), key=int):
            if len(self.skipped_message_keys) + (header.message_index - self.recv_count) <= self.max_skip:
                break

            del self.skipped_message_keys[message_index]
