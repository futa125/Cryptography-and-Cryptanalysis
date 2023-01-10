#!/usr/bin/env python3

from __future__ import annotations

import dataclasses
import os
import pickle

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurveSignatureAlgorithm
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key


@dataclasses.dataclass
class Message:
    ciphertext: bytes
    nonce: bytes
    public_key: X25519PublicKey


@dataclasses.dataclass
class Certificate:
    username: str
    public_key: bytes


@dataclasses.dataclass
class X25519KeyPair:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


@dataclasses.dataclass
class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    username: str
    ca_public_key: EllipticCurvePublicKey

    key_pair: X25519KeyPair = None
    connections: dict[str, DoubleRatchet] = dataclasses.field(default_factory=dict)
    signature_algorithm: EllipticCurveSignatureAlgorithm = ec.ECDSA(hashes.SHA256())
    shared_secret_algorithm: HashAlgorithm = hashes.SHA256()
    shared_secret_info: bytes = b"Shared Secret"
    shared_secret_salt: bytes = os.urandom(16)
    shared_secret_length: int = 32
    public_bytes_format: dict = dataclasses.field(
        default_factory=lambda: {
            "encoding": serialization.Encoding.PEM,
            "format": serialization.PublicFormat.SubjectPublicKeyInfo
        }
    )

    def generate_certificate(self) -> Certificate:
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

            Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
            javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
            objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
            dict ili tuple). Za serijalizaciju kljuca mozete koristiti
            metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

            Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
            će tako dobiveni certifikat biti proslijeđen drugim klijentima.
        """

        private_key = X25519PrivateKey.generate()
        self.key_pair = X25519KeyPair(private_key, private_key.public_key())

        return Certificate(self.username, self.key_pair.public_key.public_bytes(**self.public_bytes_format))

    def receive_certificate(self, cert: Certificate, signature: bytes):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

            Argumenti:
            cert      -- certifikacijski objekt
            signature -- digitalni potpis od `cert`

            Metoda prima certifikacijski objekt (koji sadrži inicijalni
            Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
            verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
            sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
            spremljen prilikom inicijalizacije objekta.
        """

        self.ca_public_key.verify(signature, pickle.dumps(cert), self.signature_algorithm)

        shared_secret = HKDF(
            algorithm=self.shared_secret_algorithm,
            length=self.shared_secret_length,
            salt=self.shared_secret_salt,
            info=self.shared_secret_info
        ).derive(self.key_pair.private_key.exchange(load_pem_public_key(cert.public_key)))

        self.connections[cert.username] = DoubleRatchet(
            load_pem_public_key(cert.public_key),
            self.key_pair,
            shared_secret
        )

    def send_message(self, username: str, plaintext: str) -> Message:
        """ Slanje poruke klijentu

            Argumenti:
            message  -- poruka koju ćemo poslati
            username -- klijent kojem šaljemo poruku `message`

            Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
            Pretpostavite da već posjedujete certifikacijski objekt od klijenta
            (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
            Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
            nužne `double ratchet` ključeve prema specifikaciji.

            Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
            lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
            `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
            AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
            zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
            vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
            derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
            kriptirana novim `sending` ključem.

            Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.
        """

        return self.connections[username].ratchet_encrypt(plaintext.encode())

    def receive_message(self, username, message: Message) -> str:
        """ Primanje poruke od korisnika

            Argumenti:
            message  -- poruka koju smo primili
            username -- klijent koji je poslao poruku

            Metoda prima kriptiranu poruku od klijenta s imenom `username`.
            Pretpostavite da već posjedujete certifikacijski objekt od klijenta
            (dobiven pomoću `receive_certificate`) i da je klijent izračunao
            inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
            certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
            da generirate nužne `double ratchet` ključeve prema specifikaciji.

            Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
            lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
            informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
            `receiving` ključa. Ako detektirate da je integritet poruke narušen,
            zaustavite izvršavanje programa i generirajte iznimku.

            Metoda treba vratiti dekriptiranu poruku.
        """

        return self.connections[username].ratchet_decrypt(message).decode()


@dataclasses.dataclass
class DoubleRatchet:
    DHr: X25519PublicKey
    DHs: X25519KeyPair
    RK: bytes

    CKs: bytes = None
    CKr: bytes = None
    key_length: int = 32
    kdf_hash_algorithm: HashAlgorithm = hashes.SHA256()
    kdf_info: bytes = b"Double Ratchet"
    kdf_mk_constant: bytes = b"\x01"
    kdf_ck_constant: bytes = b"\x02"
    aes_gcm_nonce_size: int = 16

    def ratchet_encrypt(self, plaintext: bytes) -> Message:
        if self.CKs is None:
            self.RK, self.CKs = self._kdf_rk(self.RK, self.DHs.private_key.exchange(self.DHr))

        mk, self.CKs = self._kdf_ck(self.CKs)

        aes = AESGCM(mk)
        nonce = os.urandom(self.aes_gcm_nonce_size)
        ciphertext = aes.encrypt(nonce, plaintext, None)

        message = Message(ciphertext, nonce, self.DHs.public_key)

        return message

    def ratchet_decrypt(self, message: Message) -> bytes:
        if message.public_key != self.DHr:
            self._dh_ratchet(message.public_key)

        mk, self.CKr = self._kdf_ck(self.CKr)

        aes = AESGCM(mk)
        plaintext = aes.decrypt(message.nonce, message.ciphertext, None)

        return plaintext

    def _dh_ratchet(self, dh_public_key: X25519PublicKey):
        self.DHr = dh_public_key
        self.RK, self.CKr = self._kdf_rk(self.RK, self.DHs.private_key.exchange(self.DHr))
        private_key = X25519PrivateKey.generate()
        self.DHs = X25519KeyPair(private_key, private_key.public_key())
        self.RK, self.CKs = self._kdf_rk(self.RK, self.DHs.private_key.exchange(self.DHr))

    def _kdf_rk(self, rk: bytes, dh_out: bytes) -> (bytes, bytes):
        derived_key = HKDF(
            algorithm=self.kdf_hash_algorithm,
            length=2 * self.key_length,
            salt=rk,
            info=self.kdf_info
        ).derive(dh_out)

        return derived_key[:self.key_length], derived_key[self.key_length:]

    def _kdf_ck(self, ck: bytes):
        hmac = HMAC(key=ck, algorithm=self.kdf_hash_algorithm)
        hmac.update(self.kdf_mk_constant)
        mk = hmac.finalize()

        hmac = HMAC(key=ck, algorithm=self.kdf_hash_algorithm)
        hmac.update(self.kdf_ck_constant)
        ck = hmac.finalize()

        return mk, ck
