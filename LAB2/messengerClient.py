#!/usr/bin/env python3
import dataclasses
import os
import pickle
from typing import Dict, Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PARAMETERS = dh.generate_parameters(generator=2, key_size=1024)


@dataclasses.dataclass
class Message:
    ciphertext: bytes
    nonce: bytes
    public_key: DHPublicKey


@dataclasses.dataclass
class Certificate:
    username: str
    public_key: bytes


class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username: str, ca_public_key: EllipticCurvePublicKey):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_public_key = ca_public_key
        self.connections: Dict[str, DoubleRatchet] = {}
        self.private_key: Optional[DHPrivateKey] = None

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

        self.private_key = PARAMETERS.generate_private_key()

        return Certificate(self.username, self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

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

        self.ca_public_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))

        self.connections[cert.username] = DoubleRatchet(
            cert.username,
            load_pem_public_key(cert.public_key),
            self.private_key,
            self.private_key.exchange(load_pem_public_key(cert.public_key))
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
        plaintext = self.connections[username].ratchet_decrypt(message)

        return plaintext.decode()


@dataclasses.dataclass
class DoubleRatchet:
    username: str
    DHr: DHPublicKey
    DHs: DHPrivateKey
    RK: bytes
    CKs: bytes = None
    CKr: bytes = None

    def ratchet_encrypt(self, plaintext: bytes) -> Message:
        if self.CKs is None:
            self.RK, self.CKs = self._kdf_rk(self.RK, self.DHs.exchange(self.DHr))

        mk, self.CKs = self._kdf_ck(self.CKs)

        aes = AESGCM(mk)
        nonce = os.urandom(128)
        ciphertext = aes.encrypt(nonce, plaintext, None)

        message = Message(ciphertext, nonce, self.DHs.public_key())

        return message

    def ratchet_decrypt(self, message: Message) -> bytes:
        if self.CKr is None or not self.public_keys_equal(message.public_key, self.DHr):
            self._dh_ratchet(message.public_key)

        mk, self.CKr = self._kdf_ck(self.CKr)

        aes = AESGCM(mk)
        plaintext = aes.decrypt(message.nonce, message.ciphertext, None)

        return plaintext

    def _dh_ratchet(self, dh_public_key: DHPublicKey):
        self.DHr = dh_public_key
        self.RK, self.CKr = self._kdf_rk(self.RK, self.DHs.exchange(self.DHr))
        self.DHs = PARAMETERS.generate_private_key()
        self.RK, self.CKs = self._kdf_rk(self.RK, self.DHs.exchange(self.DHr))

    @staticmethod
    def _kdf_rk(rk: bytes, dh_out: bytes) -> (bytes, bytes):
        derived_key = HKDF(algorithm=hashes.SHA256(), length=64, salt=rk, info=b"kdf").derive(dh_out)
        return derived_key[0:32], derived_key[32:64]

    @staticmethod
    def _kdf_ck(ck: bytes):
        hmac = HMAC(key=ck, algorithm=hashes.SHA256())
        hmac.update(b"\x01")
        mk = hmac.finalize()

        hmac = HMAC(key=ck, algorithm=hashes.SHA256())
        hmac.update(b"\x02")
        ck = hmac.finalize()

        return mk, ck

    @staticmethod
    def public_keys_equal(pub_key1: DHPublicKey, pub_key2: DHPublicKey) -> bool:
        pub_key_bytes1 = pub_key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pub_key_bytes2 = pub_key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pub_key_bytes1 == pub_key_bytes2
