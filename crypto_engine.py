"""
Kriptografijas dzinis - sifresanas algoritmu implementacija.
Atbalsta: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, 3DES-CBC.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class SifresanasAlgoritms:
    """Bazu klase visiem sifresanas algoritmiem."""

    def __init__(self, nosaukums: str, atslega: bytes):
        self.nosaukums = nosaukums
        self.atslega = atslega

    def sifret(self, dati: bytes) -> bytes:
        raise NotImplementedError

    def atsifret(self, sifretie_dati: bytes) -> bytes:
        raise NotImplementedError

    @staticmethod
    def generet_atslegu(garums_baitos: int) -> bytes:
        return os.urandom(garums_baitos)


class AES_GCM(SifresanasAlgoritms):
    """AES-GCM (Galois/Counter Mode) implementacija."""

    def __init__(self, atslega: bytes):
        bitu_garums = len(atslega) * 8
        super().__init__(f"AES-{bitu_garums}-GCM", atslega)
        self.aesgcm = AESGCM(atslega)

    def sifret(self, dati: bytes) -> bytes:
        # 12 baitu nonce (iesaka NIST)
        nonce = os.urandom(12)
        sifreteksts = self.aesgcm.encrypt(nonce, dati, None)
        # Atgriez nonce + sifretekstu (ietver autentifikacijas tagu)
        return nonce + sifreteksts

    def atsifret(self, sifretie_dati: bytes) -> bytes:
        nonce = sifretie_dati[:12]
        sifreteksts = sifretie_dati[12:]
        return self.aesgcm.decrypt(nonce, sifreteksts, None)


class ChaCha20Poly1305Algoritms(SifresanasAlgoritms):
    """ChaCha20-Poly1305 implementacija."""

    def __init__(self, atslega: bytes):
        super().__init__("ChaCha20-Poly1305", atslega)
        self.chacha = ChaCha20Poly1305(atslega)

    def sifret(self, dati: bytes) -> bytes:
        nonce = os.urandom(12)
        sifreteksts = self.chacha.encrypt(nonce, dati, None)
        return nonce + sifreteksts

    def atsifret(self, sifretie_dati: bytes) -> bytes:
        nonce = sifretie_dati[:12]
        sifreteksts = sifretie_dati[12:]
        return self.chacha.decrypt(nonce, sifreteksts, None)


class TripleDES_CBC(SifresanasAlgoritms):
    """3DES-CBC implementacija ar PKCS7 papildinajumu."""

    def __init__(self, atslega: bytes):
        super().__init__("3DES-CBC", atslega)

    def sifret(self, dati: bytes) -> bytes:
        # PKCS7 papildinajums lidz 8 baitu blokam
        papildinatais = padding.PKCS7(64).padder()
        papildinati_dati = papildinatais.update(dati) + papildinatais.finalize()

        iv = os.urandom(8)
        sifrs = Cipher(
            algorithms.TripleDES(self.atslega),
            modes.CBC(iv),
            backend=default_backend()
        )
        sifretajs = sifrs.encryptor()
        sifreteksts = sifretajs.update(papildinati_dati) + sifretajs.finalize()
        return iv + sifreteksts

    def atsifret(self, sifretie_dati: bytes) -> bytes:
        iv = sifretie_dati[:8]
        sifreteksts = sifretie_dati[8:]

        sifrs = Cipher(
            algorithms.TripleDES(self.atslega),
            modes.CBC(iv),
            backend=default_backend()
        )
        atsifretajs = sifrs.decryptor()
        papildinati_dati = atsifretajs.update(sifreteksts) + atsifretajs.finalize()

        nonemtais = padding.PKCS7(64).unpadder()
        return nonemtais.update(papildinati_dati) + nonemtais.finalize()


def izveidot_algoritmu(nosaukums: str, atslega: bytes = None) -> SifresanasAlgoritms:
    """Rupnicas metode algoritma izveidei pec nosaukuma."""
    algoritmi = {
        "AES-128-GCM": (AES_GCM, 16),
        "AES-256-GCM": (AES_GCM, 32),
        "ChaCha20-Poly1305": (ChaCha20Poly1305Algoritms, 32),
        "3DES-CBC": (TripleDES_CBC, 24),
    }

    if nosaukums not in algoritmi:
        raise ValueError(f"Nezinams algoritms: {nosaukums}. "
                         f"Pieejamie: {list(algoritmi.keys())}")

    klase, atsl_garums = algoritmi[nosaukums]
    if atslega is None:
        atslega = SifresanasAlgoritms.generet_atslegu(atsl_garums)

    return klase(atslega)


def pieejamie_algoritmi() -> list:
    """Atgriez pieejamo algoritmu nosaukumus."""
    return ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "3DES-CBC"]
