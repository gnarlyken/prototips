"""
Drosas komunikacijas sistemas klients.
Savienojas ar serveri, sifre un nosuta zinojumus.
"""

import socket
import struct
import json
import time
import sys
from crypto_engine import izveidot_algoritmu


class DrosaisKlients:
    """TCP klients ar sifresanas atbalstu."""

    def __init__(self, host: str = "127.0.0.1", ports: int = 9000):
        self.host = host
        self.ports = ports
        self.ligzda = None
        self.algoritms = None

    def savienoties(self):
        """Izveido savienojumu ar serveri un sanem sifresanas parametrus."""
        self.ligzda = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ligzda.connect((self.host, self.ports))

        # Sanem algoritma info un atslegu
        garuma_dati = self._sanem_precizi(4)
        garums = struct.unpack("!I", garuma_dati)[0]
        info_dati = self._sanem_precizi(garums)
        info = json.loads(info_dati.decode("utf-8"))

        atslega = bytes.fromhex(info["atslega"])
        self.algoritms = izveidot_algoritmu(info["algoritms"], atslega)
        print(f"[KLIENTS] Savienots ar {self.host}:{self.ports}")
        print(f"[KLIENTS] Algoritms: {self.algoritms.nosaukums}")

    def nosutit(self, zinojums: str) -> dict:
        """Sifre un nosuta zinojumu, atgriez laika merijumus."""
        dati = zinojums.encode("utf-8")

        # Sifret
        sakums = time.perf_counter_ns()
        sifretais = self.algoritms.sifret(dati)
        sifresanas_laiks = time.perf_counter_ns() - sakums

        # Nosutit
        nosut_sakums = time.perf_counter_ns()
        self.ligzda.sendall(struct.pack("!I", len(sifretais)))
        self.ligzda.sendall(sifretais)
        nosutisanas_laiks = time.perf_counter_ns() - nosut_sakums

        # Sanem atbildi
        garuma_dati = self._sanem_precizi(4)
        garums = struct.unpack("!I", garuma_dati)[0]
        sifretas_atb = self._sanem_precizi(garums)

        atsifr_sakums = time.perf_counter_ns()
        atbilde = self.algoritms.atsifret(sifretas_atb)
        atsifresanas_laiks = time.perf_counter_ns() - atsifr_sakums

        return {
            "originals_izmers": len(dati),
            "sifreta_izmers": len(sifretais),
            "sifresanas_laiks_ns": sifresanas_laiks,
            "nosutisanas_laiks_ns": nosutisanas_laiks,
            "atsifresanas_laiks_ns": atsifresanas_laiks,
            "atbilde": atbilde.decode("utf-8")
        }

    def atvienoties(self):
        """Aizver savienojumu."""
        if self.ligzda:
            self.ligzda.close()
            print("[KLIENTS] Atvienots")

    def _sanem_precizi(self, garums: int) -> bytes:
        dati = b""
        while len(dati) < garums:
            gabals = self.ligzda.recv(garums - len(dati))
            if not gabals:
                raise ConnectionError("Savienojums partraukts")
            dati += gabals
        return dati


if __name__ == "__main__":
    klients = DrosaisKlients()
    klients.savienoties()

    try:
        while True:
            teksts = input("Zinojums (vai 'iziet'): ")
            if teksts.lower() == "iziet":
                break
            rezultats = klients.nosutit(teksts)
            print(f"  Sifresana: {rezultats['sifresanas_laiks_ns']/1000:.1f} us")
            print(f"  Atsifresana: {rezultats['atsifresanas_laiks_ns']/1000:.1f} us")
            print(f"  Izmers: {rezultats['originals_izmers']} -> "
                  f"{rezultats['sifreta_izmers']} B")
            print(f"  Atbilde: {rezultats['atbilde']}")
    finally:
        klients.atvienoties()
