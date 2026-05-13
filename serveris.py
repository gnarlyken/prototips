"""
Drosas komunikacijas sistemas serveris.
Pienem TCP savienojumus, veic sifresanu/atsifresanu ar izveleto algoritmu.
"""

import socket
import threading
import json
import struct
import time
import sys
from crypto_engine import izveidot_algoritmu, pieejamie_algoritmi


class DrosaisSeveris:
    """TCP serveris ar sifresanas atbalstu."""

    def __init__(self, host: str = "127.0.0.1", ports: int = 9000):
        self.host = host
        self.ports = ports
        self.ligzda = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ligzda.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.klienti = {}
        self.algoritms = None
        self.atslega = None
        self.darbojas = False

    def start(self, algoritma_nosaukums: str = "AES-256-GCM"):
        """Palais serveri ar noraidito sifresanas algoritmu."""
        self.algoritms = izveidot_algoritmu(algoritma_nosaukums)
        self.atslega = self.algoritms.atslega
        self.darbojas = True

        self.ligzda.bind((self.host, self.ports))
        self.ligzda.listen(5)
        print(f"[SERVERIS] Klausas uz {self.host}:{self.ports}")
        print(f"[SERVERIS] Algoritms: {self.algoritms.nosaukums}")
        print(f"[SERVERIS] Atslega (hex): {self.atslega.hex()[:32]}...")

        while self.darbojas:
            try:
                self.ligzda.settimeout(1.0)
                try:
                    klients, adrese = self.ligzda.accept()
                except socket.timeout:
                    continue
                print(f"[SERVERIS] Jauns savienojums: {adrese}")

                # Nosutit algoritma info un atslegu klientam
                info = {
                    "algoritms": algoritma_nosaukums,
                    "atslega": self.atslega.hex()
                }
                info_baiti = json.dumps(info).encode("utf-8")
                klients.sendall(struct.pack("!I", len(info_baiti)))
                klients.sendall(info_baiti)

                pavedienis = threading.Thread(
                    target=self._apstradat_klientu,
                    args=(klients, adrese),
                    daemon=True
                )
                pavedienis.start()
                self.klienti[adrese] = klients

            except KeyboardInterrupt:
                break

        self.apturet()

    def _apstradat_klientu(self, klients: socket.socket, adrese: tuple):
        """Apstrada ienakosos zinojumus no klienta."""
        try:
            while self.darbojas:
                # Nolasit zinojuma garumu (4 baiti)
                garuma_dati = self._sanem_precizi(klients, 4)
                if not garuma_dati:
                    break
                garums = struct.unpack("!I", garuma_dati)[0]

                # Nolasit sifreto zinojumu
                sifretais = self._sanem_precizi(klients, garums)
                if not sifretais:
                    break

                # Atsifret
                sakuma_laiks = time.perf_counter_ns()
                atsifreti_dati = self.algoritms.atsifret(sifretais)
                atsifresanas_laiks = time.perf_counter_ns() - sakuma_laiks

                zinojums = atsifreti_dati.decode("utf-8")
                print(f"[{adrese}] Sanema: {zinojums[:100]}... "
                      f"({len(sifretais)} B sifrets, "
                      f"atsifrets {atsifresanas_laiks/1000:.1f} us)")

                # Nosutit apstiprinajumu (sifretu)
                atbilde = f"Sanema: {len(atsifreti_dati)} baiti".encode("utf-8")
                sifretas_atb = self.algoritms.sifret(atbilde)
                klients.sendall(struct.pack("!I", len(sifretas_atb)))
                klients.sendall(sifretas_atb)

        except (ConnectionResetError, BrokenPipeError):
            print(f"[SERVERIS] Klients {adrese} atvienojies")
        except Exception as e:
            print(f"[SERVERIS] Kluda ar {adrese}: {e}")
        finally:
            klients.close()
            self.klienti.pop(adrese, None)

    def _sanem_precizi(self, ligzda: socket.socket, garums: int) -> bytes:
        """Sanem precizu baitu skaitu no ligzdas."""
        dati = b""
        while len(dati) < garums:
            gabals = ligzda.recv(garums - len(dati))
            if not gabals:
                return None
            dati += gabals
        return dati

    def apturet(self):
        """Aptur serveri."""
        self.darbojas = False
        for klients in self.klienti.values():
            klients.close()
        self.ligzda.close()
        print("[SERVERIS] Apturets")


if __name__ == "__main__":
    algoritms = sys.argv[1] if len(sys.argv) > 1 else "AES-256-GCM"
    print(f"Pieejamie algoritmi: {pieejamie_algoritmi()}")
    serveris = DrosaisSeveris()
    serveris.start(algoritms)
