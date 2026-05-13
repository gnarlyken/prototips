"""
Tikla veiktspejas tests - mera sifresanas ietekmi uz tikla komunikaciju.
Palais serveri un klientu, nosuta dazada izmera zinojumus un mera latentumu.
"""

import socket
import struct
import threading
import time
import json
import os
import statistics
from crypto_engine import izveidot_algoritmu, pieejamie_algoritmi


def palaist_serveri(ports, algoritms_obj, gatavs_notikums, apturet_notikums):
    """Palais testu serveri atseviska pavedienia."""
    ligzda = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ligzda.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ligzda.bind(("127.0.0.1", ports))
    ligzda.listen(1)
    ligzda.settimeout(1.0)
    gatavs_notikums.set()

    try:
        while not apturet_notikums.is_set():
            try:
                klients, _ = ligzda.accept()
            except socket.timeout:
                continue

            try:
                while not apturet_notikums.is_set():
                    # Lasit garumu
                    garuma_dati = b""
                    while len(garuma_dati) < 4:
                        gabals = klients.recv(4 - len(garuma_dati))
                        if not gabals:
                            break
                        garuma_dati += gabals
                    if len(garuma_dati) < 4:
                        break

                    garums = struct.unpack("!I", garuma_dati)[0]

                    # Lasit sifretos datus
                    sifretie = b""
                    while len(sifretie) < garums:
                        gabals = klients.recv(garums - len(sifretie))
                        if not gabals:
                            break
                        sifretie += gabals

                    # Atsifret
                    dati = algoritms_obj.atsifret(sifretie)

                    # Sifret atbildi un nosutit
                    atbilde = algoritms_obj.sifret(dati)
                    klients.sendall(struct.pack("!I", len(atbilde)))
                    klients.sendall(atbilde)

            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                klients.close()
    finally:
        ligzda.close()


def veikt_tikla_testu(algoritma_nos: str, datu_izmers: int, iteracijas: int,
                      ports: int) -> dict:
    """Veic tikla testu ar noteiktu algoritmu un datu izmeru."""
    algoritms = izveidot_algoritmu(algoritma_nos)

    gatavs = threading.Event()
    apturet = threading.Event()

    serveris = threading.Thread(
        target=palaist_serveri,
        args=(ports, algoritms, gatavs, apturet),
        daemon=True
    )
    serveris.start()
    gatavs.wait(timeout=5)

    # Klients
    ligzda = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ligzda.connect(("127.0.0.1", ports))

    dati = os.urandom(datu_izmers)
    latentumi_ns = []

    # Iesildisana
    for _ in range(min(5, iteracijas)):
        sifretie = algoritms.sifret(dati)
        ligzda.sendall(struct.pack("!I", len(sifretie)))
        ligzda.sendall(sifretie)
        g_dati = b""
        while len(g_dati) < 4:
            g_dati += ligzda.recv(4 - len(g_dati))
        g = struct.unpack("!I", g_dati)[0]
        atb = b""
        while len(atb) < g:
            atb += ligzda.recv(g - len(atb))
        algoritms.atsifret(atb)

    # Merijumi
    for _ in range(iteracijas):
        sakums = time.perf_counter_ns()

        # Sifret + nosutit
        sifretie = algoritms.sifret(dati)
        ligzda.sendall(struct.pack("!I", len(sifretie)))
        ligzda.sendall(sifretie)

        # Sanem atbildi
        g_dati = b""
        while len(g_dati) < 4:
            g_dati += ligzda.recv(4 - len(g_dati))
        g = struct.unpack("!I", g_dati)[0]
        atb = b""
        while len(atb) < g:
            atb += ligzda.recv(g - len(atb))

        # Atsifret
        algoritms.atsifret(atb)

        beigas = time.perf_counter_ns()
        latentumi_ns.append(beigas - sakums)

    ligzda.close()
    apturet.set()
    serveris.join(timeout=3)

    latentumi_us = [l / 1000 for l in latentumi_ns]

    return {
        "algoritms": algoritma_nos,
        "datu_izmers_baiti": datu_izmers,
        "iteracijas": iteracijas,
        "videjais_latentums_us": statistics.mean(latentumi_us),
        "mediana_us": statistics.median(latentumi_us),
        "p95_us": sorted(latentumi_us)[int(len(latentumi_us) * 0.95)],
        "p99_us": sorted(latentumi_us)[int(len(latentumi_us) * 0.99)],
        "min_us": min(latentumi_us),
        "max_us": max(latentumi_us),
        "std_us": statistics.stdev(latentumi_us) if len(latentumi_us) > 1 else 0,
    }


def veikt_visus_tikla_testus() -> list:
    """Veic tikla testus ar visiem algoritmiem un datu izmeriem."""
    algoritmi = pieejamie_algoritmi()
    izmeri = {
        "64 B": 64,
        "1 KB": 1024,
        "16 KB": 16384,
        "64 KB": 65536,
        "256 KB": 262144,
        "1 MB": 1048576,
    }
    iteracijas_skaits = {
        "64 B": 2000,
        "1 KB": 2000,
        "16 KB": 1000,
        "64 KB": 500,
        "256 KB": 200,
        "1 MB": 100,
    }

    visi_rezultati = []
    ports = 19000

    print("=" * 100)
    print("TIKLA VEIKTSPEJAS TESTI (klient-serveris ar sifresanu)")
    print("=" * 100)

    for izm_nos, izm_baiti in izmeri.items():
        print(f"\n--- Datu izmers: {izm_nos} ---")
        itr = iteracijas_skaits[izm_nos]

        for alg_nos in algoritmi:
            ports += 1
            try:
                rez = veikt_tikla_testu(alg_nos, izm_baiti, itr, ports)
                visi_rezultati.append(rez)
                print(f"  {alg_nos:22s} | Latentums: "
                      f"vid={rez['videjais_latentums_us']:.0f} us, "
                      f"med={rez['mediana_us']:.0f} us, "
                      f"p95={rez['p95_us']:.0f} us, "
                      f"p99={rez['p99_us']:.0f} us")
            except Exception as e:
                print(f"  {alg_nos:22s} | KLUDA: {e}")

    return visi_rezultati


if __name__ == "__main__":
    rezultati = veikt_visus_tikla_testus()

    # Saglabat
    with open("tikla_rezultati.json", "w", encoding="utf-8") as f:
        json.dump(rezultati, f, indent=2, ensure_ascii=False)
    print(f"\nRezultati saglabati: tikla_rezultati.json")
