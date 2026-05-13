"""
Sifresanas algoritmu veiktspejas merisanas riks.
Veic visaptverosus testus ar dazadiem datu apjomiem un algoritmu konfiguracijam.
"""

import time
import os
import sys
import json
import statistics
import resource
from crypto_engine import izveidot_algoritmu, pieejamie_algoritmi


# Testu parametri
DATU_IZMERI = {
    "64 B": 64,
    "256 B": 256,
    "1 KB": 1024,
    "4 KB": 4096,
    "16 KB": 16384,
    "64 KB": 65536,
    "256 KB": 262144,
    "1 MB": 1048576,
    "4 MB": 4194304,
    "16 MB": 16777216,
}

ITERACIJAS = {
    "64 B": 10000,
    "256 B": 10000,
    "1 KB": 5000,
    "4 KB": 5000,
    "16 KB": 2000,
    "64 KB": 1000,
    "256 KB": 500,
    "1 MB": 200,
    "4 MB": 50,
    "16 MB": 20,
}


def merit_laiku_ns(funkcija, *argumenti):
    """Mera funkcijas izpildes laiku nanosekundes."""
    sakums = time.perf_counter_ns()
    rezultats = funkcija(*argumenti)
    beigas = time.perf_counter_ns()
    return beigas - sakums, rezultats


def merit_atminu():
    """Atgriez pasobano atminas paterinanu kilobaitos."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # KB


def veikt_algoritma_testu(algoritma_nos: str, datu_izmers_nos: str,
                          datu_izmers: int, iteracijas: int) -> dict:
    """Veic viena algoritma testu ar noteiktu datu izmeru."""
    algoritms = izveidot_algoritmu(algoritma_nos)
    dati = os.urandom(datu_izmers)

    sifresanas_laiki = []
    atsifresanas_laiki = []
    sifreto_izmeri = []

    # Iesildisanas raunds (neieskaita)
    for _ in range(min(10, iteracijas)):
        sifreti = algoritms.sifret(dati)
        algoritms.atsifret(sifreti)

    # Galvenie merijumi
    for i in range(iteracijas):
        # Sifresana
        s_laiks, sifretie = merit_laiku_ns(algoritms.sifret, dati)
        sifresanas_laiki.append(s_laiks)
        sifreto_izmeri.append(len(sifretie))

        # Atsifresana
        a_laiks, atsifreti = merit_laiku_ns(algoritms.atsifret, sifretie)
        atsifresanas_laiki.append(a_laiks)

        # Pareizibas parbaude
        if atsifreti != dati:
            raise RuntimeError(f"Atsifresanas kluda! Algoritms: {algoritma_nos}")

    # Statistika
    def aprekenat_statistiku(laiki_ns, datu_izmers):
        laiki_us = [t / 1000 for t in laiki_ns]
        kopejais_ns = sum(laiki_ns)
        caurlaidspeja_mbps = (datu_izmers * len(laiki_ns) * 8) / (kopejais_ns / 1e9) / 1e6

        return {
            "videjais_us": statistics.mean(laiki_us),
            "mediana_us": statistics.median(laiki_us),
            "std_us": statistics.stdev(laiki_us) if len(laiki_us) > 1 else 0,
            "min_us": min(laiki_us),
            "max_us": max(laiki_us),
            "p95_us": sorted(laiki_us)[int(len(laiki_us) * 0.95)],
            "p99_us": sorted(laiki_us)[int(len(laiki_us) * 0.99)],
            "caurlaidspeja_mbps": caurlaidspeja_mbps,
        }

    videjais_palielinajums = statistics.mean(sifreto_izmeri) / datu_izmers

    return {
        "algoritms": algoritma_nos,
        "datu_izmers": datu_izmers_nos,
        "datu_izmers_baiti": datu_izmers,
        "iteracijas": iteracijas,
        "sifresana": aprekenat_statistiku(sifresanas_laiki, datu_izmers),
        "atsifresana": aprekenat_statistiku(atsifresanas_laiki, datu_izmers),
        "izmera_palielinajums": videjais_palielinajums,
    }


def izdrukot_rezultatu(rez: dict):
    """Formateti izdruka viena testa rezultatu."""
    alg = rez["algoritms"]
    izm = rez["datu_izmers"]
    sif = rez["sifresana"]
    ats = rez["atsifresana"]

    print(f"  {alg:22s} | {izm:8s} | "
          f"Sifr: {sif['videjais_us']:10.1f} us ({sif['caurlaidspeja_mbps']:8.1f} Mbps) | "
          f"Atsifr: {ats['videjais_us']:10.1f} us ({ats['caurlaidspeja_mbps']:8.1f} Mbps) | "
          f"Izm+: {rez['izmera_palielinajums']:.3f}x")


def veikt_visus_testus() -> list:
    """Veic visus testus ar visiem algoritmiem un datu izmeriem."""
    algoritmi = pieejamie_algoritmi()
    visi_rezultati = []

    print("=" * 120)
    print("SIFRESANAS ALGORITMU VEIKTSPEJAS TESTI")
    print("=" * 120)
    print(f"Algoritmi: {', '.join(algoritmi)}")
    print(f"Datu izmeri: {', '.join(DATU_IZMERI.keys())}")
    print(f"Platforma: {sys.platform}")
    print()

    for izm_nos, izm_baiti in DATU_IZMERI.items():
        print(f"\n--- Datu izmers: {izm_nos} ({izm_baiti} baiti) ---")
        iteracijas = ITERACIJAS[izm_nos]
        print(f"    Iteracijas: {iteracijas}")

        for alg_nos in algoritmi:
            try:
                rez = veikt_algoritma_testu(alg_nos, izm_nos, izm_baiti, iteracijas)
                visi_rezultati.append(rez)
                izdrukot_rezultatu(rez)
            except Exception as e:
                print(f"  {alg_nos:22s} | KLUDA: {e}")

    return visi_rezultati


def saglabat_rezultatus(rezultati: list, faila_nosaukums: str = "rezultati.json"):
    """Saglaba rezultatus JSON faila."""
    with open(faila_nosaukums, "w", encoding="utf-8") as f:
        json.dump(rezultati, f, indent=2, ensure_ascii=False)
    print(f"\nRezultati saglabati: {faila_nosaukums}")


def izdrukot_kopsavilkumu(rezultati: list):
    """Izdruka tabularsku kopsavilkumu."""
    print("\n" + "=" * 120)
    print("KOPSAVILKUMS - Caurlaidspeja (Mbps)")
    print("=" * 120)

    algoritmi = list(dict.fromkeys(r["algoritms"] for r in rezultati))
    izmeri = list(dict.fromkeys(r["datu_izmers"] for r in rezultati))

    # Galvene
    header = f"{'Izmers':>10s}"
    for alg in algoritmi:
        header += f" | {alg:>22s}"
    print(header)
    print("-" * len(header))

    # Dati
    for izm in izmeri:
        rinda = f"{izm:>10s}"
        for alg in algoritmi:
            rez = next((r for r in rezultati
                        if r["algoritms"] == alg and r["datu_izmers"] == izm), None)
            if rez:
                mbps = rez["sifresana"]["caurlaidspeja_mbps"]
                rinda += f" | {mbps:22.1f}"
            else:
                rinda += f" | {'N/A':>22s}"
        print(rinda)

    # Atsifresanas caurlaidspeja
    print("\n" + "=" * 120)
    print("KOPSAVILKUMS - Atsifresanas caurlaidspeja (Mbps)")
    print("=" * 120)
    print(header)
    print("-" * len(header))

    for izm in izmeri:
        rinda = f"{izm:>10s}"
        for alg in algoritmi:
            rez = next((r for r in rezultati
                        if r["algoritms"] == alg and r["datu_izmers"] == izm), None)
            if rez:
                mbps = rez["atsifresana"]["caurlaidspeja_mbps"]
                rinda += f" | {mbps:22.1f}"
            else:
                rinda += f" | {'N/A':>22s}"
        print(rinda)


if __name__ == "__main__":
    rezultati = veikt_visus_testus()
    izdrukot_kopsavilkumu(rezultati)
    saglabat_rezultatus(rezultati)
