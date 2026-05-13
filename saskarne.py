"""
Grafiska saskarne drosas komunikacijas prototipam.
Visas funkcijas pieejamas viena loga ar cilnem.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import subprocess
import queue
import sys
import os
import json
import time

from crypto_engine import izveidot_algoritmu, pieejamie_algoritmi
from klients import DrosaisKlients


PYTHON = sys.executable
DARBA_DIR = os.path.dirname(os.path.abspath(__file__))


class SaskarneGUI:
    def __init__(self, sakne: tk.Tk):
        self.sakne = sakne
        self.sakne.title("Drošas komunikācijas prototips")
        self.sakne.geometry("1100x750")
        self.sakne.minsize(900, 600)

        # Procesu un klienta stavoklis
        self.servera_process: subprocess.Popen | None = None
        self.servera_rinda: queue.Queue = queue.Queue()
        self.benchmark_process: subprocess.Popen | None = None
        self.benchmark_rinda: queue.Queue = queue.Queue()
        self.tikla_process: subprocess.Popen | None = None
        self.tikla_rinda: queue.Queue = queue.Queue()
        self.klients: DrosaisKlients | None = None

        # Pedejais sifrets rezultats (binaras baitu virknes) sifresanas cilnei
        self._pedejais_sifrs: bytes | None = None

        self._izveidot_stilus()
        self._izveidot_saskarni()

        # Periodiska logu atjauninasana
        self.sakne.after(100, self._atjaunot_logus)
        self.sakne.protocol("WM_DELETE_WINDOW", self._aizvert)

    # ------------------------------------------------------------------
    # Saskarnes izveide
    # ------------------------------------------------------------------

    def _izveidot_stilus(self):
        stils = ttk.Style()
        try:
            stils.theme_use("clam")
        except tk.TclError:
            pass
        stils.configure("Virsraksts.TLabel", font=("Helvetica", 14, "bold"))
        stils.configure("Zalais.TLabel", foreground="#1b7a1b")
        stils.configure("Sarkanais.TLabel", foreground="#b22222")

    def _izveidot_saskarni(self):
        notebook = ttk.Notebook(self.sakne)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 4))

        self._cilne_sifresana(notebook)
        self._cilne_serveris(notebook)
        self._cilne_klients(notebook)
        self._cilne_veiktspeja(notebook)
        self._cilne_tikls(notebook)
        self._cilne_rezultati(notebook)

        self.statusa_mainigais = tk.StringVar(value="Gatavs")
        statusa_josla = ttk.Label(
            self.sakne, textvariable=self.statusa_mainigais,
            relief=tk.SUNKEN, anchor=tk.W, padding=(8, 4)
        )
        statusa_josla.pack(fill=tk.X, side=tk.BOTTOM)

    # ------------------------------------------------------------------
    # Cilne: atseviska sifresana/atsifresana
    # ------------------------------------------------------------------

    def _cilne_sifresana(self, notebook: ttk.Notebook):
        rāmis = ttk.Frame(notebook, padding=12)
        notebook.add(rāmis, text="🔐 Šifrēšana")

        ttk.Label(rāmis, text="Šifrēšanas / atšifrēšanas rīks",
                  style="Virsraksts.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        ttk.Label(rāmis, text="Algoritms:").grid(row=1, column=0, sticky="w", padx=(0, 6))
        self.sifr_algoritms = tk.StringVar(value="AES-256-GCM")
        alg_kombo = ttk.Combobox(rāmis, textvariable=self.sifr_algoritms,
                                 values=pieejamie_algoritmi(), state="readonly", width=25)
        alg_kombo.grid(row=1, column=1, sticky="w")
        alg_kombo.bind("<<ComboboxSelected>>", lambda e: self._generet_atslegu())

        ttk.Button(rāmis, text="🔑 Ģenerēt atslēgu",
                   command=self._generet_atslegu).grid(row=1, column=2, padx=6)

        ttk.Label(rāmis, text="Atslēga (hex):").grid(row=2, column=0, sticky="nw", pady=(8, 0))
        self.atslegas_lauks = tk.Text(rāmis, height=2, width=80, font=("Courier", 10))
        self.atslegas_lauks.grid(row=2, column=1, columnspan=3, sticky="we", pady=(8, 0))

        ttk.Label(rāmis, text="Atklātais teksts:").grid(row=3, column=0, sticky="nw", pady=(8, 0))
        self.atkl_teksts = scrolledtext.ScrolledText(rāmis, height=6, width=80, font=("Courier", 10))
        self.atkl_teksts.grid(row=3, column=1, columnspan=3, sticky="we", pady=(8, 0))
        self.atkl_teksts.insert("1.0", "Sveika, pasaule! Tests 123.")

        pogu_ramis = ttk.Frame(rāmis)
        pogu_ramis.grid(row=4, column=1, columnspan=3, sticky="w", pady=8)
        ttk.Button(pogu_ramis, text="▶ Šifrēt", command=self._sifret).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(pogu_ramis, text="◀ Atšifrēt", command=self._atsifret).pack(side=tk.LEFT, padx=6)
        ttk.Button(pogu_ramis, text="🧹 Notīrīt", command=self._tirit_sifresanu).pack(side=tk.LEFT, padx=6)

        ttk.Label(rāmis, text="Šifrētais (hex):").grid(row=5, column=0, sticky="nw", pady=(8, 0))
        self.sifr_teksts = scrolledtext.ScrolledText(rāmis, height=6, width=80, font=("Courier", 10))
        self.sifr_teksts.grid(row=5, column=1, columnspan=3, sticky="we", pady=(8, 0))

        ttk.Label(rāmis, text="Informācija:").grid(row=6, column=0, sticky="nw", pady=(8, 0))
        self.sifr_info = ttk.Label(rāmis, text="—", foreground="#444")
        self.sifr_info.grid(row=6, column=1, columnspan=3, sticky="w", pady=(8, 0))

        rāmis.columnconfigure(1, weight=1)
        self._generet_atslegu()

    def _generet_atslegu(self):
        try:
            alg = izveidot_algoritmu(self.sifr_algoritms.get())
        except Exception as e:
            messagebox.showerror("Kļūda", str(e))
            return
        self.atslegas_lauks.delete("1.0", tk.END)
        self.atslegas_lauks.insert("1.0", alg.atslega.hex())
        self._statuss(f"Ģenerēta jauna {alg.nosaukums} atslēga")

    def _ielasit_algoritmu(self):
        hex_atsl = self.atslegas_lauks.get("1.0", tk.END).strip()
        try:
            atslega = bytes.fromhex(hex_atsl)
        except ValueError:
            raise ValueError("Atslēga nav derīgs hex teksts")
        return izveidot_algoritmu(self.sifr_algoritms.get(), atslega)

    def _sifret(self):
        try:
            alg = self._ielasit_algoritmu()
            dati = self.atkl_teksts.get("1.0", tk.END).rstrip("\n").encode("utf-8")
            t0 = time.perf_counter_ns()
            sifrs = alg.sifret(dati)
            laiks_us = (time.perf_counter_ns() - t0) / 1000
        except Exception as e:
            messagebox.showerror("Šifrēšanas kļūda", str(e))
            return

        self._pedejais_sifrs = sifrs
        self.sifr_teksts.delete("1.0", tk.END)
        self.sifr_teksts.insert("1.0", sifrs.hex())
        self.sifr_info.configure(
            text=f"{alg.nosaukums}: {len(dati)} B → {len(sifrs)} B "
                 f"(palielinājums {len(sifrs) / max(1, len(dati)):.3f}x, šifrēšana {laiks_us:.1f} μs)"
        )
        self._statuss("Šifrēts")

    def _atsifret(self):
        try:
            alg = self._ielasit_algoritmu()
            hex_sifrs = self.sifr_teksts.get("1.0", tk.END).strip().replace(" ", "").replace("\n", "")
            if not hex_sifrs:
                raise ValueError("Šifrētais lauks ir tukšs")
            sifrs = bytes.fromhex(hex_sifrs)
            t0 = time.perf_counter_ns()
            atsifrets = alg.atsifret(sifrs)
            laiks_us = (time.perf_counter_ns() - t0) / 1000
        except Exception as e:
            messagebox.showerror("Atšifrēšanas kļūda", str(e))
            return

        self.atkl_teksts.delete("1.0", tk.END)
        try:
            self.atkl_teksts.insert("1.0", atsifrets.decode("utf-8"))
        except UnicodeDecodeError:
            self.atkl_teksts.insert("1.0", f"<binary, {len(atsifrets)} B, hex: {atsifrets.hex()}>")
        self.sifr_info.configure(text=f"{alg.nosaukums}: atšifrēts {len(atsifrets)} B ({laiks_us:.1f} μs)")
        self._statuss("Atšifrēts")

    def _tirit_sifresanu(self):
        self.atkl_teksts.delete("1.0", tk.END)
        self.sifr_teksts.delete("1.0", tk.END)
        self.sifr_info.configure(text="—")

    # ------------------------------------------------------------------
    # Cilne: serveris
    # ------------------------------------------------------------------

    def _cilne_serveris(self, notebook: ttk.Notebook):
        rāmis = ttk.Frame(notebook, padding=12)
        notebook.add(rāmis, text="🖥 Serveris")

        ttk.Label(rāmis, text="Servera vadība", style="Virsraksts.TLabel").grid(
            row=0, column=0, columnspan=6, sticky="w", pady=(0, 10))

        ttk.Label(rāmis, text="Algoritms:").grid(row=1, column=0, sticky="w")
        self.serv_alg = tk.StringVar(value="AES-256-GCM")
        ttk.Combobox(rāmis, textvariable=self.serv_alg,
                     values=pieejamie_algoritmi(), state="readonly", width=22).grid(row=1, column=1, padx=6)

        self.serv_poga_sakt = ttk.Button(rāmis, text="▶ Palaist serveri", command=self._palaist_serveri)
        self.serv_poga_sakt.grid(row=1, column=2, padx=6)

        self.serv_poga_apturet = ttk.Button(rāmis, text="■ Apturēt", command=self._apturet_serveri, state=tk.DISABLED)
        self.serv_poga_apturet.grid(row=1, column=3, padx=6)

        ttk.Button(rāmis, text="🧹 Notīrīt log", command=lambda: self._tirit_logu(self.serv_logs)).grid(row=1, column=4, padx=6)

        self.serv_statuss = ttk.Label(rāmis, text="● Apturēts", style="Sarkanais.TLabel")
        self.serv_statuss.grid(row=1, column=5, sticky="e")

        self.serv_logs = scrolledtext.ScrolledText(rāmis, height=25, font=("Courier", 10))
        self.serv_logs.grid(row=2, column=0, columnspan=6, sticky="nsew", pady=(10, 0))

        rāmis.columnconfigure(5, weight=1)
        rāmis.rowconfigure(2, weight=1)

    def _palaist_serveri(self):
        if self.servera_process and self.servera_process.poll() is None:
            return
        komanda = [PYTHON, "-u", "serveris.py", self.serv_alg.get()]
        try:
            self.servera_process = subprocess.Popen(
                komanda, cwd=DARBA_DIR,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            messagebox.showerror("Kļūda", f"Nevar palaist serveri: {e}")
            return

        threading.Thread(
            target=self._lasit_procesa_izvadi,
            args=(self.servera_process, self.servera_rinda),
            daemon=True
        ).start()

        self.serv_poga_sakt.configure(state=tk.DISABLED)
        self.serv_poga_apturet.configure(state=tk.NORMAL)
        self.serv_statuss.configure(text="● Darbojas", style="Zalais.TLabel")
        self._statuss(f"Serveris palaists ({self.serv_alg.get()})")

    def _apturet_serveri(self):
        if self.servera_process and self.servera_process.poll() is None:
            self.servera_process.terminate()
            try:
                self.servera_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.servera_process.kill()
        self.serv_poga_sakt.configure(state=tk.NORMAL)
        self.serv_poga_apturet.configure(state=tk.DISABLED)
        self.serv_statuss.configure(text="● Apturēts", style="Sarkanais.TLabel")
        self._statuss("Serveris apturēts")

    # ------------------------------------------------------------------
    # Cilne: klients
    # ------------------------------------------------------------------

    def _cilne_klients(self, notebook: ttk.Notebook):
        rāmis = ttk.Frame(notebook, padding=12)
        notebook.add(rāmis, text="📱 Klients")

        ttk.Label(rāmis, text="Klienta vadība", style="Virsraksts.TLabel").grid(
            row=0, column=0, columnspan=6, sticky="w", pady=(0, 10))

        ttk.Label(rāmis, text="Hosts:").grid(row=1, column=0, sticky="w")
        self.kl_hosts = tk.StringVar(value="127.0.0.1")
        ttk.Entry(rāmis, textvariable=self.kl_hosts, width=15).grid(row=1, column=1, padx=(4, 12))

        ttk.Label(rāmis, text="Ports:").grid(row=1, column=2, sticky="w")
        self.kl_ports = tk.StringVar(value="9000")
        ttk.Entry(rāmis, textvariable=self.kl_ports, width=8).grid(row=1, column=3, padx=(4, 12))

        self.kl_poga_conn = ttk.Button(rāmis, text="🔌 Savienoties", command=self._klients_savienoties)
        self.kl_poga_conn.grid(row=1, column=4, padx=6)
        self.kl_poga_disc = ttk.Button(rāmis, text="✖ Atvienoties", command=self._klients_atvienoties, state=tk.DISABLED)
        self.kl_poga_disc.grid(row=1, column=5, padx=6)

        self.kl_statuss = ttk.Label(rāmis, text="● Nav savienots", style="Sarkanais.TLabel")
        self.kl_statuss.grid(row=1, column=6, sticky="e", padx=(10, 0))

        ttk.Label(rāmis, text="Ziņojums:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.kl_zinojums = tk.StringVar(value="Sveika, serveri!")
        zin_lauks = ttk.Entry(rāmis, textvariable=self.kl_zinojums)
        zin_lauks.grid(row=2, column=1, columnspan=4, sticky="we", pady=(10, 0), padx=(4, 6))
        zin_lauks.bind("<Return>", lambda e: self._klients_sutit())

        self.kl_poga_sutit = ttk.Button(rāmis, text="✉ Sūtīt", command=self._klients_sutit, state=tk.DISABLED)
        self.kl_poga_sutit.grid(row=2, column=5, pady=(10, 0))

        ttk.Button(rāmis, text="🧹 Notīrīt log",
                   command=lambda: self._tirit_logu(self.kl_logs)).grid(row=2, column=6, pady=(10, 0), padx=(10, 0))

        self.kl_logs = scrolledtext.ScrolledText(rāmis, height=22, font=("Courier", 10))
        self.kl_logs.grid(row=3, column=0, columnspan=7, sticky="nsew", pady=(10, 0))

        rāmis.columnconfigure(1, weight=1)
        rāmis.columnconfigure(6, weight=1)
        rāmis.rowconfigure(3, weight=1)

    def _klients_savienoties(self):
        hosts = self.kl_hosts.get().strip() or "127.0.0.1"
        try:
            ports = int(self.kl_ports.get())
        except ValueError:
            messagebox.showerror("Kļūda", "Nederīgs ports")
            return

        def darbs():
            try:
                klients = DrosaisKlients(hosts, ports)
                klients.savienoties()
                self.klients = klients
                self._pielikt_logam(self.kl_logs,
                                     f"[KLIENTS] Savienots ({klients.algoritms.nosaukums})")
                self.sakne.after(0, lambda: (
                    self.kl_poga_conn.configure(state=tk.DISABLED),
                    self.kl_poga_disc.configure(state=tk.NORMAL),
                    self.kl_poga_sutit.configure(state=tk.NORMAL),
                    self.kl_statuss.configure(text="● Savienots", style="Zalais.TLabel"),
                    self._statuss("Klients savienots"),
                ))
            except Exception as e:
                self._pielikt_logam(self.kl_logs, f"[KLIENTS] KĻŪDA: {e}")
                self.sakne.after(0, lambda: messagebox.showerror("Savienojuma kļūda", str(e)))

        threading.Thread(target=darbs, daemon=True).start()

    def _klients_atvienoties(self):
        if self.klients:
            try:
                self.klients.atvienoties()
            except Exception:
                pass
            self.klients = None
        self.kl_poga_conn.configure(state=tk.NORMAL)
        self.kl_poga_disc.configure(state=tk.DISABLED)
        self.kl_poga_sutit.configure(state=tk.DISABLED)
        self.kl_statuss.configure(text="● Nav savienots", style="Sarkanais.TLabel")
        self._pielikt_logam(self.kl_logs, "[KLIENTS] Atvienots")
        self._statuss("Klients atvienots")

    def _klients_sutit(self):
        if not self.klients:
            return
        teksts = self.kl_zinojums.get()
        if not teksts:
            return

        def darbs():
            try:
                rez = self.klients.nosutit(teksts)
                self._pielikt_logam(
                    self.kl_logs,
                    f"→ {teksts[:60]}\n"
                    f"  izmērs {rez['originals_izmers']} B → {rez['sifreta_izmers']} B, "
                    f"šifr {rez['sifresanas_laiks_ns']/1000:.1f} μs, "
                    f"atšifr {rez['atsifresanas_laiks_ns']/1000:.1f} μs\n"
                    f"  ← {rez['atbilde']}"
                )
            except Exception as e:
                self._pielikt_logam(self.kl_logs, f"[KLIENTS] KĻŪDA: {e}")

        threading.Thread(target=darbs, daemon=True).start()

    # ------------------------------------------------------------------
    # Cilne: lokalais veiktspejas tests
    # ------------------------------------------------------------------

    def _cilne_veiktspeja(self, notebook: ttk.Notebook):
        rāmis = ttk.Frame(notebook, padding=12)
        notebook.add(rāmis, text="⚡ Veiktspēja")

        ttk.Label(rāmis, text="Lokāls šifrēšanas bencmarks (veiktspejas_tests.py)",
                  style="Virsraksts.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        ttk.Label(rāmis,
                  text="Pilns tests uz visiem algoritmiem un datu izmēriem līdz 16 MB.\n"
                       "Tas var aizņemt vairākas minūtes atkarībā no aparatūras.",
                  foreground="#555").grid(row=1, column=0, columnspan=4, sticky="w", pady=(0, 8))

        self.bench_poga_sakt = ttk.Button(rāmis, text="▶ Palaist bencmarku", command=self._bench_sakt)
        self.bench_poga_sakt.grid(row=2, column=0, padx=(0, 6))
        self.bench_poga_aptur = ttk.Button(rāmis, text="■ Pārtraukt", command=self._bench_apturet, state=tk.DISABLED)
        self.bench_poga_aptur.grid(row=2, column=1, padx=6)
        ttk.Button(rāmis, text="📁 Atvērt rezultātu failu",
                   command=lambda: self._atvert_failu("rezultati.json")).grid(row=2, column=2, padx=6)
        ttk.Button(rāmis, text="🧹 Notīrīt log",
                   command=lambda: self._tirit_logu(self.bench_logs)).grid(row=2, column=3, padx=6)

        self.bench_logs = scrolledtext.ScrolledText(rāmis, height=28, font=("Courier", 9))
        self.bench_logs.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=(10, 0))

        rāmis.columnconfigure(3, weight=1)
        rāmis.rowconfigure(3, weight=1)

    def _bench_sakt(self):
        if self.benchmark_process and self.benchmark_process.poll() is None:
            return
        try:
            self.benchmark_process = subprocess.Popen(
                [PYTHON, "-u", "veiktspejas_tests.py"], cwd=DARBA_DIR,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            messagebox.showerror("Kļūda", str(e))
            return
        threading.Thread(
            target=self._lasit_procesa_izvadi,
            args=(self.benchmark_process, self.benchmark_rinda),
            daemon=True
        ).start()
        self.bench_poga_sakt.configure(state=tk.DISABLED)
        self.bench_poga_aptur.configure(state=tk.NORMAL)
        self._statuss("Veiktspējas bencmarks darbojas…")

    def _bench_apturet(self):
        if self.benchmark_process and self.benchmark_process.poll() is None:
            self.benchmark_process.terminate()
        self.bench_poga_sakt.configure(state=tk.NORMAL)
        self.bench_poga_aptur.configure(state=tk.DISABLED)
        self._statuss("Bencmarks apturēts")

    # ------------------------------------------------------------------
    # Cilne: tikla tests
    # ------------------------------------------------------------------

    def _cilne_tikls(self, notebook: ttk.Notebook):
        rāmis = ttk.Frame(notebook, padding=12)
        notebook.add(rāmis, text="🌐 Tīkla tests")

        ttk.Label(rāmis, text="Tīkla veiktspējas tests (tikla_tests.py)",
                  style="Virsraksts.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        ttk.Label(rāmis,
                  text="Mēra klient-serveris round-trip latentumu ar katru algoritmu un datu izmēru.",
                  foreground="#555").grid(row=1, column=0, columnspan=4, sticky="w", pady=(0, 8))

        self.tikla_poga_sakt = ttk.Button(rāmis, text="▶ Palaist tīkla testu", command=self._tikla_sakt)
        self.tikla_poga_sakt.grid(row=2, column=0, padx=(0, 6))
        self.tikla_poga_aptur = ttk.Button(rāmis, text="■ Pārtraukt", command=self._tikla_apturet, state=tk.DISABLED)
        self.tikla_poga_aptur.grid(row=2, column=1, padx=6)
        ttk.Button(rāmis, text="📁 Atvērt rezultātu failu",
                   command=lambda: self._atvert_failu("tikla_rezultati.json")).grid(row=2, column=2, padx=6)
        ttk.Button(rāmis, text="🧹 Notīrīt log",
                   command=lambda: self._tirit_logu(self.tikla_logs)).grid(row=2, column=3, padx=6)

        self.tikla_logs = scrolledtext.ScrolledText(rāmis, height=28, font=("Courier", 9))
        self.tikla_logs.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=(10, 0))

        rāmis.columnconfigure(3, weight=1)
        rāmis.rowconfigure(3, weight=1)

    def _tikla_sakt(self):
        if self.tikla_process and self.tikla_process.poll() is None:
            return
        try:
            self.tikla_process = subprocess.Popen(
                [PYTHON, "-u", "tikla_tests.py"], cwd=DARBA_DIR,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            messagebox.showerror("Kļūda", str(e))
            return
        threading.Thread(
            target=self._lasit_procesa_izvadi,
            args=(self.tikla_process, self.tikla_rinda),
            daemon=True
        ).start()
        self.tikla_poga_sakt.configure(state=tk.DISABLED)
        self.tikla_poga_aptur.configure(state=tk.NORMAL)
        self._statuss("Tīkla tests darbojas…")

    def _tikla_apturet(self):
        if self.tikla_process and self.tikla_process.poll() is None:
            self.tikla_process.terminate()
        self.tikla_poga_sakt.configure(state=tk.NORMAL)
        self.tikla_poga_aptur.configure(state=tk.DISABLED)
        self._statuss("Tīkla tests apturēts")

    # ------------------------------------------------------------------
    # Cilne: rezultatu skatitajs
    # ------------------------------------------------------------------

    def _cilne_rezultati(self, notebook: ttk.Notebook):
        rāmis = ttk.Frame(notebook, padding=12)
        notebook.add(rāmis, text="📊 Rezultāti")

        ttk.Label(rāmis, text="Saglabāto rezultātu apskate", style="Virsraksts.TLabel").grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        ttk.Button(rāmis, text="📂 Ielādēt rezultati.json",
                   command=lambda: self._ieladat_rezultatus("rezultati.json", "lokals")).grid(row=1, column=0, padx=(0, 6))
        ttk.Button(rāmis, text="📂 Ielādēt tikla_rezultati.json",
                   command=lambda: self._ieladat_rezultatus("tikla_rezultati.json", "tikls")).grid(row=1, column=1, padx=6)
        ttk.Button(rāmis, text="📂 Cits fails…", command=self._ieladat_citu).grid(row=1, column=2, padx=6)

        self.rez_info = ttk.Label(rāmis, text="—", foreground="#555")
        self.rez_info.grid(row=1, column=3, sticky="e")

        kolonnas = ("algoritms", "izmers", "sifr_us", "sifr_mbps", "atsifr_us", "atsifr_mbps", "palielinajums")
        self.rez_koks = ttk.Treeview(rāmis, columns=kolonnas, show="headings", height=25)

        galvenes = [
            ("algoritms", "Algoritms", 180),
            ("izmers", "Datu izmērs", 110),
            ("sifr_us", "Šifr. vid. (μs)", 130),
            ("sifr_mbps", "Šifr. Mbps", 120),
            ("atsifr_us", "Atšifr. vid. (μs)", 130),
            ("atsifr_mbps", "Atšifr. Mbps", 120),
            ("palielinajums", "Izm. ×", 100),
        ]
        for k, v, w in galvenes:
            self.rez_koks.heading(k, text=v)
            self.rez_koks.column(k, width=w, anchor="center")

        self.rez_koks.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=(10, 0))

        ritjosla = ttk.Scrollbar(rāmis, orient="vertical", command=self.rez_koks.yview)
        self.rez_koks.configure(yscrollcommand=ritjosla.set)
        ritjosla.grid(row=2, column=4, sticky="ns", pady=(10, 0))

        rāmis.columnconfigure(3, weight=1)
        rāmis.rowconfigure(2, weight=1)

    def _ieladat_rezultatus(self, faila_nos: str, tips: str):
        celjs = os.path.join(DARBA_DIR, faila_nos)
        if not os.path.exists(celjs):
            messagebox.showwarning("Nav faila", f"Fails nav atrasts:\n{celjs}")
            return
        try:
            with open(celjs, encoding="utf-8") as f:
                dati = json.load(f)
        except Exception as e:
            messagebox.showerror("Kļūda", f"Nevar ielasīt: {e}")
            return

        for rinda in self.rez_koks.get_children():
            self.rez_koks.delete(rinda)

        if tips == "lokals":
            for r in dati:
                self.rez_koks.insert("", tk.END, values=(
                    r["algoritms"],
                    r["datu_izmers"],
                    f"{r['sifresana']['videjais_us']:.2f}",
                    f"{r['sifresana']['caurlaidspeja_mbps']:.1f}",
                    f"{r['atsifresana']['videjais_us']:.2f}",
                    f"{r['atsifresana']['caurlaidspeja_mbps']:.1f}",
                    f"{r['izmera_palielinajums']:.3f}",
                ))
        else:
            for r in dati:
                izm = r["datu_izmers_baiti"]
                izm_str = f"{izm} B" if izm < 1024 else f"{izm // 1024} KB" if izm < 1048576 else f"{izm // 1048576} MB"
                self.rez_koks.insert("", tk.END, values=(
                    r["algoritms"], izm_str,
                    f"{r['videjais_latentums_us']:.1f}",
                    f"med {r['mediana_us']:.1f}",
                    f"p95 {r['p95_us']:.1f}",
                    f"p99 {r['p99_us']:.1f}",
                    f"σ {r['std_us']:.1f}",
                ))

        self.rez_info.configure(text=f"{faila_nos}: {len(dati)} ieraksti")
        self._statuss(f"Ielādēts {faila_nos}")

    def _ieladat_citu(self):
        celjs = filedialog.askopenfilename(
            initialdir=DARBA_DIR,
            filetypes=[("JSON faili", "*.json"), ("Visi faili", "*.*")]
        )
        if not celjs:
            return
        # Noskaidrot tipu pec satura
        try:
            with open(celjs, encoding="utf-8") as f:
                dati = json.load(f)
            tips = "lokals" if dati and "sifresana" in dati[0] else "tikls"
        except Exception as e:
            messagebox.showerror("Kļūda", str(e))
            return
        self._ieladat_rezultatus(os.path.basename(celjs), tips)

    # ------------------------------------------------------------------
    # Palidz funkcijas
    # ------------------------------------------------------------------

    def _lasit_procesa_izvadi(self, process: subprocess.Popen, rinda: queue.Queue):
        try:
            for rindina in iter(process.stdout.readline, ""):
                rinda.put(rindina)
        finally:
            process.stdout.close()
            rinda.put(None)

    def _atjaunot_logus(self):
        # Serveris
        self._plusot_rindu(self.servera_rinda, self.serv_logs, self._servera_beidzies)
        # Benchmark
        self._plusot_rindu(self.benchmark_rinda, self.bench_logs, self._benchmarka_beidzies)
        # Tikla tests
        self._plusot_rindu(self.tikla_rinda, self.tikla_logs, self._tikla_testa_beidzies)
        self.sakne.after(100, self._atjaunot_logus)

    def _plusot_rindu(self, rinda: queue.Queue, logs: scrolledtext.ScrolledText, beigu_callback):
        try:
            while True:
                gabals = rinda.get_nowait()
                if gabals is None:
                    beigu_callback()
                else:
                    self._pielikt_logam(logs, gabals.rstrip("\n"))
        except queue.Empty:
            pass

    def _servera_beidzies(self):
        self.serv_poga_sakt.configure(state=tk.NORMAL)
        self.serv_poga_apturet.configure(state=tk.DISABLED)
        self.serv_statuss.configure(text="● Apturēts", style="Sarkanais.TLabel")

    def _benchmarka_beidzies(self):
        self.bench_poga_sakt.configure(state=tk.NORMAL)
        self.bench_poga_aptur.configure(state=tk.DISABLED)
        self._statuss("Veiktspējas bencmarks pabeigts")

    def _tikla_testa_beidzies(self):
        self.tikla_poga_sakt.configure(state=tk.NORMAL)
        self.tikla_poga_aptur.configure(state=tk.DISABLED)
        self._statuss("Tīkla tests pabeigts")

    def _pielikt_logam(self, logs: scrolledtext.ScrolledText, teksts: str):
        logs.configure(state=tk.NORMAL)
        logs.insert(tk.END, teksts + "\n")
        logs.see(tk.END)

    def _tirit_logu(self, logs: scrolledtext.ScrolledText):
        logs.delete("1.0", tk.END)

    def _atvert_failu(self, faila_nos: str):
        celjs = os.path.join(DARBA_DIR, faila_nos)
        if not os.path.exists(celjs):
            messagebox.showwarning("Nav faila", f"{faila_nos} vēl neeksistē — palaidiet bencmarku vispirms.")
            return
        if sys.platform == "darwin":
            subprocess.Popen(["open", celjs])
        elif sys.platform.startswith("win"):
            os.startfile(celjs)
        else:
            subprocess.Popen(["xdg-open", celjs])

    def _statuss(self, teksts: str):
        self.statusa_mainigais.set(teksts)

    def _aizvert(self):
        for p in (self.servera_process, self.benchmark_process, self.tikla_process):
            if p and p.poll() is None:
                p.terminate()
        if self.klients:
            try:
                self.klients.atvienoties()
            except Exception:
                pass
        self.sakne.destroy()


def main():
    sakne = tk.Tk()
    SaskarneGUI(sakne)
    sakne.mainloop()


if __name__ == "__main__":
    main()
