# Drošas komunikācijas prototips

Bakalaura darba prototips, kas demonstrē un salīdzina dažādu simetrisko šifrēšanas algoritmu veiktspēju klient-serveris arhitektūrā.

## Apraksts

Prototips realizē TCP klient-serveris sistēmu ar pilnībā šifrētu datu pārraidi un nodrošina rīkus algoritmu veiktspējas salīdzināšanai gan lokāli (tīrs kriptogrāfijas darbs), gan tīklā (latentums end-to-end).

### Atbalstītie šifrēšanas algoritmi

- **AES-128-GCM** — 128 bitu atslēga, autentificēta šifrēšana
- **AES-256-GCM** — 256 bitu atslēga, autentificēta šifrēšana
- **ChaCha20-Poly1305** — 256 bitu atslēga, autentificēta šifrēšana
- **3DES-CBC** — 192 bitu atslēga, ar PKCS7 papildinājumu (salīdzinājumam, mantotais algoritms)

## Projekta struktūra

| Fails | Apraksts |
|-------|----------|
| [crypto_engine.py](crypto_engine.py) | Šifrēšanas dzinis ar visu algoritmu implementācijām |
| [serveris.py](serveris.py) | TCP serveris ar šifrēšanas atbalstu |
| [klients.py](klients.py) | TCP klients, kas savienojas ar serveri |
| [veiktspejas_tests.py](veiktspejas_tests.py) | Lokālie šifrēšanas/atšifrēšanas veiktspējas testi |
| [tikla_tests.py](tikla_tests.py) | Tīkla latentuma testi ar šifrēšanu |
| [saskarne_web.py](saskarne_web.py) | Grafiskā saskarne (web, palaižas pārlūkā) |
| [rezultati.json](rezultati.json) | Lokālo testu rezultāti |
| [tikla_rezultati.json](tikla_rezultati.json) | Tīkla testu rezultāti |

## Prasības

- Python 3.10 vai jaunāks
- `cryptography` bibliotēka

### Instalācija

```bash
pip install cryptography
```

## Lietošana

### 1. Grafiskā saskarne (ieteicams)

Visvienkāršākais veids — palaist web saskarni, kura apvieno visas funkcijas vienā logā:

```bash
python saskarne_web.py
```

Pārlūks atvērsies automātiski (parasti `http://127.0.0.1:8765`).

Sadaļas:
- **Šifrēšana** — manuāla teksta šifrēšana/atšifrēšana
- **Serveris** — servera palaišana un apturēšana
- **Klients** — savienošanās ar serveri un ziņojumu sūtīšana
- **Veiktspēja** — lokālo testu palaišana
- **Tīkls** — tīkla testu palaišana
- **Rezultāti** — saglabāto rezultātu apskate

### 2. Klient-serveris no komandrindas

**Servera palaišana** (vienā terminālī):

```bash
# Pec noklusejuma izmanto AES-256-GCM
python serveris.py

# Vai ar izveletu algoritmu
python serveris.py AES-128-GCM
python serveris.py ChaCha20-Poly1305
python serveris.py 3DES-CBC
```

Serveris klausās uz `127.0.0.1:9000` un, klientam pieslēdzoties, automātiski nosūta tam izvēlēto algoritmu un sesijas atslēgu.

**Klienta palaišana** (otrā terminālī):

```bash
python klients.py
```

Pēc savienošanās var ievadīt ziņojumus, kas tiks šifrēti un nosūtīti serverim. Klients izvada šifrēšanas, nosūtīšanas un atšifrēšanas laikus mikrosekundēs. Lai izietu, ievadiet `iziet`.

### 3. Veiktspējas testi

**Lokāli šifrēšanas testi** (mēra tīru kriptogrāfijas algoritma ātrumu ar dažādiem datu apjomiem no 64 B līdz 16 MB):

```bash
python veiktspejas_tests.py
```

Rezultāti tiek saglabāti failā `rezultati.json`.

**Tīkla testi** (mēra end-to-end latentumu, ietverot šifrēšanu, pārraidi un atšifrēšanu):

```bash
python tikla_tests.py
```

Rezultāti tiek saglabāti failā `tikla_rezultati.json`.

## Mērītie rādītāji

Lokālajos testos:
- Šifrēšanas un atšifrēšanas laiks (µs)
- Caurlaidspēja (Mbps)
- Mediāna, p95, p99, min, max, standartnovirze
- Šifrētā teksta izmēra palielinājums

Tīkla testos:
- Pilna apļa latentums (klient → serveris → klients)
- Mediāna, p95, p99

## Programmatiskā lietošana

```python
from crypto_engine import izveidot_algoritmu

# Izveidot algoritmu ar automatiski generetu atslegu
alg = izveidot_algoritmu("AES-256-GCM")

# Sifret
dati = b"Slepens zinojums"
sifretie = alg.sifret(dati)

# Atsifret
atsifretie = alg.atsifret(sifretie)
assert atsifretie == dati
```

## Konteksts

Šis prototips izstrādāts bakalaura darba ietvaros, lai praktiski salīdzinātu mūsdienu (AES-GCM, ChaCha20-Poly1305) un mantotos (3DES-CBC) simetriskās šifrēšanas algoritmus gan no veiktspējas, gan no izmantojamības viedokļa drošā komunikācijas sistēmā.
