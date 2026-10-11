# Evidence bundle — cfw.kasai.rip / x3fw.win vs N-SAK

**Prepared:** 2026-08-24 (collection timestamp 2026-08-24T12:54:17Z / 14:54 CEST)
**Prepared for:** N-SAK owner (Hitcher99)
**Purpose:** preserve, byte-exact and hash-fixed, the evidence that cfw.kasai.rip / x3fw.win copied N-SAK's BLE flash engine and redistributes N-SAK's compiled MCU CFW, plus SHU-sourced firmware.

## What's inside

```
KASAI_EVIDENCE_2026-08-24/
├── README_EVIDENCE.md          ← this file
├── EXHIBITS.md                 ← the side-by-side proof (A–E), with exact line refs
├── KASAI_vs_NSAK_REPORT.md     ← full technical report (VCU + MCU + website)
├── MANIFEST.sha256             ← SHA-256 of every file below (integrity/provenance)
├── website/                    ← byte-exact site capture (curl), HTTP headers kept
│   ├── flasher.js              ← THE key file (N-SAK flash-engine port; admission comments)
│   ├── cfw.kasai.rip_index.html
│   ├── static_js_liquid-glass.js, static_style.css
│   ├── *.headers.txt           ← the HTTP response headers for each fetch
│   └── x3fw.win/               ← the mirror (identical flasher.js)
├── firmware/
│   ├── MCU_FIRM.bin.enc / .dec.bin   ← "v2 is peak" MCU (= N-SAK MCU CFW 2.4.0, 99.96%)
│   └── VCU_FIRM.bin.enc / .dec.bin   ← VCU (= SHU 1.5.15 Compat, 99.55%)
└── analysis/                   ← the exact scripts used (reproducible)
    ├── dec.py basecmp.py patchdiff.py      (VCU)
    └── mdec.py mbase.py mdiff.py           (MCU)
```

## How it was collected

- **Website:** `curl -sS -D <headers> -o <file> <url>` against the public, unauthenticated sites `https://cfw.kasai.rip/` and `https://x3fw.win/`. No login, no scraping of non-linked resources, GET only. Response headers are preserved alongside each file (`*.headers.txt`) for date/server provenance. `cfw.kasai.rip/static/js/flasher.js` and `x3fw.win/static/js/flasher.js` are byte-identical (equal SHA-256 in the manifest).
- **Firmware:** the two `FIRM.bin.enc` files supplied by the owner (the VCU from cfw.kasai.rip, the MCU labelled "x3fw.win – g3-mcu – v2 is peak"). Decrypted locally with N-SAK's own NinebotTEA implementation (default key), verified by exact envelope-checksum round-trip and a valid ARM vector table.
- **Base identification:** each decrypted image was byte-compared against the full SHU-Compat library, the **genuine SHU packages captured from the SHU app** (`captures/phase0/02-shu-flash-latest/…/firmware-package-g3.zip`), and every N-SAK CFW build in the repo.

## How to verify (independently)

1. **Integrity:** `shasum -a 256 -c MANIFEST.sha256` (run inside the bundle) — all files must report `OK`.
2. **Re-fetch the site** and compare: `curl -s https://cfw.kasai.rip/static/js/flasher.js | shasum -a 256` should equal the `website/flasher.js` hash in the manifest (until they change the site — hence this archive).
3. **Reproduce the firmware findings** (needs Python 3 + `capstone`, and the N-SAK repo for the reference builds):
   - VCU: `python3 analysis/dec.py`, `analysis/basecmp.py`, `analysis/patchdiff.py`
   - MCU: `python3 analysis/mdec.py`, `analysis/mbase.py`, `analysis/mdiff.py`
   (Paths inside the scripts point at the original working copy; adjust if run elsewhere.)

## Key conclusions (see EXHIBITS.md for the proof)

- Their **web flash engine is a hand-port of N-SAK's** — admitted in their own comments ("OTA profiles … from N-SAK go.* table", "N-SAK Flash-Slots") and corroborated by a byte-identical address table, OTA profile table, pairing key and opcodes.
- Their **MCU firmware is N-SAK MCU CFW 2.4.0** (99.96 %, 24-byte preset overlay); their site credits N-SAK's field-weakening to "Consorsbank."
- Their **VCU firmware is SHU 1.5.15 (Compat)** with a speed-uncap preset.
- **N-SAK is credited nowhere on either public site.**

