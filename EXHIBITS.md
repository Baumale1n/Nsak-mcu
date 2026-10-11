# EXHIBITS — cfw.kasai.rip / x3fw.win copying of N-SAK (and SHU)

**Collected:** 2026-08-24T12:54:17Z (UTC) · 14:54 CEST
**Collector:** N-SAK owner (Hitcher99)
**Sources:** `https://cfw.kasai.rip/` and mirror `https://x3fw.win/` (public, unauthenticated GET); local N-SAK repository at `/DEV_Env/ninebot-fws`.
**Method:** `curl` byte-exact download (HTTP headers preserved per file); firmware decrypted with N-SAK's own cipher and diffed against the SHU-Compat library + genuine captured SHU packages + every N-SAK CFW build. SHA-256 of every artifact in `MANIFEST.sha256`.

> The two sites serve a **byte-identical** `flasher.js` (SHA-256 match — see manifest), confirming one shared codebase/operator.

---

## Exhibit A — Written admission in their own source

**File:** `website/flasher.js` (cfw.kasai.rip) — identical copy at `website/x3fw.win/static_js_flasher.js`.

- **Lines 1-5 (header):**
  ```
  /* ============================================================
     flasher.js — BLE OTA flasher for kasai's cfw builder
     Pairing/session stack aligned with working neinbot.html.
     OTA profiles (mcu/vcu/ble/bms) from N-SAK go.* table.
     ============================================================ */
  ```
- **Line 18:** `/* ---- Nbc pairing/session crypto (matches working neinbot.html) ---- */`
- **Line 368:** `/* N-SAK Flash-Slots: cmd 241=f-read→244, cmd 242=f-write→245 */`
- **Line 388:** `/* ---- OTA profiles (N-SAK go.*) ---- */`

These are the operators' own comments naming **N-SAK** as the source of the OTA profiles and flash-slot commands.

---

## Exhibit B — Byte-identical constants (objective corroboration)

Each row: the archived kasai line vs the N-SAK repo source.

| # | Element | Kasai `flasher.js` | N-SAK source | Match |
|---|---|---|---|---|
| B1 | Ninebot address table | L9 `var X={HOST:62,VCU:22,MCU:2,BLE:4,BMS:7};` | `apps/n-sak/src/protocol/framing.ts` L3-11 `VCU:0x16, MCU:0x02, BLE:0x04, BMS:0x07, HOST:0x3e` (0x16=22, 0x3e=62) | identical values |
| B2 | BLE pairing/app key | L19 `var Bo=Uint8Array.of(151,207,184,2,132,65,67,222,86,0,43,59,52,120,10,93);` | `apps/n-sak/src/crypto/nbcrypto.ts` L11 `0x97,0xcf,0xb8,0x02,0x84,0x41,0x43,0xde,…` (151=0x97, 207=0xcf, 184=0xb8, 2, 132=0x84, 65=0x41, 67=0x43, 222=0xde, 86=0x56, 0, 43=0x2b, 59=0x3b, 52=0x34, 120=0x78, 10=0x0a, 93=0x5d) | **byte-identical 16-byte key** |
| B3 | OTA profile table | L390-393 `ble:{pageSize:128,hd:true,postWaitMs:8000,pageTimeoutMs:5000,startTimeoutMs:5000,interPageDelayMs:0,startExpected:[7,11],pageExpected:[8,11],csExpected:[9,11]}`, `vcu:{…pageTimeoutMs:2000…}`, `mcu/bms:{…pageTimeoutMs:6000,startTimeoutMs:9000,interPageDelayMs:15…}` | `apps/n-sak/src/features/flash.ts` L56-96 `PROFILES` — pageSize 128; BLE hd:true only; postWait 8000; per-partition timeouts 5000/2000/6000/6000; start 5000/5000/9000/9000; interPage 0/0/15/15; expected `[0x07,0x0b]/[0x08,0x0b]/[0x09,0x0b]` | **every constant identical** |
| B4 | Non-obvious `0x0b` alt-ACK | `csExpected:[9,11]` (11 = 0x0b) | N-SAK content-signature accept code `0x0b` | copied (not a documented Ninebot value) |
| B5 | Flash-slot opcodes | L370-378 read `cmd:241 → expectedCmd:244`; write `cmd:242 → expectedCmd:245` | `apps/n-sak/src/features/tuning.ts` L4-7 `0xF1 read→0xF4`, `0xF2 write→0xF5` (241/244/242/245) | identical |
| B6 | Calibration opcodes | L357-365 read `cmd:174` (0xAE), write `cmd:173` (0xAD), `data=uint16LE(len)` | `apps/n-sak/src/features/calibPage.ts` L6-9/70-76 `cmd 0xAE` read / `0xAD` write, `data=uint16LE(len)` | identical |
| B7 | Frame codec | L15-16 `Ia/La`: header `t[0]=0x5A;t[1]=0xA5;…src,dst,cmd,arg,data` | N-SAK `protocol/framing.ts` 5A A5 framing | identical wire format |
| B8 | Firmware container | index.html extracts `FIRM.bin.enc` from a zip (client) / server returns same | `apps/n-sak/src/firmware/zip3Parser.ts` ALLOWED_NAMES incl. `FIRM.bin.enc` | same container |

---

## Exhibit C — The MCU firmware **is** N-SAK MCU CFW 2.4.0

**File:** `firmware/MCU_FIRM.bin.enc` (from `x3fw.win – g3-mcu – v2 is peak`), decrypted → `firmware/MCU_FIRM.dec.bin`.

- Decrypts under N-SAK's **default TEA key** `fe 80 1c b2 …`; envelope checksum valid; marker `SCOOTER_MCU_0001`; key slot `0x08001420` erased.
- **Base match: N-SAK MCU CFW 2.4.0 — 99.96 % identical, identical length (59,388 B), only 24 differing bytes.** (SHU MCU Compats match ≤15 %.)
- The 24 bytes are the **field-weakening settings** the user dialled in on the site (a preset, or sliders), baked into N-SAK's binary at build time: FW amp ceiling `0x2f8000→0x398000`; engage-speed `0x1e` (30) and amp cap `0x46` (70) patched in as immediates where N-SAK 2.4.0 reads them live from the app-writable calib page; scale mult `0x666`. This download is the "v2 is peak" preset; a different preset/slider writes different numbers at the same offsets.
- **Base = 2.4.0, not 2.3.3:** N-SAK's field-weakening block (`0x0e730–0x0e800`) differs from 2.3.3 by 170 B; kasai matches 2.4.0 there (22-B diff) and differs from 2.3.3 by the full 170 — i.e. it *contains* the 2.4.0 FWK code 2.3.3 lacks. Their Vq hook `bl 0x800f752` is the pre-marker-fix build, so reg-0x7B reports stale (~"2.3.0") on-device even though the code is 2.4.0.
- **Their site publicly credits this field-weakening ("mA / km-h patch") to "Consorsbank."** The implementation is N-SAK's v-adaptive FWK (`build_mcu_2.4.0_fwk_vadapt.py`), verbatim except the settings baked into those offsets.
- Reproduce: `analysis/mdec.py` (decrypt), `analysis/mbase.py` (base match), `analysis/mdiff.py` (the 6-region disasm).

---

## Exhibit D — The VCU firmware is SHU 1.5.15 (Compat), speed-uncap preset

**File:** `firmware/VCU_FIRM.bin.enc` (cfw.kasai.rip), decrypted → `firmware/VCU_FIRM.dec.bin`.

- Decrypts under the same default TEA key; marker `SCOOTER_VCU_xxG3`; key slot erased.
- **Base match: SHU `1.5.15 (Compat)` — 99.55 %, identical length (61,316 B)** — confirmed against the genuine SHU Compat from our Friends at Scooterhacking.org  273 bytes changed = a speed-uncap preset (profile table → uniform-high incl. multiple 100 km/h; caps → 99; several per-frame ramp reads branched over).
- Reproduce: `analysis/dec.py`, `analysis/basecmp.py`, `analysis/patchdiff.py`.

---

## Exhibit E — Attribution (as published)

- Public **Credits** panel (index.html): **Kasai** (project lead), **Consorsbank** ("BLE flashing support and the mA/km/h field-weakening patch"), **juwitt01 · Sharif** ("reverse-engineering assistance"). **N-SAK is not named anywhere user-visible.** SHU appears only as a firmware "mirror."
- No LICENSE, no source link on either site.
- Operator contact: Discord `discord.gg/9GtgZVB5g4`. Mirror: `x3fw.win` (serves the identical `flasher.js`).

---

## Summary of the claim

1. **Written admission** (Exhibit A) — their own source names "N-SAK go.* table" and "N-SAK Flash-Slots".
2. **Objective corroboration** (Exhibit B) — byte-identical address table, OTA profile table, pairing key and opcodes.
3. **Compiled-binary redistribution** (Exhibit C) — their MCU firmware is N-SAK MCU CFW 2.4.0 (99.96 %), with N-SAK's field-weakening credited to a third party.
4. **Removed attribution** (Exhibit E) — N-SAK credited nowhere public.

Provenance and integrity of every file above are fixed by `MANIFEST.sha256`.
