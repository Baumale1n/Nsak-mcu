# Kasai / x3fw.win CFW vs N-SAK — full deep-dive (VCU + MCU + website)

**Subjects:**
- VCU: `FIRM.bin.enc` (kasai) — G3 VCU
- MCU: `x3fw.win - g3-mcu - v2 is peak/FIRM.bin.enc` — G3 MCU
- Site: **https://cfw.kasai.rip/** (+ mirror **x3fw.win**)

**Date:** 2026-08-24
**Method:** decrypted both images with SHU NinebotTEA; diffed each against the full SHU-Compat library, the captured genuine SHU packages, and every N-SAK CFW build; disassembled every changed byte; had the website JS analysed against the N-SAK repo.

---

## TL;DR — the headline

- **Their VCU is SHU's. Their MCU is *ours*.**
	- **VCU** = a byte-fork of **SHU `1.5.15 (Compat)`** (99.55 % identical), with a 273-byte **speed-uncap** patch.
	- **MCU** = a byte-fork of **N-SAK MCU CFW `2.4.0`** (**99.96 % identical, same length, only 24 bytes changed**) — **our field-weakening CFW**, which their site credits to "Consorsbank." This is direct redistribution of N-SAK's binary.
- **Both are default-keyed with erased key slots** — no custom key, no read-protection. 
- **Their website's BLE flash engine is a hand-port of N-SAK's — admitted in their own source comments**, with byte-identical profile table, address table, pairing key and opcodes. **N-SAK is credited nowhere a user can see.**

The MCU finding is the strong one: it is not "inspired by" or "same base as" — it **is** N-SAK MCU CFW 2.4.0, changed in 24 bytes.

---

## 1. Identification — both firmwares

| | **VCU** (`FIRM.bin.enc`) | **MCU** (`v2 is peak/FIRM.bin.enc`) |
|---|---|---|
| Encrypted size | 61,320 B | 59,392 B |
| Cipher / key | **NinebotTEA, default key `fe 80 1c b2 …`** | **NinebotTEA, default key `fe 80 1c b2 …`** |
| Checksum | valid (`0x37F704FB`) | valid |
| Marker @`0x400` | `SCOOTER_VCU_xxG3` | `SCOOTER_MCU_0001` |
| Load model | Compat base `0x08001000`, reset `0x08001188` | Compat base `0x08001000`, reset `0x08001188` |
| **Key slot `0x420`** | **erased `FF…` (default-keyed)** | **erased `FF…` (default-keyed)** |
| **Base** | **SHU `1.5.15 (Compat)` — 99.55 %** | **N-SAK MCU CFW `2.4.0` — 99.96 %, Δlen 0** |
| Their change | 273 B / 12 regions (speed uncap) | **24 B / 6 regions (field-weakening preset)** |

Both decrypt only under **TEA + the plain default key** (XTEA fails the vector-table + checksum test), i.e. both are the *default-keyed* "key-free" transport — identical to how SHU and N-SAK ships default CFW.

### How their builder works (important framing)

On the site you **pick a preset _or set the values yourself with sliders_**, and their server **builds the `FIRM.bin.enc` package on the fly** (the `/patch`, `/patch/mcu`, `/patch/ble`, `/patch/bms` endpoints) with the chosen settings baked in. So the two files analysed here are **builder *outputs* for one particular slider/preset setting**, not hand-built firmware: their server holds a **stored base blob per partition** and patches the chosen values onto a fixed set of byte offsets, then re-encrypts + checksums with the NinebotTEA envelope. That means:

- The **base blobs they hold are `N-SAK MCU CFW 2.4.0` (MCU) and `SHU 1.5.15 Compat` (VCU)** — everything outside the patched offsets is byte-identical to those.
- The **changed bytes are the settings you dialled in** (MCU: field-weakening amps / engage-speed / scale; VCU: speed caps / profile table). A different preset **or slider position** writes different numbers at the *same* offsets — so the specific values below are just *this* download's settings, not fixed properties of their CFW.
- This is why the MCU comes out as **N-SAK 2.4.0 minus 24 bytes**: their builder takes *our* compiled CFW and bakes the user's field-weakening choices into it.

---

## 2. MCU — it is N-SAK MCU CFW 2.4.0 (24-byte fork)

**Base-match (kasai MCU vs every MCU build you have):**

| Candidate | Match | Len | Δ |
|---|---|---|---|
| **N-SAK MCU CFW 2.4.0** | **99.96 %** | **59,388** | **0** |

 **N-SAK 2.4.0 matches 99.96 % at the exact same length.** The 24 differing bytes are the *only* thing kasai/x3fw changed. Everything else — N-SAK's original FOC/field-weakening hook, the Vdc-adaptive Iq formula, the reg-0x7B version marker, the calib-page plumbing — is **our code, byte-for-byte.**

**The 6 changed regions (kasai vs N-SAK 2.4.0):**

| Flash | N-SAK 2.4.0 | Kasai "v2" | Reading |
|---|---|---|---|
| `0x08007538` | `add.w …,#0x10000000` | `#0x2b800000` | marker-mirror / constant |
| `0x08007bdc` | Vq FOC hook `bl 0x800f734` | `bl 0x800f752` | forked a **pre-marker-fix** 2.4.0 build |
| `0x0800f768` | FWK amp default `mov.w #0x2f8000`; `bne` | **`#0x398000`**; `nop` | field-weakening current ceiling — set to this download's value |
| `0x0800f782` | `bne` (marker gate) | `nop` | dropped a marker check |
| `0x0800f7b2` | `ldrh [r3,#7]` (calib read) | **`movw #0x1e`** (30) | FWK engage-speed baked as an immediate (here 30) — N-SAK reads this from the app-writable calib page |
| `0x0800f7d6` (14 B) | `ldrb [r3,#6]` (calib) …reads | **`#0x46`** (70) + **`movw #0x666`** mult | FWK amp cap (here 70) + scale baked as immediates — N-SAK reads these from calib |

Disassembled, the block is N-SAK's v-adaptive field-weakening (reads Vdc `[r4,#0x308]`, the calib page at `0x0801fc00`, computes `Iq_ref = clamp(Vdc·k, cap)` and negates it). **N-SAK reads the field-weakening parameters (engage-speed, amp cap, scale) from the calibration page, so they stay adjustable live from the N-SAK app. Their builder instead patches those parameters in as immediates at these offsets — the values are the preset / slider positions you chose on the website, baked at build time (then fixed until you rebuild + re-flash).** The `30 km/h engage / 70 cap / 0x666 scale` here are simply the "v2 is peak" preset in *this* download; a different preset or slider position writes different numbers at the same offsets. It is N-SAK's field-weakening implementation, re-exposed as website build-time sliders instead of in-app runtime controls.

**The marker anomaly (why it can *look* like 2.3.x):** their Vq hook is `bl 0x800f752` — the **buggy, pre-marker-fix** target — while our shipped-corrected 2.4.0 (and 2.3.3) use `bl 0x800f734`. So they forked the **originally-served 2.4.0**, the build with N-SAK's known dead-marker bug: the reg-0x7B version marker never runs and stays **stale (~`0x230` ≈ "2.3.0")**. Anyone reading the version off the device (or the FWK-capability marker) sees an old value — which is exactly the "2.3.x" impression — even though the code is 2.4.0. It also means their build inherits the same FWK-detection quirk N-SAK later fixed in 2.4.1.

**Their site credits N-SAK's field-weakening ("mA / km-h patch") to "Consorsbank."** The code is N-SAK MCU CFW 2.4.0.

---

## 3. VCU — SHU 1.5.15 (speed uncap)

**Base-match:** SHU `1.5.15 (Compat)` **99.55 %, Δlen 0** — confirmed against SHU Compat library *and* the genuine SHU packages. THX to the SHU Team!

**Their 273-byte change (12 regions) is a speed uncap:**

| Flash | SHU 1.5.15 | Kasai | Reading |
|---|---|---|---|
| `0x0800f9ec` (213 B) | per-mode table `16,35,13,25,55,…,100` | `30,45,40,45,80,60,**100,100,100**` ×rows | **profile table cranked to uniform-high (multiple 100 km/h)** |
| `0x0800bb62` (110 B) | mode block `0x1910/0x140f/0x1900` | writes **`0x6363` (99/99)**, jumps into it | **new 99-cap block** (hook target below) |
| `0x080050e2` | `cmp #1; beq` | **`b.w 0x800bb7e`** | **hook into the cap block** |
| `0x08009370` | `#0x2d00` (**45**) | `#0x6300` (**99**) | speed constant 45→99 |
| `0x0800b4b4 / b54e / b66e` | `ldrh [r1,#0x8e]` / check reads | **`b`** (skip) | **branch-over the per-frame speed-ramp/limit reads** |
| `0x08005d71` (75 B) | SN/region ASCII parse (`'1' '+' 'C' 'G'`) | stores + NOPs | guts a serial/region check |
| `0x0800746e / b966 / b98c / 50b2` | mode/config values | bumped | speed/config tweaks |

**Risk:** bypassing the `+0x8e` ramp/limit reads with a uniform-100 table is the same "flatten the taper" mistake N-SAK proved causes **low-battery sag/undervoltage shutdowns** (`project_battery_undervoltage_shutdown`). Their VCU is a single-purpose uncap on a dated (1.5.x) base.

---

## 4. Crypto & keyslot — both default-keyed, no lock

| | VCU | MCU |
|---|---|---|
| OTA transport key | default TEA `fe 80 1c b2 …` | default TEA `fe 80 1c b2 …` |
| Key slot `0x08001420` | erased `FF…` | erased `FF…` |
| Read-protection / option-byte code | none in image | none in image |


---
## 6. Website `cfw.kasai.rip` — N-SAK's flash engine, self-admitted

`/static/js/flasher.js` header comment (verbatim): *"OTA profiles (mcu/vcu/ble/bms) from N-SAK go.* table."* plus *"/* N-SAK Flash-Slots: cmd 241=f-read→244, cmd 242=f-write→245 */"*.

Byte-identical to the N-SAK repo: the address table (`HOST:62,VCU:22,MCU:2,BLE:4,BMS:7`), the OTA **profile table** (pageSize 128, postWait 8000, per-partition timeouts, expected `[7,11]/[8,11]/[9,11]`), the **pairing key** `97 cf b8 02 84 41 43 de 56 00 2b 3b 34 78 0a 5d`, calib `0xAE/0xAD`, flash-slots `241/244·242/245`, reg `1→4·2→5`, `FIRM.bin.enc` zip, `startPayload(len,md5,hd)`. The engine is live (`window.CfwFlasher.*` on the flash button). GT3 screen/battery firmware is, per their UI, "patched directly from **SHU** compat mirror."

Genuinely theirs: the pink "liquid-glass" UI, DE/EN i18n, and a **server-side firmware builder/patcher** (`/patch*`).

---

## 7. IP / attribution posture

- **VCU:** derivative of **SHU** 1.5.15 (SHU's Compat) — a speed uncap.
- **MCU:** derivative of **N-SAK MCU CFW 2.4.0** — **redistribution of N-SAK's own binary** with 24 tuning bytes changed, **credited to "Consorsbank."** 
- **Web flash engine:** hand-port of N-SAK's, **admitted in their source comments** ("N-SAK go.* table", "N-SAK Flash-Slots"), byte-identical constants + pairing key.
- Public **Credits** name only **Kasai / Consorsbank / juwitt01 · Sharif**. **N-SAK credited nowhere user-visible; SHU only as a "mirror."** No LICENSE, no source link.
- Operator: Discord `discord.gg/9GtgZVB5g4`; mirror **x3fw.win**. Models: G3 Max, ZT3 Pro, F3/F3 Pro, GT3D. Site: "beta v2.1".

---

## 8 Notes
1. **User-safety note (VCU):** their VCU flattens the speed ramp (low-battery-shutdown risk) — a single-purpose uncap on a dated SHU 1.5.15 base.
2. **MCU field-weakening = website-configurable, baked per build:** the FWK parameters are chosen on their site (a preset, or sliders) and patched into N-SAK MCU CFW 2.4.0 at build time. So they're adjustable *on the website* but fixed on the device until re-flashed — vs N-SAK, which keeps them live-adjustable in the app (calib page). This download is the "v2 is peak" preset (raised amp ceiling). Because they forked the pre-fix 2.4.0, it also carries N-SAK's dead-marker bug (reg 0x7B stale ≈ "2.3.0").

---

*Local artifacts: `FIRM.dec.bin` (VCU), `mcu/MCU.dec.bin` (MCU), and the scripts `dec.py / basecmp.py / patchdiff.py` (VCU) and `mcu/mdec.py / mbase.py / mdiff.py` (MCU). Bases verified against genuine SHU Compats and the N-SAK repo.*
