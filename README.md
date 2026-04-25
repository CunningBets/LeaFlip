# LeaFlip

A [Flipper Zero](https://flipperzero.one/) app that reads and verifies **LEAF Verified** Open Application cards over NFC (ISO 14443-4 / NXP MIFARE DUOX). Built as a companion / hardware port of the official LEAF reference reader.

> Disclaimer: All code in this project was written by AI (GitHub Copilot / Claude Opus 4.7 & Sonnet 4.6) and tested by a human.

## What it does

LeafFlip executes the full LEAF Open Application authentication flow on the Flipper Zero:

1. **SELECT** the LEAF Open Application AID
2. **READ** the on-card X.509 device certificate
3. **VERIFY** the certificate against the embedded **LEAF Root CA** public key (ECDSA P-256 / SHA-256)
4. **INTERNAL AUTHENTICATE** with a fresh 16-byte challenge
5. **VERIFY** the card's ECDSA signature over `challenge || card_random` using the certified device public key

If every step passes, the 12-digit **Open ID** is extracted from the certificate's Subject and shown on screen — proving the card is a genuine LEAF-issued credential.

This implementation is based on the official LEAF reference Python reader:

> **Reference:** [LEAF-Community/leaf-verified-device-onboarding-guide](https://github.com/LEAF-Community/leaf-verified-device-onboarding-guide) — `detect_and_select.py` and `PROTOCOL_GUIDE.md`.

The cryptographic verification uses **mbedTLS**, which ships with the Flipper firmware. The LEAF Root CA P-256 public key is embedded in `leaf_flip_crypto.c`.

## Features

- **Read LEAF card** — full SELECT → READ → cert chain → INTERNAL AUTH → signature verification flow with a live progress checklist
- **Verified screen** — large "VERIFIED" + 12-digit Open ID once both signatures pass
- **More menu** — drill into:
  - **Save** — persist all read data (certificate, public key, challenge, card random, signature, etc.) to a `.lvr` file in `apps_data/leaf_flip/`
  - **Info** — view parsed certificate details (Subject CN, Issuer CN, raw public key, CSN, signatures…)
  - **Add to access list** / **Remove from access list** — manage the Access Verifier list (see below)
- **Load past read** — re-open any saved `.lvr` file and view its parsed contents
- **Access Verifier mode** — turn your Flipper into a one-tap access checker (see next section)

## Access Verifier

If a file named `access_list.txt` exists at `/ext/apps_data/leaf_flip/access_list.txt`, the main menu gains a third option: **Access Verifier**.

Access Verifier mode performs the same cryptographic flow as the main reader, but on success it checks the card's Open ID against the access list:

- **Listed Open ID** → big **GRANTED** screen with the alias from the list (or the Open ID if no alias is set)
- **Unlisted Open ID** → big **DENIED** screen with reason "Not in access list"
- **Card failed crypto verification** → big **DENIED** screen with the failure reason

This makes the Flipper a stand-alone offline LEAF access checker — no network or backend required. The card is still cryptographically verified end-to-end against the LEAF Root CA before the access list is consulted, so a forged card with a known Open ID will still be rejected.

### Access list file format

Plain text, one entry per line:

```
<OPEN_ID>[<whitespace><ALIAS>]
```

- `OPEN_ID` is the 12-digit decimal Open ID
- `ALIAS` is optional; everything after the first whitespace is treated as the alias (spaces allowed)
- Lines starting with `#` and blank lines are ignored

#### Example `access_list.txt`

```
# LeafFlip access list — one Open ID per line, optional alias after a space
123456789012 Alice
234567890123 Bob (front door)
345678901234 Conference Room A
# This entry has no alias and will display the Open ID:
456789012345
```

You can edit this file directly on the SD card with any text editor, or use the **Add to access list** / **Remove from access list** menu items after a successful read. The Add option appends just the Open ID; edit the file by hand to add or change aliases.

## Building

This project uses [ufbt](https://github.com/flipperdevices/flipperzero-ufbt):

```bash
# install ufbt if needed
pipx install ufbt

# build
cd LeafFlip
ufbt

# build, install, and launch on a connected Flipper
ufbt launch
```

The built `.fap` lands at `dist/leaf_flip.fap` and is installed to `/ext/apps/NFC/leaf_flip.fap` on the device.

GitHub Actions builds against both the `release` and `dev` SDK channels on every push and on a daily schedule — see `.github/workflows/build.yml`.

## Repository layout

```
LeafFlip/
  application.fam       # ufbt app manifest
  leaf_flip.c           # main UI (ViewDispatcher, scenes)
  leaf_flip.h           # shared types and prototypes
  leaf_flip_reader.c    # NFC poller + APDU TX/RX, SELECT/READ/AUTH flow
  leaf_flip_crypto.c    # DER cert parser + mbedTLS ECDSA verify, Root CA pubkey
  leaf_flip_save.c      # FlipperFormat save/load of .lvr files
  leaf_flip_access.c    # Access list parsing and management
  examples/
    access_list.txt     # Example access list — copy to /ext/apps_data/leaf_flip/
  .catalog/             # Flipper Application Catalog metadata
  .github/workflows/    # CI build for dev + release SDK channels
```

## Acknowledgements

- The **LEAF Community** for publishing the open Verified protocol and the reference [onboarding guide](https://github.com/LEAF-Community/leaf-verified-device-onboarding-guide), without which this app would not exist.
- [`bettse/passy`](https://github.com/bettse/passy) — the eMRTD reader app that served as a structural reference for ufbt-packaged Flipper NFC apps.
- Flipper Devices for the SDK and toolchain.

## License

MIT — see `LICENSE` in the repository root.
