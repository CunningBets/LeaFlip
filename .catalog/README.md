LeafFlip reads and verifies LEAF Verified Open Application cards (NXP MIFARE DUOX / ISO 14443-4) end-to-end on your Flipper Zero.

## What it does

- SELECT the LEAF Open Application AID
- READ the on-card X.509 device certificate
- VERIFY the certificate against the embedded LEAF Root CA (ECDSA P-256 / SHA-256, mbedTLS)
- INTERNAL AUTHENTICATE with a fresh 16-byte challenge
- VERIFY the card's signature over challenge || card_random
- Display the 12-digit Open ID once both signatures pass

## Features

- Live progress checklist showing each verification step
- Save full read (cert, public key, challenge, signature, …) to a .lvr file
- Re-open and inspect any saved read
- **Access Verifier mode**: drop an `access_list.txt` into the app data folder and the app turns into an offline LEAF access checker — large GRANTED / DENIED screen with optional aliases. Cards are still cryptographically verified before being checked against the list.

## Access list format

Plain text, one entry per line:

```
<OPEN_ID> [ALIAS]
```

Place the file at `/ext/apps_data/leaf_flip/access_list.txt`. Add / remove entries directly from the More menu after a successful read, or edit the file by hand to set aliases.

## Credits

Based on the official [LEAF Verified onboarding guide](https://github.com/LEAF-Community/leaf-verified-device-onboarding-guide) reference reader.

## Source

[github.com/&lt;your-fork&gt;/LeafFlip](https://github.com/) — MIT licensed.
