# Apollo 4.2.1 — keyless

No key, no server verdict, no hardware binding. One script, two byte patches, one license file.

## Run it

```powershell
powershell -ExecutionPolicy Bypass -File .\patch-apollo.ps1
```

It finds the install (or pass `-AppDir "<the folder containing resources\modules>"`), asks for
admin because the host lives under `Program Files`, backs up the stock exe to
`<app>\host-backup\*.stock.bin`, patches, and writes the license record. Then start Apollo from
the desktop shortcut.

Re-run it after any Apollo update — updates ship a fresh host.

## What the two patches do

Host: `resources\modules\dcknhrygfqphn.exe`, NativeAOT x64, ImageBase `0x140000000`,
all license code in `.managed` (rva `0x7E000`, raw `0x7C600`).

| VA | stock | patched | effect |
|---|---|---|---|
| `0x140083D67` | `0F 84 E7 00 00 00` | `90 ×6` | nops the `je` in the verdict builder (`0x140083520`). The `?type=init&ver=` answer no longer gates anything — `authorized`, expiry, dead-key message and the new-version lock are all ignored. Local record wins. |
| `0x140085DE7` | `48 85 D2 74 0C … 33 C0 EB 36` (21 b) | `E9 10 00 00 00` + `90 ×16` | jumps to the success return in the record loader (`0x140085950`), skipping the null-sig rejection and the HMAC-SHA256 verify at `0x140086CB0` (single caller, now dead code). |

## License record

`%USERPROFILE%\Documents\Apollo\license.json`

```json
{"key":"APOLLO-UNSIGNED-0000-0000-0000-0000-0000","verifiedUtc":"...","expiryUtc":"2099-12-31T23:59:59.0000000Z","deadMessage":"","lastSeenUtc":"...","offlineLaunches":0,"outdatedMsg":"","sig":"unsigned"}
```

`deadMessage` / `outdatedMsg` are the server's "key is dead" / "update required" strings and are
rendered verbatim in the License page, so they stay empty. `sig` is never read now — the host
re-signs the record itself on first launch with its machine-derived key and refreshes the
timestamps, so the file becomes self-consistent and nothing phones home.

A missing file is not covered: the loader returns null at `0x140085A59` and the verdict falls
back to *"Not activated. Enter your license key."* The record has to exist.

## Verified

```
host: ...\dcknhrygfqphn.exe (12407846 bytes)
patch 1: online verdict gate nop'd at file offset 0x82367
patch 2: HMAC signature check disabled at file offset 0x843E7
>> license.status
{"authorized":true,"expiry":"2099-12-31","reason":"License active, valid until 2099-12-31."}
>> tracker.start
{"armed":true,"enabled":true}
```

Hashes — stock `151C51E8F02EDBE5666F61618D447573EBC7D14E9E691DC611CF73D76E99972A`,
patched `8ACD105643839C512BE1C0BF0CFB7CAF5204A7B779B12C0374D1E4E746A79D0B`.

## Files

```
patch-apollo.ps1                 patcher + license writer (self-elevating)
dcknhrygfqphn.exe                pre-patched 4.2.1 host, manual drop-in
license.json                     unsigned seed record, expiry 2099
```

## Rollback

Copy `host-backup\<name>.stock.bin` back over `resources\modules\<name>.exe`. Or just swap in the
stock binary from `C:\Program Files\...` if you kept one.
