# NoMorePwn

A local Python/PySide6 password-vault application with a browser-extension/native-messaging integration. Core modules live in `nomorepwn/`; desktop views live in `nomorepwn_app/`; extension source lives in `extension/`.

## Verified fixture behavior

The Windows audit ran 257 unittest cases against disposable vaults and offscreen Qt views. They exercise encryption/decryption, tamper/wrong-key rejection, vault lifecycle, validation, grouping, and view construction. Network/provider behavior is mocked where applicable. Passing these tests is not an independent security audit or proof that storing real secrets is safe.

The reviewed correction gives Firefox its own temporary-add-on instructions, including `manifest.json` and the restart limitation. Chromium browsers retain their Load unpacked instructions. Tests no longer assume the computer's default browser is Chrome.

## Run from source

Use a dedicated Python 3.10+ environment and install `requirements.txt` before launching the existing desktop entry point `NoMorePwn.py`. For fixture verification:

```sh
python -m unittest discover -s tests -v
```

On headless systems set `QT_QPA_PLATFORM=offscreen` before running the view tests. Do not point test runs at a personal vault.

## Limits

Real-browser native messaging/autofill, packaged executable installation, live breach queries and updater downloads were not exercised in this audit. Some functions can make network requests, so the whole application is not described as air-gapped. Firefox's temporary development installation is removed on browser restart; end-user distribution requires a signed packaged add-on. [Mozilla's temporary-installation guide](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/).

No zero-vulnerability, production-readiness, independent certification or blanket offline guarantee is claimed.
