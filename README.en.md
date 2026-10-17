<div align="center">

# NORMA

**Node for Obfuscated Routing and Masked Access**

Automatic selection of a working bypass for YouTube (and Discord) throttling on Windows. Powered by the zapret engine (`winws`).

[![CI](https://github.com/Quancore21/NORMA/actions/workflows/ci.yml/badge.svg)](https://github.com/Quancore21/NORMA/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Quancore21/NORMA)](https://github.com/Quancore21/NORMA/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Русский](README.md) · [Download](https://github.com/Quancore21/NORMA/releases/latest) · [Architecture](docs/ARCHITECTURE.md) · [Strategies](docs/STRATEGIES.md) · [Bypass techniques](docs/TECHNIQUES.md) · [Fake payloads](docs/PAYLOADS.md)

</div>

## What it is

Ready-made zapret bundles make you pick a strategy by hand: what works depends on your ISP, and what worked yesterday may stop today.
NORMA does it for you:

- measures what is **actually** blocked without a bypass and touches only that;
- tries strategies and takes the first one that opens everything and **breaks nothing** that already worked;
- keeps watching and **switches strategy** when it stops helping or the network changes;
- compares strategies by stability and response time (benchmark).

It is written in PowerShell 5.1 and needs no installation. While running it loads the WinDivert driver and enables TCP timestamps
(required by some strategies, the original zapret does the same). NORMA does not touch the `hosts` file.

## Quick start

1. Download the archive from [Releases](https://github.com/Quancore21/NORMA/releases/latest) and unpack it to a path **without non-ASCII characters**, e.g. `C:\NORMA`.
2. Enable Secure DNS (DNS over HTTPS) in your browser or in Windows 11 network settings.
3. Run `NORMA.bat` and accept the administrator prompt.
4. Choose item **1**. Keep the window open; any key turns the bypass off.

Requirements: Windows 10 (1803+) or 11, 64-bit.

## Features

| | |
|---|---|
| **Auto-pick** | Baseline measurement, strategy search, a control check that the bypass does not break anything else. For a known network the previously working strategy is tried first |
| **Benchmark** | All strategies; every viable one is checked three times (stability, median time). Results within 15% are treated as equal, so noise is not presented as an advantage |
| **Watchdog** | Every 45 seconds the required sites and the network are checked; on degradation another strategy is selected |
| **Per-network memory** | Home, work, cafe: each network remembers its own strategy |
| **Background and autostart** | Windowless operation, start at logon (scheduled task) |
| **Doctor** | Diagnostics: rights, files and driver signature, conflicts, VPN, DNS, IPv6; the report is copied to the clipboard |
| **Custom strategies** | Drop a `*.args` file or a ready `.bat` from another zapret build into `strategies/user` and it joins the search |
| **Readable strategies** | Every strategy in the list has a one-line description of what it does (mode, fooling, split, overlap). Reference: [docs/OPTIONS.md](docs/OPTIONS.md) |
| **No redundant checks** | Strategies with the same YouTube rule are not re-tested once that rule has failed, so the search is faster |
| **Game filter and IPSet** | The zapret game filter (off, TCP and UDP, TCP only, UDP only) and IPSet modes (none, any, loaded) are switched from the menu |
| **Updates** | Check for a new NORMA and upstream version, update domain lists and IPSet. Files are downloaded and verified together first, then replaced with a backup; on failure everything is rolled back |
| **Care** | NORMA stops only its own `winws` processes, restores TCP timestamps on exit, and the Doctor verifies the checksums of every file in `bin` |
| **Slim strategies** | 34 ready strategies for YouTube/Google only; other traffic is left alone |

## Menu

| Item | Action |
|---|---|
| 1 | Turn NORMA on automatically |
| 2 | Full strategy search again |
| 3 | Benchmark: test all, pick the best |
| 4 | Choose a strategy manually |
| 5 | Network probe: what does not open without a bypass |
| 6 | Doctor |
| 7 | Background mode and autostart |
| 8 | Check profile: YouTube or YouTube + Discord |
| 9 | Extras: zapret `service.bat`, game filter, updates and IPSet, cleanup (driver, TCP timestamps), folders |

## What the benchmark measures

The benchmark checks whether the required sites open, how stable that is (three runs) and how fast the servers respond.
It does not measure the video stream speed itself: that is set by your ISP and Google rather than by the chosen strategy,
and it cannot be measured reliably from outside the browser. When several strategies pass the checks equally they are treated as equal,
and NORMA takes the one that comes first in the list (slim YouTube strategies come first).

## What counts as "opens"

A site counts as reachable when a real server response is received. The certificate is verified, so the response cannot be forged on the way.
The status code is shown when it is not 2xx: many service roots answer 404, which still means "the connection works". A block is the absence of a response (reset, timeout).

## Custom settings

| What | Where |
|---|---|
| Extra domains to bypass | `vendor/zapret/lists/list-general-user.txt` (one per line) |
| Exclusions | `vendor/zapret/lists/list-exclude-user.txt` |
| Extra sites to check | `data/targets.user.txt`, lines like `MySite = "https://example.com"` |
| Custom strategies | `strategies/user/*.args` or `*.bat` (sample: `example.args.sample`) |

## Repository layout

```
NORMA.bat            launcher (administrator rights)
app/                 code: menu, picker, watchdog, Doctor, background; app/native: experimental C# engine
strategies/          norma/ (generated), user/ (yours)
vendor/zapret/       the original zapret-discord-youtube, unchanged
data/                created at runtime: state, logs
docs/                documentation
tools/               gen_strategies.py, selftest.ps1
```

## Troubleshooting

1. Item **6 (Doctor)** shows conflicts (old `winws`, zapret service, VPN), missing files (antivirus may have removed WinDivert) and DNS spoofing.
2. If nothing is found: enable Secure DNS, disable VPN while testing, try the benchmark and the "YouTube + Discord" profile.
3. Antivirus software may flag WinDivert (a packet capture driver). This is normal for zapret; add the folder to exclusions.
4. Telegram is blocked by IP address, which a packet-level bypass cannot fix.
5. Open an [issue](https://github.com/Quancore21/NORMA/issues/new/choose) and attach the Doctor report.

The zapret game filter is off by default (menu 9 → 6). Logs are in `data/logs`.

## Development

```powershell
powershell -ExecutionPolicy Bypass -File tools\selftest.ps1   # core self-test
python tools/gen_strategies.py                                # rebuild NORMA strategies, reference and checksums from vendor/zapret
python tools/payload_tool.py selfcheck                        # parse and rebuild fake payloads (.bin)
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Versions are numbered `0.X` (0.8, 0.9, 0.10, 0.11, and so on); history is in [CHANGELOG.md](CHANGELOG.md).

## Credits and license

NORMA stands on [zapret](https://github.com/bol-van/zapret) (bol-van), [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) (Flowseal)
and [WinDivert](https://reqrypt.org/windivert.html) (basil00). Components and licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

NORMA's own code is released under the [MIT](LICENSE) license. Author: [Quancore21](https://github.com/Quancore21).

## Disclaimer

NORMA changes only the network traffic of your own computer (packet interception by the WinDivert driver). You are responsible for making sure
its use complies with the laws of your country and the rules of your ISP and services. The software is provided "as is", without warranty.
