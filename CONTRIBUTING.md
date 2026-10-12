# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you start

- Bugs: open an issue and attach the report from **Doctor** (menu item 6) and the last log from `data/logs`.
- Ideas and new strategies: open an issue first, so we can agree on the shape of the change.

## Development setup

You need Windows with PowerShell 5.1 and, for the strategy generator, Python 3.

```powershell
powershell -ExecutionPolicy Bypass -File tools\selftest.ps1   # must pass
python tools/gen_strategies.py                                # only if vendor/zapret changed
```

The same checks run in CI (`.github/workflows/ci.yml`) on every push and pull request.

## Code conventions

- Windows PowerShell 5.1 only: no `?.`, `??`, ternary operators or other PowerShell 7 features.
- `.ps1` files are UTF-8 **with BOM** and CRLF line endings (Cyrillic text in the UI); `.gitattributes` enforces line endings.
- Output goes through `Say` (screen and log). Functions that return values must not write to the pipeline by accident:
  a stray output turns a single result into an array.
- Do not name a variable `$profile` (an automatic variable in PowerShell); the code uses `$prof`.
- Files in `vendor/zapret/` are upstream's. Do not edit them; see [docs/UPSTREAM.md](docs/UPSTREAM.md).
- Files in `strategies/norma/` are generated; change `tools/gen_strategies.py` instead.

## Adding a strategy

See [docs/STRATEGIES.md](docs/STRATEGIES.md). Include the benchmark result (`data/ranking.json`) and your ISP/region in the pull request.

## Versions and commits

- Versions are `0.X`: 0.8, 0.9, 0.10, 0.11 and so on. Compare the parts as numbers (0.10 is newer than 0.9).
- The version lives in the `VERSION` file and must match the top entry of `CHANGELOG.md`; a release is a tag `vX.Y` on `main`.
- Commit messages: a short imperative summary in English or Russian, for example `Fix caret handling in FAKE TLS AUTO`.

## License

By contributing you agree that your contribution is licensed under the MIT license of this repository.
