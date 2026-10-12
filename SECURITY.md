# Security policy

## Scope

NORMA runs with administrator rights and loads the WinDivert kernel driver, so security reports are taken seriously.

In scope: the code in `app/`, `tools/`, `NORMA.bat` and the release process.
Out of scope for fixes here (report upstream): vulnerabilities in `winws`, WinDivert or Cygwin themselves.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this repository
(<https://github.com/Quancore21/NORMA/security/advisories/new>). Do not open a public issue for a vulnerability.

You will get an answer as soon as possible. Please include the NORMA version (`VERSION`), Windows version and steps to reproduce.

## Verifying a download

Binaries in `vendor/zapret/bin` come unchanged from the upstream project. Their SHA-256 sums are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and the in-app Doctor prints them for `winws.exe` and `WinDivert64.sys`.
Download releases only from this repository's Releases page.
