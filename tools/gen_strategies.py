#!/usr/bin/env python3
"""NORMA: генератор «тонких» стратегий для YouTube.

Берёт все vendor/zapret/general*.bat, вытаскивает уникальные правила для TCP 443 по списку list-google
(то есть для YouTube/Google) и превращает каждое в отдельную компактную стратегию strategies/norma/*.args:
  * norma-yt-NN.args   - только TCP 443 (трогает один YouTube/Google, остальное в системе не затрагивается);
  * norma-yt-NNq.args  - то же плюс подмена QUIC (UDP 443) для списка list-google.
Каждая стратегия состоит только из правил, которые уже есть в upstream, поэтому набор параметров заведомо допустим.

Заодно собирает манифест контрольных сумм app/core/checksums.txt (и таблицу в THIRD_PARTY_NOTICES.md) для всех файлов vendor/zapret/bin и справочник параметров docs/OPTIONS.md из app/core/options.txt и реального использования параметров в стратегиях.

Запуск (нужен только Python 3, из любой папки):  python tools/gen_strategies.py
"""
import glob
import hashlib
import os
import re
import sys
from collections import OrderedDict

# Вывод в UTF-8 в любой среде: на Windows (в том числе в CI) кодировка консоли и каналов не UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "vendor", "zapret")
OUT = os.path.join(ROOT, "strategies", "norma")

QUIC_RULE = ('--filter-udp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=fake --dpi-desync-repeats=6 '
             '--dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new')
GOOGLE = '--hostlist="%LISTS%list-google.txt"'


def read_args(bat_path):
    """Аргументы winws из general*.bat (одна команда start ... winws.exe с переносами через ^)."""
    text = open(bat_path, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    lines = text.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line.lstrip().lower().startswith("start ") and "winws.exe" in line:
            start = i
            break
    if start is None:
        return None
    buf = []
    for line in lines[start:]:
        line = line.rstrip()
        cont = line.endswith("^")
        buf.append((line[:-1] if cont else line).strip())
        if not cont:
            break
    m = re.search(r'"%BIN%winws\.exe"\s+(.*)$', " ".join(buf))
    if not m:
        return None
    return re.sub(r"\^(.)", r"\1", m.group(1))      # снять экранирование cmd (^! -> !)


def youtube_clauses():
    found = OrderedDict()                              # правило -> список источников
    for path in sorted(glob.glob(os.path.join(VENDOR, "general*.bat"))):
        name = os.path.splitext(os.path.basename(path))[0]
        args = read_args(path)
        if not args:
            print("пропуск (не разобран):", name, file=sys.stderr)
            continue
        for seg in [s.strip() for s in args.split("--new")]:
            if "--filter-tcp=443" in seg and "list-google" in seg:
                core = re.sub(r'--hostlist="%LISTS%list-google\.txt"\s*', "", seg)
                core = core.replace("--filter-tcp=443", "").strip()
                found.setdefault(core, []).append(name)
    items = list(found.items())
    items.sort(key=lambda kv: -len(kv[1]))             # самые распространённые первыми (sort устойчивый)
    return items


KIND_TITLES = [
    ("capture", "Захват трафика"),
    ("filter", "Выбор трафика (профили)"),
    ("list", "Списки доменов и адресов"),
    ("desync", "Десинхронизация"),
    ("split", "Разрез и перекрытие"),
    ("fake", "Содержимое поддельных пакетов"),
    ("misc", "Прочее"),
]


def option_usage():
    """Сколько стратегий zapret используют каждый параметр."""
    usage = {}
    for path in sorted(glob.glob(os.path.join(VENDOR, "general*.bat"))):
        args = read_args(path)
        if not args:
            continue
        names = set()
        for tok in re.findall(r'(?:[^\s"]+|"[^"]*")+', args):
            m = re.match(r"^--([A-Za-z0-9-]+)", tok)
            if m:
                names.add(m.group(1))
        for n in names:
            usage[n] = usage.get(n, 0) + 1
    return usage


def write_options_doc():
    ref_path = os.path.join(ROOT, "app", "core", "options.txt")
    ref = OrderedDict()
    with open(ref_path, encoding="utf-8") as f:
        for line in f.read().replace("\r\n", "\n").split("\n"):
            if not line.strip() or line.startswith("#"):
                continue
            name, kind, text = line.split("\t", 2)
            ref[name] = (kind, text)
    usage = option_usage()
    unknown = sorted(n for n in usage if n not in ref)
    if unknown:
        print("параметры без описания в app/core/options.txt:", ", ".join(unknown), file=sys.stderr)
    total = len(glob.glob(os.path.join(VENDOR, "general*.bat")))
    lines = [
        "# Параметры winws в стратегиях",
        "",
        "Справочник создаётся `tools/gen_strategies.py` из `app/core/options.txt` и реального использования параметров в стратегиях zapret.",
        "Правьте описания в `app/core/options.txt`, а не этот файл. Самопроверка NORMA следит, чтобы каждый параметр стратегий был описан.",
        "",
        "Колонка «Стратегий» показывает, в скольких из %d стратегий zapret параметр встречается." % total,
        "",
    ]
    for kind, title in KIND_TITLES:
        rows = [(n, v[1]) for n, v in ref.items() if v[0] == kind]
        if not rows:
            continue
        lines += ["## " + title, "", "| Параметр | Что делает | Стратегий |", "|---|---|---|"]
        for n, text in rows:
            lines.append("| `--%s` | %s | %d |" % (n, text, usage.get(n, 0)))
        lines.append("")
    with open(os.path.join(ROOT, "docs", "OPTIONS.md"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines))


CORE_BINARIES = ["winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll"]


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def write_checksums():
    """Манифест app/core/checksums.txt и таблица контрольных сумм в THIRD_PARTY_NOTICES.md."""
    bindir = os.path.join(VENDOR, "bin")
    sums = OrderedDict()
    for name in sorted(os.listdir(bindir), key=str.lower):
        path = os.path.join(bindir, name)
        if os.path.isfile(path):
            sums[name] = sha256_of(path)
    lines = [
        "# Контрольные суммы SHA-256 файлов vendor/zapret/bin. Создаётся tools/gen_strategies.py, не правьте вручную.",
        "# Формат: SHA256, два пробела, имя файла. Доктор NORMA сверяет с ним файлы при проверке.",
    ]
    lines += ["%s  %s" % (h, n) for n, h in sums.items()]
    with open(os.path.join(ROOT, "app", "core", "checksums.txt"), "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(lines) + "\n")

    notices = os.path.join(ROOT, "THIRD_PARTY_NOTICES.md")
    with open(notices, encoding="utf-8", newline="") as f:
        text = f.read().replace("\r\n", "\n")
    start, end = "<!-- checksums:start -->", "<!-- checksums:end -->"
    i, j = text.index(start), text.index(end)
    table = ["| File | SHA-256 |", "|---|---|"]
    table += ["| `%s` | `%s` |" % (n, sums[n]) for n in CORE_BINARIES if n in sums]
    text = text[: i + len(start)] + "\n" + "\n".join(table) + "\n" + text[j:]
    with open(notices, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return len(sums)


def describe(clause):
    modes = re.search(r"--dpi-desync=(\S+)", clause)
    fool = re.search(r"--dpi-desync-fooling=(\S+)", clause)
    parts = [modes.group(1) if modes else "?"]
    if fool:
        parts.append("fooling=" + fool.group(1))
    if "seqovl" in clause:
        parts.append("seqovl")
    return ", ".join(parts)


def write(path, header, body):
    text = "\r\n".join(header) + "\r\n" + body + "\r\n"
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def main():
    os.makedirs(OUT, exist_ok=True)
    for old in glob.glob(os.path.join(OUT, "*.args")):
        os.remove(old)
    clauses = youtube_clauses()
    for n, (clause, sources) in enumerate(clauses, 1):
        num = "%02d" % n
        src = ", ".join(sources)
        base_header = [
            "# scope: youtube",
            "# desc: %s" % describe(clause),
            "# from: %s" % src,
            "# Файл создан tools/gen_strategies.py; правки будут перезаписаны при повторной генерации.",
        ]
        tcp = '--wf-tcp=443 --filter-tcp=443 %s %s' % (GOOGLE, clause)
        write(os.path.join(OUT, "norma-yt-%s.args" % num),
              ["# name: NORMA YT-%s" % num, "# family: tcp"] + base_header, tcp)
        quic = '--wf-tcp=443 --wf-udp=443 %s %s' % (QUIC_RULE, "--filter-tcp=443 %s %s" % (GOOGLE, clause))
        write(os.path.join(OUT, "norma-yt-%sq.args" % num),
              ["# name: NORMA YT-%sQ" % num, "# family: quic"] + base_header, quic)
    print("создано стратегий:", len(clauses) * 2, "(правил TCP: %d)" % len(clauses))
    write_options_doc()
    print("справочник параметров: docs/OPTIONS.md")
    print("контрольные суммы: app/core/checksums.txt (%d файлов)" % write_checksums())


if __name__ == "__main__":
    main()
