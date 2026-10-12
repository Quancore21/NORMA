#!/usr/bin/env python3
"""NORMA: генератор «тонких» стратегий для YouTube.

Берёт все vendor/zapret/general*.bat, вытаскивает уникальные правила для TCP 443 по списку list-google
(то есть для YouTube/Google) и превращает каждое в отдельную компактную стратегию strategies/norma/*.args:
  * norma-yt-NN.args   - только TCP 443 (трогает один YouTube/Google, остальное в системе не затрагивается);
  * norma-yt-NNq.args  - то же плюс подмена QUIC (UDP 443) для списка list-google.
Каждая стратегия состоит только из правил, которые уже есть в upstream, поэтому набор параметров заведомо допустим.

Запуск (нужен только Python 3, из любой папки):  python tools/gen_strategies.py
"""
import glob
import os
import re
import sys
from collections import OrderedDict

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


if __name__ == "__main__":
    main()
