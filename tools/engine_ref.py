#!/usr/bin/env python3
"""NORMA: эталонная реализация планировщика приёмов десинхронизации и «золотые» тесты для C#-версии.

Планировщик отвечает на вопрос: какие пакеты отправит приём, если ему дать настоящий TLS ClientHello?
  * поддельные пакеты (fake): сколько, какой длины;
  * сегменты данных: смещения и длины в порядке отправки (multisplit: по возрастанию, multidisorder: в обратном порядке);
  * перекрытие seqovl у первого сегмента;
  * то, что планировщик пока не моделирует (hostfakesplit, fakedsplit, маркер sniext и другие), перечисляется явно.

Это не отправка пакетов: планировщик чисто вычисляет план, поэтому его можно проверять без сети и драйвера.
Та же логика реализована на C# (app/native/NormaPlan.cs, используется в NORMA). Каноническая запись плана совпадает в обеих реализациях,
а tests/engine-golden.json хранит ожидаемые результаты для всех настоящих ClientHello из vendor/zapret/bin и всех правил YouTube.
Самопроверка NORMA на Windows сверяет C# с этим файлом.

  python tools/engine_ref.py golden    пересоздать tests/engine-golden.json
  python tools/engine_ref.py check     проверить инварианты плана на всех случаях (для CI)
"""
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import payload_tool  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINDIR = os.path.join(ROOT, "vendor", "zapret", "bin")
GOLDEN = os.path.join(ROOT, "tests", "engine-golden.json")

SPECS = ["1", "2", "5000", "0", "1,midsld", "midsld", "host", "endhost", "host+1", "endhost-1", "2,sniext+1",
         "1,host,endhost", "method+2", "3,3,2", "abc"]


def u16(d, p):
    return (d[p] << 8) | d[p + 1]


def strict_parse(data):
    """Строгий разбор TLS ClientHello: каждая длина проверяется относительно границы своей структуры.
    Возвращает (смещение имени, длина имени) или None при любой несогласованности (обрезанные данные, противоречивые длины,
    имя за пределами расширения, повторное расширение server_name и т.п.). Те же правила в app/native/NormaPlan.cs."""
    n = len(data)
    if n < 5 or data[0] != 0x16:
        return None
    rec_end = 5 + u16(data, 3)
    if rec_end > n:
        return None
    pos = 5
    if pos + 4 > rec_end or data[pos] != 0x01:
        return None
    hs_end = pos + 4 + int.from_bytes(data[pos + 1:pos + 4], "big")
    if hs_end != rec_end:                       # одно сообщение ClientHello ровно на всю запись
        return None
    pos += 4
    if pos + 2 + 32 > hs_end:
        return None
    pos += 2 + 32
    if pos + 1 > hs_end:
        return None
    pos += 1 + data[pos]                        # session id
    if pos + 2 > hs_end:
        return None
    pos += 2 + u16(data, pos)                   # cipher suites
    if pos + 1 > hs_end:
        return None
    pos += 1 + data[pos]                        # compression methods
    if pos + 2 > hs_end:
        return None
    ext_end = pos + 2 + u16(data, pos)
    pos += 2
    if ext_end != hs_end:                       # расширения занимают остаток сообщения без лишних байт
        return None
    found = None
    while pos < ext_end:
        if pos + 4 > ext_end:
            return None
        etype = u16(data, pos)
        elen = u16(data, pos + 2)
        dstart = pos + 4
        dend = dstart + elen
        if dend > ext_end:
            return None
        if etype == 0:
            if found is not None:               # повтор server_name запрещён
                return None
            if elen < 5:
                return None
            list_len = u16(data, dstart)
            if 2 + list_len != elen:            # список имён ровно на всё расширение
                return None
            if data[dstart + 2] != 0:           # только host_name
                return None
            nlen = u16(data, dstart + 3)
            if nlen == 0 or 3 + nlen != list_len:
                return None
            found = (dstart + 5, nlen)
        pos = dend
    return found


def hello_info(data):
    """Смещение и длина имени сайта в ClientHello; None, если это не корректный ClientHello с SNI."""
    r = strict_parse(data)
    if r is None:
        return None
    off, ln = r
    return {"off": off, "len": ln, "host": data[off:off + ln].decode("ascii", "replace")}


def describe_hello(data):
    info = hello_info(data)
    if info is None:
        return "Ok:0"
    return "Ok:1;off:%d;len:%d;host:%s" % (info["off"], info["len"], info["host"])


def apply_mutation(data, op):
    """Операции над байтами для проверки разбора: truncate:N, set8:СМЕЩЕНИЕ:ЗНАЧЕНИЕ, set16:..., set24:... (big-endian)."""
    parts = op.split(":")
    b = bytearray(data)
    if parts[0] == "truncate":
        return bytes(b[:int(parts[1])])
    off, val = int(parts[1]), int(parts[2])
    if parts[0] == "set8":
        b[off] = val & 0xFF
    elif parts[0] == "set16":
        b[off:off + 2] = val.to_bytes(2, "big")
    elif parts[0] == "set24":
        b[off:off + 3] = val.to_bytes(3, "big")
    return bytes(b)


def mutation_ops(data):
    """Набор искажений для одного ClientHello: (имя, операция, ожидается ли разбор)."""
    p = payload_tool.parse_tls_clienthello(data)
    sni = next(e for e in p["exts"] if e["type"] == 0)
    n = len(data)
    return [
        ("control", "truncate:%d" % n, True),
        ("truncate-half", "truncate:%d" % (n // 2), False),
        ("truncate-5", "truncate:5", False),
        ("truncate-1", "truncate:%d" % (n - 1), False),
        ("record-plus1", "set16:3:%d" % (p["rec_len"] + 1), False),
        ("record-minus1", "set16:3:%d" % (p["rec_len"] - 1), False),
        ("handshake-plus1", "set24:%d:%d" % (p["hs_start"] - 3, p["hs_len"] + 1), False),
        ("handshake-minus1", "set24:%d:%d" % (p["hs_start"] - 3, p["hs_len"] - 1), False),
        ("extensions-plus1", "set16:%d:%d" % (p["ext_len_pos"], p["ext_total"] + 1), False),
        ("extensions-minus1", "set16:%d:%d" % (p["ext_len_pos"], p["ext_total"] - 1), False),
        ("sni-ext-len-plus1", "set16:%d:%d" % (sni["pos"] + 2, sni["len"] + 1), False),
        ("sni-list-too-big", "set16:%d:%d" % (sni["pos"] + 4, sni["len"] + 10), False),
        ("sni-list-too-small", "set16:%d:2" % (sni["pos"] + 4), False),
        ("sni-name-too-big", "set16:%d:5000" % (sni["pos"] + 7), False),
        ("sni-name-zero", "set16:%d:0" % (sni["pos"] + 7), False),
        ("sni-type-not-host", "set8:%d:1" % (sni["pos"] + 6), False),
        ("session-id-oversized", "set8:43:255", False),
    ]


def mid_sld(info):
    labels = info["host"].split(".")
    if len(labels) < 2:
        return info["off"] + info["len"] // 2
    start = sum(len(x) + 1 for x in labels[:-2])
    return info["off"] + start + len(labels[-2]) // 2


def add_unique(lst, item):
    if item not in lst:
        lst.append(item)


def resolve_positions(data, spec):
    """Позиции разреза и список неподдерживаемых маркеров. Поддерживаются числа, host, endhost, midsld с поправкой +N/-N."""
    res = []
    unsupported = []
    info = None
    info_loaded = False
    for part in spec.split(","):
        p = part.strip()
        if not p:
            continue
        if re.fullmatch(r"[0-9]{1,9}", p):
            value = int(p)
        else:
            m = re.fullmatch(r"([a-z]+)([+-][0-9]{1,9})?", p)
            if not m:
                add_unique(unsupported, p)
                continue
            name = m.group(1)
            delta = int(m.group(2)) if m.group(2) else 0
            if not info_loaded:
                info = hello_info(data)
                info_loaded = True
            if name == "host" and info:
                base = info["off"]
            elif name == "endhost" and info:
                base = info["off"] + info["len"]
            elif name == "midsld" and info:
                base = mid_sld(info)
            else:
                add_unique(unsupported, name)
                continue
            value = base + delta
        if 0 < value < len(data) and value not in res:
            res.append(value)
    res.sort()
    return res, unsupported


def describe_positions(data, spec):
    pos, uns = resolve_positions(data, spec)
    out = "P:" + ",".join(str(x) for x in pos)
    if uns:
        out += "|U:" + ",".join(uns)
    return out


def build_plan(data, modes, split_pos, seqovl, repeats, fooling, fake_len):
    """Возвращает (пакеты, неподдерживаемое). Пакет: (вид, смещение, длина, доп), где доп это повторы у fake и перекрытие у data."""
    ml = [m.strip() for m in modes.split(",") if m.strip()]
    packets = []
    unsupported = []
    has_fake = "fake" in ml
    disorder = "multidisorder" in ml
    split = ("multisplit" in ml) or disorder
    for m in ml:
        if m not in ("fake", "multisplit", "multidisorder"):
            add_unique(unsupported, m)
    if has_fake:
        packets.append(("fake", 0, fake_len, repeats if repeats > 0 else 1))
    pos = []
    if split:
        pos, uns = resolve_positions(data, split_pos or "")
        for u in uns:
            add_unique(unsupported, "pos:" + u)
    if split and pos:
        bounds = [0] + pos + [len(data)]
        segs = [("data", bounds[i], bounds[i + 1] - bounds[i], seqovl if i == 0 else 0) for i in range(len(bounds) - 1)]
        if disorder:
            segs.reverse()
        packets += segs
    else:
        if split:
            add_unique(unsupported, "split-pos:none")
        packets.append(("data", 0, len(data), 0))
    return packets, unsupported


def describe_plan(data, modes, split_pos, seqovl, repeats, fooling, fake_len):
    packets, uns = build_plan(data, modes, split_pos, seqovl, repeats, fooling, fake_len)
    out = ";".join("%s:%d:%d:%d" % p for p in packets)
    if uns:
        out += "|U:" + ",".join(uns)
    if fooling:
        out += "|F:" + fooling
    return out


# ---------- случаи для золотого файла
def read_rule(path):
    body = " ".join(l.strip() for l in open(path, encoding="utf-8").read().replace("\r\n", "\n").split("\n")
                    if l.strip() and not l.startswith("#"))
    opts = {}
    for tok in re.findall(r'(?:[^\s"]+|"[^"]*")+', body):
        m = re.match(r"^--([A-Za-z0-9-]+)(?:=(.*))?$", tok)
        if m:
            opts[m.group(1)] = (m.group(2) or "").strip('"')
    return opts


def fake_length(opts):
    v = opts.get("dpi-desync-fake-tls", "")
    m = re.match(r"^%BIN%(.+)$", v)
    if m and os.path.exists(os.path.join(BINDIR, m.group(1))):
        return os.path.getsize(os.path.join(BINDIR, m.group(1)))
    return 0


def build_cases():
    cases = []
    hellos = sorted(os.path.basename(p) for p in glob.glob(os.path.join(BINDIR, "tls_clienthello_*.bin")))
    for h in hellos:
        data = open(os.path.join(BINDIR, h), "rb").read()
        for spec in SPECS:
            cases.append({"id": "pos:%s:%s" % (h, spec), "kind": "positions", "hello": h, "spec": spec,
                          "expect": describe_positions(data, spec)})
    for h in hellos:
        data = open(os.path.join(BINDIR, h), "rb").read()
        for name, op, _ in mutation_ops(data):
            cases.append({"id": "hello:%s:%s" % (h, name), "kind": "hello", "hello": h, "op": op,
                          "expect": describe_hello(apply_mutation(data, op))})
    rules = sorted(glob.glob(os.path.join(ROOT, "strategies", "norma", "norma-yt-[0-9][0-9].args")))
    sample = ["tls_clienthello_www_google_com.bin", hellos[0] if hellos else ""]
    for rp in rules:
        o = read_rule(rp)
        name = os.path.basename(rp)[:-5]
        for h in dict.fromkeys(sample):
            if not h:
                continue
            data = open(os.path.join(BINDIR, h), "rb").read()
            modes = o.get("dpi-desync", "")
            spec = o.get("dpi-desync-split-pos", "")
            seqovl = int(o.get("dpi-desync-split-seqovl", "0") or 0)
            reps = int(o.get("dpi-desync-repeats", "0") or 0)
            foo = o.get("dpi-desync-fooling", "")
            fl = fake_length(o)
            cases.append({"id": "plan:%s:%s" % (name, h), "kind": "plan", "hello": h, "modes": modes, "splitPos": spec,
                          "seqovl": seqovl, "repeats": reps, "fooling": foo, "fakeLen": fl,
                          "expect": describe_plan(data, modes, spec, seqovl, reps, foo, fl)})
    return cases


def cmd_golden():
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    cases = build_cases()
    with open(GOLDEN, "w", encoding="utf-8", newline="") as f:
        json.dump(cases, f, indent=1, ensure_ascii=True)
        f.write("\n")
    print("создан tests/engine-golden.json: случаев %d" % len(cases))
    return 0


def cmd_check():
    errors = []

    def check(cond, text):
        if not cond:
            errors.append(text)

    cases = build_cases()
    check(len(cases) > 100, "слишком мало случаев: %d" % len(cases))
    hellos = sorted(glob.glob(os.path.join(BINDIR, "tls_clienthello_*.bin")))
    for hp in hellos:
        data = open(hp, "rb").read()
        info = hello_info(data)
        check(info is not None, "%s: имя сайта не найдено" % os.path.basename(hp))
        if not info:
            continue
        check(data[info["off"]:info["off"] + info["len"]].decode("ascii") == info["host"], "%s: смещение имени неверно" % os.path.basename(hp))
        for spec in SPECS + ["1,host,midsld,endhost"]:
            for modes in ("multisplit", "multidisorder", "fake,multisplit", "fake,multidisorder", "multisplit,fakedsplit"):
                for seqovl in (0, 681):
                    pk, uns = build_plan(data, modes, spec, seqovl, 6, "ts", 681)
                    d = [p for p in pk if p[0] == "data"]
                    # инвариант 1: сегменты данных покрывают пакет ровно один раз
                    cover = sorted((p[1], p[2]) for p in d)
                    pos = 0
                    for off, ln in cover:
                        check(off == pos and ln > 0, "%s %s %s: сегменты не смыкаются" % (os.path.basename(hp), modes, spec))
                        pos += ln
                    check(pos == len(data), "%s %s %s: сегменты не покрывают пакет" % (os.path.basename(hp), modes, spec))
                    # инвариант 2: fake всегда первым, disorder даёт обратный порядок смещений
                    if "fake" in modes.split(","):
                        check(pk[0][0] == "fake", "fake не первым")
                    offs = [p[1] for p in d]
                    if "multidisorder" in modes.split(",") and len(offs) > 1:
                        check(offs == sorted(offs, reverse=True), "disorder не в обратном порядке")
                    elif len(offs) > 1:
                        check(offs == sorted(offs), "split не по возрастанию")
                    # инвариант 3: перекрытие только у сегмента со смещением 0 и только если пакет действительно разрезан
                    for p in d:
                        expected = seqovl if (p[1] == 0 and len(d) > 1) else 0
                        check(p[3] == expected, "%s %s %s: перекрытие не у первого сегмента" % (os.path.basename(hp), modes, spec))
    # строгий разбор: искажённые ClientHello не дают имени сайта, исходные дают
    for hp in hellos:
        data = open(hp, "rb").read()
        for name, op, should_parse in mutation_ops(data):
            got = hello_info(apply_mutation(data, op)) is not None
            check(got == should_parse, "%s %s: ожидалось %s, получено %s" % (os.path.basename(hp), name, "разбор" if should_parse else "отказ", "разбор" if got else "отказ"))
    # повтор server_name запрещён: расширение дописывается ещё раз
    g = open(os.path.join(BINDIR, "tls_clienthello_www_google_com.bin"), "rb").read()
    pp = payload_tool.parse_tls_clienthello(g)
    se = next(e for e in pp["exts"] if e["type"] == 0)
    ext_bytes = g[se["pos"]:se["pos"] + 4 + se["len"]]
    dup = bytearray(g + ext_bytes)
    dup[3:5] = (pp["rec_len"] + len(ext_bytes)).to_bytes(2, "big")
    dup[pp["hs_start"] - 3:pp["hs_start"]] = (pp["hs_len"] + len(ext_bytes)).to_bytes(3, "big")
    dup[pp["ext_len_pos"]:pp["ext_len_pos"] + 2] = (pp["ext_total"] + len(ext_bytes)).to_bytes(2, "big")
    check(hello_info(bytes(dup)) is None, "повторное расширение server_name должно отвергаться")
    check(hello_info(g) is not None, "исходный образец должен разбираться")
    if errors:
        for e in errors[:20]:
            print("  FAIL ", e)
        print("ошибок: %d" % len(errors))
        return 1
    print("инварианты планировщика выполнены (случаев в золотом файле: %d)" % len(cases))
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] == "golden":
        return cmd_golden()
    if len(argv) == 2 and argv[1] == "check":
        return cmd_check()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
