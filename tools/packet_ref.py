#!/usr/bin/env python3
"""NORMA: эталонная сборка пакетов по плану приёма и «золотые» тесты для C#-версии.

Планировщик (tools/engine_ref.py) решает, какие пакеты отправить: сколько поддельных и какие сегменты данных в каком порядке.
Здесь эти решения превращаются в настоящие байты IPv4+TCP:
  * сегмент данных: заголовки исходного пакета, свои порядковый номер, длина и контрольные суммы; PSH только у сегмента, которым заканчиваются данные;
  * перекрытие seqovl: перед первым сегментом идут байты шаблона, порядковый номер сдвигается назад на их число;
  * поддельный пакет: содержимое поддельного ClientHello и «подделка», чтобы сервер его отбросил, а DPI принял:
      badsum   контрольная сумма TCP намеренно неверна (увеличена на 1);
      badseq   порядковый номер сдвинут на заданное число (по умолчанию -10000);
      md5sig   добавлена опция TCP MD5 (вид 19, 16 нулевых байт), которую сервер без общего ключа отбрасывает;
      ts       метка времени (TSval) отодвинута в далёкое прошлое на 600000, если в заголовке есть опция Timestamps;
      TTL      значение dpi-desync-ttl для поддельных пакетов;
  * идентификатор IP: с ip-id=zero у всех собранных пакетов 0, иначе ID исходного пакета плюс номер пакета в плане.
Это определения NORMA, а не точная копия того, что делает winws: они описывают способ и позволяют проверять сборку по байтам.

Сборка чисто вычислительная (без сети и драйвера). Та же логика на C# (app/native/NormaEngine.cs); tests/packet-golden.json хранит
для каждого случая каноническую запись результата (с SHA-256 каждого пакета), и самопроверка NORMA сверяет C# с этим файлом.

  python tools/packet_ref.py golden    пересоздать tests/packet-golden.json
  python tools/packet_ref.py check     проверить инварианты на всех случаях (для CI)
"""
import glob
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine_ref  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = engine_ref.ROOT
BINDIR = engine_ref.BINDIR
GOLDEN = os.path.join(ROOT, "tests", "packet-golden.json")

MASK = 0xFFFFFFFF
TS_DELTA = 600000
DEFAULT_BADSEQ = -10000
KNOWN_FOOLING = ("badsum", "badseq", "md5sig", "ts")
DEFAULT_FAKE = "tls_clienthello_www_google_com.bin"
FLAG_PSH = 0x08


# ---------- байты и контрольные суммы
def u16(b, o):
    return (b[o] << 8) | b[o + 1]


def u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def csum16(data):
    if len(data) % 2:
        data = data + b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def parse_packet(pkt):
    """Разбор IPv4+TCP пакета: поля заголовков и содержимое."""
    if len(pkt) < 40 or (pkt[0] >> 4) != 4 or pkt[9] != 6:
        raise ValueError("не пакет IPv4 TCP")
    ihl = (pkt[0] & 15) * 4
    total = u16(pkt, 2)
    if total > len(pkt) or total < ihl + 20:
        raise ValueError("длина в заголовке IP не согласована с пакетом")
    tcp = ihl
    thl = (pkt[tcp + 12] >> 4) * 4
    if thl < 20 or tcp + thl > total:
        raise ValueError("длина заголовка TCP не согласована")
    return {
        "raw": pkt[:total], "ihl": ihl, "total": total, "id": u16(pkt, 4), "ttl": pkt[8],
        "tcp": tcp, "seq": u32(pkt, tcp + 4), "ack": u32(pkt, tcp + 8), "thl": thl, "flags": pkt[tcp + 13],
        "opts": bytes(pkt[tcp + 20:tcp + thl]), "payload": bytes(pkt[tcp + thl:total]),
    }


def verify(pkt):
    """True, если контрольные суммы IP и TCP пакета верны (проверка независимо от сборки)."""
    t = parse_packet(pkt)
    if csum16(bytes(pkt[:t["ihl"]])) != 0:
        return False
    seg = bytes(pkt[t["tcp"]:t["total"]])
    pseudo = bytes(pkt[12:16]) + bytes(pkt[16:20]) + bytes([0, 6]) + struct.pack(">H", len(seg))
    return csum16(pseudo + seg) == 0


def build_one(t, payload, seq, flags, ttl, ipid, options, bad_checksum):
    ip = bytearray(t["raw"][:t["ihl"]])
    tcp = bytearray(t["raw"][t["tcp"]:t["tcp"] + 20])
    opts = bytes(options)
    thl = 20 + len(opts)
    tcp[12] = ((thl // 4) << 4) | (t["raw"][t["tcp"] + 12] & 0x0F)
    tcp[13] = flags & 0xFF
    tcp[4:8] = struct.pack(">I", seq & MASK)
    tcp[16:18] = b"\x00\x00"
    seg = bytes(tcp) + opts + bytes(payload)
    ip[2:4] = struct.pack(">H", t["ihl"] + len(seg))
    ip[4:6] = struct.pack(">H", ipid & 0xFFFF)
    ip[8] = ttl & 0xFF
    ip[10:12] = b"\x00\x00"
    pseudo = bytes(ip[12:16]) + bytes(ip[16:20]) + bytes([0, 6]) + struct.pack(">H", len(seg))
    cs = csum16(pseudo + seg)
    if bad_checksum:
        cs = (cs + 1) & 0xFFFF
    seg = seg[:16] + struct.pack(">H", cs) + seg[18:]
    ip[10:12] = struct.pack(">H", csum16(bytes(ip)))
    return bytes(ip) + seg


# ---------- опции TCP
def strip_eol(opts):
    """Обрезает опции по первому EOL (вид 0) на границе опции: после него идёт заполнение."""
    i = 0
    n = len(opts)
    while i < n:
        k = opts[i]
        if k == 0:
            return bytes(opts[:i])
        if k == 1:
            i += 1
            continue
        if i + 1 >= n or opts[i + 1] < 2:
            break
        i += opts[i + 1]
    return bytes(opts)


def bad_timestamp(opts):
    """Отодвигает TSval на TS_DELTA назад. Возвращает (опции, применено)."""
    b = bytearray(opts)
    i = 0
    n = len(b)
    while i < n:
        k = b[i]
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        if i + 1 >= n or b[i + 1] < 2:
            break
        ln = b[i + 1]
        if k == 8 and ln == 10 and i + 10 <= n:
            v = (u32(b, i + 2) - TS_DELTA) & MASK
            b[i + 2:i + 6] = struct.pack(">I", v)
            return bytes(b), True
        i += ln
    return bytes(opts), False


def add_md5(opts):
    """Добавляет опцию MD5 (вид 19, длина 18, 16 нулевых байт) и выравнивает NOP до 4 байт. Возвращает (опции, применено)."""
    o = bytearray(strip_eol(opts))
    o += bytes([19, 18]) + bytes(16)
    while len(o) % 4:
        o.append(1)
    if len(o) > 40:
        return bytes(opts), False
    return bytes(o), True


# ---------- шаблон пакета для проверок
def make_template(kind, payload):
    """Заголовки IPv4+TCP пакета, несущего данные payload, с верными контрольными суммами. kind: win (без опций) или ts (с Timestamps)."""
    opts = b""
    if kind == "ts":
        opts = bytes([1, 1, 8, 10]) + struct.pack(">II", 0x00A1B2C3, 0x00D4E5F6)
    tcp = bytearray(20)
    tcp[0:2] = struct.pack(">H", 51234)
    tcp[2:4] = struct.pack(">H", 443)
    tcp[4:8] = struct.pack(">I", 0x1A2B3C4D)
    tcp[8:12] = struct.pack(">I", 0x5E6F7081)
    tcp[12] = ((20 + len(opts)) // 4) << 4
    tcp[13] = 0x18                       # PSH + ACK
    tcp[14:16] = struct.pack(">H", 513)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack(">H", 20 + 20 + len(opts) + len(payload))
    ip[4:6] = struct.pack(">H", 0x1C46)
    ip[6:8] = struct.pack(">H", 0x4000)  # DF
    ip[8] = 128
    ip[9] = 6
    ip[12:16] = bytes([192, 168, 31, 57])
    ip[16:20] = bytes([142, 250, 74, 46])
    seg = bytes(tcp) + opts + bytes(payload)
    pseudo = bytes(ip[12:16]) + bytes(ip[16:20]) + bytes([0, 6]) + struct.pack(">H", len(seg))
    tcp[16:18] = struct.pack(">H", csum16(pseudo + seg))
    ip[10:12] = struct.pack(">H", csum16(bytes(ip)))
    return bytes(ip) + bytes(tcp) + opts


# ---------- сборка по плану
def add_unique(lst, item):
    if item not in lst:
        lst.append(item)


def resolve_fake(spec):
    """Поддельное содержимое: %BIN%файл, 0xШЕСТНАДЦАТЕРИЧНО или встроенное (образец ClientHello для www.google.com)."""
    m = re.match(r"^%BIN%(.+)$", spec or "")
    if m and os.path.exists(os.path.join(BINDIR, m.group(1))):
        return open(os.path.join(BINDIR, m.group(1)), "rb").read()
    m = re.match(r"^0x([0-9a-fA-F]+)$", spec or "")
    if m and len(m.group(1)) % 2 == 0:
        return bytes.fromhex(m.group(1))
    return open(os.path.join(BINDIR, DEFAULT_FAKE), "rb").read()


def resolve_pattern(spec):
    m = re.match(r"^%BIN%(.+)$", spec or "")
    if m and os.path.exists(os.path.join(BINDIR, m.group(1))):
        return open(os.path.join(BINDIR, m.group(1)), "rb").read()
    return b""


def build_packets(pkt, modes, split_pos, seqovl, repeats, fooling, fake_payload, pattern, ttl, badseq_inc, ipid_zero, fake_mod=False):
    """Возвращает (шаблон, список пакетов, примечания). Пакет: словарь с байтами и полями."""
    t = parse_packet(pkt)
    payload = t["payload"]
    plan, notes = engine_ref.build_plan(payload, modes, split_pos, seqovl, repeats, fooling, len(fake_payload))
    notes = list(notes)
    foo = [x.strip() for x in (fooling or "").split(",") if x.strip()]
    for f in foo:
        if f not in KNOWN_FOOLING:
            add_unique(notes, "fooling:" + f)
    if fake_mod:
        add_unique(notes, "fake-tls-mod")           # изменения поддельного ClientHello (rnd, dupsid, sni=) пока не моделируются
    out = []
    for kind, off, ln, extra in plan:
        if kind == "fake":
            for _ in range(extra):
                i = len(out)
                seq = t["seq"]
                if "badseq" in foo:
                    seq = (seq + badseq_inc) & MASK
                opts = t["opts"]
                if "ts" in foo:
                    opts, ok = bad_timestamp(opts)
                    if not ok:
                        add_unique(notes, "ts-no-option")
                if "md5sig" in foo:
                    opts, ok = add_md5(opts)
                    if not ok:
                        add_unique(notes, "md5sig-overflow")
                p = build_one(t, fake_payload, seq, t["flags"], ttl if ttl > 0 else t["ttl"],
                              0 if ipid_zero else (t["id"] + i), opts, "badsum" in foo)
                out.append({"kind": "fake", "pkt": p, "seq": seq, "plen": len(fake_payload), "flags": t["flags"],
                            "ttl": ttl if ttl > 0 else t["ttl"], "id": 0 if ipid_zero else (t["id"] + i) & 0xFFFF})
        else:
            i = len(out)
            body = payload[off:off + ln]
            seq = (t["seq"] + off) & MASK
            if extra > 0:
                body = (pattern[:extra] + bytes(extra))[:extra] + body
                seq = (seq - extra) & MASK
            flags = t["flags"]
            if flags & FLAG_PSH:
                flags = (flags & ~FLAG_PSH) | (FLAG_PSH if off + ln == len(payload) else 0)
            pid = 0 if ipid_zero else (t["id"] + i) & 0xFFFF
            p = build_one(t, body, seq, flags, t["ttl"], pid, t["opts"], False)
            out.append({"kind": "data", "pkt": p, "seq": seq, "plen": len(body), "flags": flags, "ttl": t["ttl"], "id": pid})
    return t, out, notes


def describe_packets(pkt, modes, split_pos, seqovl, repeats, fooling, fake_payload, pattern, ttl, badseq_inc, ipid_zero, fake_mod=False):
    t, out, notes = build_packets(pkt, modes, split_pos, seqovl, repeats, fooling, fake_payload, pattern, ttl, badseq_inc, ipid_zero, fake_mod)
    parts = []
    for e in out:
        rel = ((e["seq"] - t["seq"] + 2 ** 31) % 2 ** 32) - 2 ** 31
        ok = 1 if verify(e["pkt"]) else 0
        parts.append("%s:%d:%d:%02x:%d:%d:%d:%s" % (e["kind"], rel, e["plen"], e["flags"], e["ttl"], e["id"], ok,
                                                      hashlib.sha256(e["pkt"]).hexdigest()))
    s = ";".join(parts)
    if notes:
        s += "|N:" + ",".join(notes)
    return s


# ---------- случаи для золотого файла
def parse_int(text, default):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return default


def case_from_rule(name, opts, hello, tpl_kind):
    payload = open(os.path.join(BINDIR, hello), "rb").read()
    hdr = make_template(tpl_kind, payload)
    c = {
        "id": "pkt:%s:%s:%s" % (name, hello, tpl_kind), "kind": "packets", "hello": hello, "template": tpl_kind, "hdr": hdr.hex(),
        "modes": opts.get("dpi-desync", ""), "splitPos": opts.get("dpi-desync-split-pos", ""),
        "seqovl": parse_int(opts.get("dpi-desync-split-seqovl", "0"), 0), "repeats": parse_int(opts.get("dpi-desync-repeats", "0"), 0),
        "fooling": opts.get("dpi-desync-fooling", ""), "ttl": parse_int(opts.get("dpi-desync-ttl", "0"), 0),
        "badseqInc": parse_int(opts.get("dpi-desync-badseq-increment", ""), DEFAULT_BADSEQ),
        "ipidZero": opts.get("ip-id", "") == "zero", "fake": opts.get("dpi-desync-fake-tls", ""),
        "pattern": opts.get("dpi-desync-split-seqovl-pattern", ""), "fakeMod": opts.get("dpi-desync-fake-tls-mod", ""),
    }
    c["expect"] = describe_case(c)
    return c


def describe_case(c):
    payload = open(os.path.join(BINDIR, c["hello"]), "rb").read()
    return describe_packets(bytes.fromhex(c["hdr"]) + payload, c["modes"], c["splitPos"], c["seqovl"], c["repeats"], c["fooling"],
                            resolve_fake(c["fake"]), resolve_pattern(c["pattern"]), c["ttl"], c["badseqInc"], c["ipidZero"], bool(c["fakeMod"]))


SYNTHETIC = [
    ("badsum", dict(modes="fake,multisplit", splitPos="1,midsld", repeats=3, fooling="badsum")),
    ("md5sig", dict(modes="fake,multisplit", splitPos="1,midsld", repeats=2, fooling="md5sig")),
    ("badseq-default", dict(modes="fake,multisplit", splitPos="2", repeats=2, fooling="badseq")),
    ("badseq-2", dict(modes="fake,multisplit", splitPos="2", repeats=2, fooling="badseq", badseqInc=2)),
    ("ts", dict(modes="fake,multisplit", splitPos="2", repeats=2, fooling="ts")),
    ("all-fooling", dict(modes="fake,multidisorder", splitPos="1,host,endhost", repeats=2, fooling="badseq,md5sig,ts,badsum")),
    ("ttl3", dict(modes="fake,multisplit", splitPos="2", repeats=2, fooling="", ttl=3)),
    ("ipid-keep", dict(modes="fake,multisplit", splitPos="1,midsld", repeats=2, fooling="ts", ipidZero=False)),
    ("seqovl-pattern", dict(modes="fake,multidisorder", splitPos="1,midsld", repeats=2, fooling="ts", seqovl=681,
                            pattern="%BIN%tls_clienthello_www_google_com.bin")),
    ("seqovl-zero-pattern", dict(modes="multisplit", splitPos="3", seqovl=10, fooling="")),
    ("unknown-fooling", dict(modes="fake,multisplit", splitPos="2", repeats=2, fooling="datanoack,ts")),
    ("fake-only", dict(modes="fake", splitPos="", repeats=2, fooling="ts")),
    ("unsupported-mode", dict(modes="fake,hostfakesplit", splitPos="2", repeats=2, fooling="ts")),
    ("fake-mod", dict(modes="fake,multisplit", splitPos="2", repeats=1, fooling="ts", fakeMod="rnd,dupsid,sni=www.google.com")),
    ("fake-hex", dict(modes="fake,multisplit", splitPos="2", repeats=1, fooling="ts", fake="0x00000000")),
    ("no-split-pos", dict(modes="multisplit", splitPos="abc,sniext", fooling="")),
]


def build_cases():
    cases = []
    sample_hellos = ["tls_clienthello_www_google_com.bin", "tls_clienthello_4pda_to.bin"]
    for rp in sorted(glob.glob(os.path.join(ROOT, "strategies", "norma", "norma-yt-[0-9][0-9].args")), key=os.path.basename):
        opts = engine_ref.read_rule(rp)
        name = os.path.basename(rp)[:-5]
        for h in sample_hellos:
            for tk in ("win", "ts"):
                cases.append(case_from_rule(name, opts, h, tk))
    for hp in sorted(os.path.basename(x) for x in glob.glob(os.path.join(BINDIR, "tls_clienthello_*.bin"))):
        pl = open(os.path.join(BINDIR, hp), "rb").read()
        for tk in ("win", "ts"):
            cases.append({"id": "tpl:%s:%s" % (hp, tk), "kind": "template", "hello": hp, "template": tk,
                          "expect": hashlib.sha256(make_template(tk, pl) + pl).hexdigest()})
    for sname, kw in SYNTHETIC:
        opts = {"dpi-desync": kw.get("modes", ""), "dpi-desync-split-pos": kw.get("splitPos", ""),
                "dpi-desync-split-seqovl": str(kw.get("seqovl", 0)), "dpi-desync-repeats": str(kw.get("repeats", 0)),
                "dpi-desync-fooling": kw.get("fooling", ""), "dpi-desync-ttl": str(kw.get("ttl", 0)),
                "ip-id": "zero" if kw.get("ipidZero", True) else "", "dpi-desync-fake-tls": kw.get("fake", ""),
                "dpi-desync-split-seqovl-pattern": kw.get("pattern", ""), "dpi-desync-fake-tls-mod": kw.get("fakeMod", "")}
        if "badseqInc" in kw:
            opts["dpi-desync-badseq-increment"] = str(kw["badseqInc"])
        for tk in ("win", "ts"):
            cases.append(case_from_rule("syn-" + sname, opts, sample_hellos[0], tk))
    return cases


def cmd_golden():
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    cases = build_cases()
    with open(GOLDEN, "w", encoding="utf-8", newline="") as f:
        json.dump(cases, f, indent=1, ensure_ascii=True)
        f.write("\n")
    print("создан tests/packet-golden.json: случаев %d" % len(cases))
    return 0


def _option_kinds(opts):
    res = []
    i = 0
    n = len(opts)
    while i < n:
        k = opts[i]
        res.append(k)
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        if i + 1 >= n or opts[i + 1] < 2:
            break
        i += opts[i + 1]
    return res


def cmd_check():
    errors = []

    def check(cond, text):
        if not cond:
            errors.append(text)

    # контрольная сумма: известный пример из описания IPv4 (заголовок 4500 0073 0000 4000 4011 [b861] c0a8 0001 c0a8 00c7)
    check(csum16(bytes.fromhex("450000730000400040110000c0a80001c0a800c7")) == 0xB861, "csum16 не совпала с известным примером")
    cases = build_cases()
    check(len(cases) >= 100, "слишком мало случаев: %d" % len(cases))
    for c in cases:
        if c["kind"] != "packets":
            continue
        payload = open(os.path.join(BINDIR, c["hello"]), "rb").read()
        pkt = bytes.fromhex(c["hdr"]) + payload
        t, out, notes = build_packets(pkt, c["modes"], c["splitPos"], c["seqovl"], c["repeats"], c["fooling"],
                                      resolve_fake(c["fake"]), resolve_pattern(c["pattern"]), c["ttl"], c["badseqInc"], c["ipidZero"], bool(c["fakeMod"]))
        cid = c["id"]
        foo = [x.strip() for x in c["fooling"].split(",") if x.strip()]
        check(verify(pkt), cid + ": шаблон должен иметь верные суммы")
        fakes = [e for e in out if e["kind"] == "fake"]
        datas = [e for e in out if e["kind"] == "data"]
        for e in out:                                             # длины, заголовки, суммы
            p = parse_packet(e["pkt"])
            check(p["total"] == len(e["pkt"]), cid + ": длина в заголовке IP не равна длине пакета")
            check(p["thl"] == 20 + len(p["opts"]) and p["thl"] % 4 == 0 and p["thl"] <= 60, cid + ": длина заголовка TCP")
            check(len(p["payload"]) == e["plen"], cid + ": длина содержимого")
            if e["kind"] == "data" or "badsum" not in foo:
                check(verify(e["pkt"]), cid + ": у пакета должны быть верные контрольные суммы")
            else:
                check(not verify(e["pkt"]), cid + ": у поддельного пакета с badsum сумма должна быть неверной")
                check(csum16(e["pkt"][:p["ihl"]]) == 0, cid + ": у пакета с badsum сумма IP должна быть верной")
        if "fake" in c["modes"].split(","):                       # поддельные: число, содержимое, подделка
            reps = c["repeats"] if c["repeats"] > 0 else 1
            check(len(fakes) == reps, cid + ": число поддельных пакетов")
        for e in fakes:
            p = parse_packet(e["pkt"])
            check(p["payload"] == resolve_fake(c["fake"]), cid + ": содержимое поддельного пакета")
            if "badseq" in foo:
                check(p["seq"] == (t["seq"] + c["badseqInc"]) & MASK, cid + ": сдвиг порядкового номера")
            if "md5sig" in foo:
                check(19 in _option_kinds(p["opts"]), cid + ": опция md5sig должна быть добавлена")
            if c["ttl"] > 0:
                check(p["ttl"] == c["ttl"], cid + ": TTL поддельного пакета")
        stream = {}                                               # данные: покрытие, порядок, PSH, перекрытие
        for e in datas:
            p = parse_packet(e["pkt"])
            rel = (p["seq"] - t["seq"]) & MASK
            rel = rel - (1 << 32) if rel >= (1 << 31) else rel
            body = p["payload"]
            if rel < 0:                                           # перекрытие: байты шаблона перед данными
                body = body[-rel:]
                rel = 0
            stream[rel] = body
        joined = b""
        pos = 0
        for off in sorted(stream):
            check(off == pos, cid + ": сегменты данных не смыкаются")
            joined += stream[off]
            pos += len(stream[off])
        check(joined == t["payload"], cid + ": данные после склейки не совпали с исходными")
        if t["flags"] & FLAG_PSH:
            check(len([e for e in datas if e["flags"] & FLAG_PSH]) == 1, cid + ": PSH должен быть ровно у одного сегмента")
        ids = [e["id"] for e in out]
        if c["ipidZero"]:
            check(all(i == 0 for i in ids), cid + ": ip-id=zero")
        elif out:
            check(ids == [(t["id"] + k) & 0xFFFF for k in range(len(out))], cid + ": идентификаторы IP")
    if errors:
        for e in errors[:25]:
            print("  FAIL ", e)
        print("ошибок: %d" % len(errors))
        return 1
    print("инварианты сборки пакетов выполнены (случаев: %d)" % len(cases))
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
