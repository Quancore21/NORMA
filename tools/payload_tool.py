#!/usr/bin/env python3
"""NORMA: инструмент для поддельных пакетов (.bin) из vendor/zapret/bin.

Поддельные пакеты это заготовки, которые winws отправляет перед настоящими данными (см. docs/TECHNIQUES.md).
Инструмент нужен, чтобы понимать их устройство и уметь создавать свои:

  python tools/payload_tool.py inspect ФАЙЛ [ФАЙЛ ...]     разобрать пакеты и показать устройство
  python tools/payload_tool.py set-sni ВХОД ИМЯ ВЫХОД      собрать TLS ClientHello с другим именем сайта
                                                           (длины пересчитываются, размер сохраняется, если есть padding)
  python tools/payload_tool.py report                      создать docs/PAYLOADS.md
  python tools/payload_tool.py selfcheck                   проверка разбора и сборки (для CI)

Нужен только Python 3, внешние пакеты не используются.
"""
import glob
import hashlib
import os
import struct
import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINDIR = os.path.join(ROOT, "vendor", "zapret", "bin")

EXT_NAMES = {
    0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
    16: "alpn", 18: "signed_certificate_timestamp", 21: "padding", 23: "extended_master_secret", 27: "compress_certificate",
    28: "record_size_limit", 34: "delegated_credentials", 35: "session_ticket", 43: "supported_versions",
    45: "psk_key_exchange_modes", 51: "key_share",
    17513: "application_settings", 17613: "application_settings (new)", 65037: "encrypted_client_hello", 65281: "renegotiation_info",
}


def ext_name(t):
    if (t & 0x0F0F) == 0x0A0A and (t >> 8) == (t & 0xFF):
        return "GREASE"
    return EXT_NAMES.get(t, "0x%04x" % t)


class ParseError(Exception):
    pass


def need(data, pos, n, what):
    if pos + n > len(data):
        raise ParseError("обрыв данных при чтении: %s" % what)


def parse_tls_clienthello(data):
    """Разбирает TLS ClientHello; возвращает словарь с полями и позициями (нужны для пересборки)."""
    need(data, 0, 5, "заголовок записи")
    if data[0] != 0x16:
        raise ParseError("не запись TLS Handshake (первый байт 0x%02x)" % data[0])
    rec_ver = struct.unpack(">H", data[1:3])[0]
    rec_len = struct.unpack(">H", data[3:5])[0]
    need(data, 5, rec_len, "тело записи")
    pos = 5
    need(data, pos, 4, "заголовок Handshake")
    if data[pos] != 0x01:
        raise ParseError("не ClientHello (тип Handshake %d)" % data[pos])
    hs_len = int.from_bytes(data[pos + 1:pos + 4], "big")
    hs_start = pos + 4
    pos = hs_start
    need(data, pos, 2 + 32, "версия и random")
    client_ver = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2 + 32
    need(data, pos, 1, "session id")
    sid_len = data[pos]
    pos += 1 + sid_len
    need(data, pos, 2, "cipher suites")
    cs_len = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2 + cs_len
    need(data, pos, 1, "compression")
    pos += 1 + data[pos]
    need(data, pos, 2, "длина расширений")
    ext_len_pos = pos
    ext_total = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    ext_start = pos
    need(data, pos, ext_total, "расширения")
    exts = []
    while pos < ext_start + ext_total:
        need(data, pos, 4, "заголовок расширения")
        t, ln = struct.unpack(">HH", data[pos:pos + 4])
        need(data, pos + 4, ln, "данные расширения")
        exts.append({"type": t, "len": ln, "pos": pos})
        pos += 4 + ln
    sni = None
    for e in exts:
        if e["type"] == 0:
            d = data[e["pos"] + 4:e["pos"] + 4 + e["len"]]
            if len(d) >= 5 and d[2] == 0:
                nlen = struct.unpack(">H", d[3:5])[0]
                sni = d[5:5 + nlen].decode("ascii", "replace")
    return {
        "rec_ver": rec_ver, "rec_len": rec_len, "hs_len": hs_len, "hs_start": hs_start, "client_ver": client_ver,
        "session_id_len": sid_len, "cipher_bytes": cs_len, "ext_len_pos": ext_len_pos, "ext_total": ext_total,
        "exts": exts, "sni": sni, "size": len(data), "trailing": len(data) - (5 + rec_len),
    }


def parse_quic_initial(data):
    """Разбирает открытую часть заголовка QUIC (содержимое Initial зашифровано и здесь не читается)."""
    need(data, 0, 7, "заголовок QUIC")
    b0 = data[0]
    if not (b0 & 0x80):
        raise ParseError("короткий заголовок QUIC")
    version = struct.unpack(">I", data[1:5])[0]
    dcid_len = data[5]
    pos = 6
    need(data, pos, dcid_len + 1, "DCID")
    pos += dcid_len
    scid_len = data[pos]
    pos += 1 + scid_len
    return {"version": version, "packet_type": (b0 >> 4) & 0x03, "dcid_len": dcid_len, "scid_len": scid_len, "size": len(data)}


def parse_stun(data):
    if len(data) >= 20 and data[4:8] == b"\x21\x12\xa4\x42":
        mtype, mlen = struct.unpack(">HH", data[0:4])
        return {"type": mtype, "len": mlen, "size": len(data)}
    return None


def describe_file(path):
    """Короткое описание файла: (тип, подробности)."""
    name = os.path.basename(path)
    data = open(path, "rb").read()
    try:
        if name.startswith("tls_clienthello"):
            p = parse_tls_clienthello(data)
            names = ", ".join(ext_name(e["type"]) for e in p["exts"])
            return "TLS ClientHello", "SNI `%s`, %d байт, расширений: %d" % (p["sni"], p["size"], len(p["exts"])), p, names
        if name.startswith("quic_initial") or name.startswith("ACTIVE_"):
            p = parse_quic_initial(data)
            return "QUIC Initial", "версия 0x%08x, DCID %d байт, %d байт" % (p["version"], p["dcid_len"], p["size"]), p, ""
        if name.startswith("stun"):
            p = parse_stun(data)
            if p:
                return "STUN", "сообщение тип 0x%04x, %d байт" % (p["type"], p["size"]), p, ""
    except ParseError as e:
        return "ошибка разбора", str(e), None, ""
    return "прочее", "%d байт, начало %s" % (len(data), data[:8].hex()), None, ""


def set_sni(data, host):
    """Возвращает ClientHello с другим именем в SNI. Длины пересчитываются; если есть padding, размер сохраняется."""
    p = parse_tls_clienthello(data)
    sni_ext = next((e for e in p["exts"] if e["type"] == 0), None)
    if sni_ext is None:
        raise ParseError("в ClientHello нет расширения server_name")
    hostb = host.encode("ascii")
    new_data = struct.pack(">HBH", 3 + len(hostb), 0, len(hostb)) + hostb          # список имён: длина, тип 0, имя
    new_ext = struct.pack(">HH", 0, len(new_data)) + new_data
    old_ext_len = 4 + sni_ext["len"]
    delta = len(new_ext) - old_ext_len
    out = bytearray(data[:sni_ext["pos"]] + new_ext + data[sni_ext["pos"] + old_ext_len:])

    # padding: компенсируем изменение размера, чтобы поддельный пакет остался прежней длины
    pad = next((e for e in p["exts"] if e["type"] == 21), None)
    if pad is not None and delta != 0:
        pad_pos = pad["pos"] + (delta if pad["pos"] > sni_ext["pos"] else 0)
        new_pad_len = pad["len"] - delta
        if new_pad_len >= 0:
            out[pad_pos + 2:pad_pos + 4] = struct.pack(">H", new_pad_len)
            if delta > 0:
                del out[pad_pos + 4 + new_pad_len:pad_pos + 4 + pad["len"]]
            else:
                out[pad_pos + 4 + pad["len"]:pad_pos + 4 + pad["len"]] = b"\x00" * (-delta)
            delta = 0
    # длины: записи, Handshake, расширений
    total_delta = len(out) - len(data)
    out[3:5] = struct.pack(">H", p["rec_len"] + total_delta)
    out[p["hs_start"] - 3:p["hs_start"]] = (p["hs_len"] + total_delta).to_bytes(3, "big")
    out[p["ext_len_pos"]:p["ext_len_pos"] + 2] = struct.pack(">H", p["ext_total"] + total_delta)
    return bytes(out)


def add_padding(data, n):
    """Тестовый помощник: добавляет в конец расширений ClientHello расширение padding длиной n и исправляет длины."""
    p = parse_tls_clienthello(data)
    ext = struct.pack(">HH", 21, n) + b"\x00" * n
    out = bytearray(data + ext)
    out[3:5] = struct.pack(">H", p["rec_len"] + len(ext))
    out[p["hs_start"] - 3:p["hs_start"]] = (p["hs_len"] + len(ext)).to_bytes(3, "big")
    out[p["ext_len_pos"]:p["ext_len_pos"] + 2] = struct.pack(">H", p["ext_total"] + len(ext))
    return bytes(out)


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def cmd_inspect(files):
    for f in files:
        kind, info, parsed, exts = describe_file(f)
        print("%s: %s; %s" % (os.path.basename(f), kind, info))
        if exts:
            print("    расширения:", exts)
    return 0


def cmd_set_sni(src, host, dst):
    out = set_sni(open(src, "rb").read(), host)
    parse_tls_clienthello(out)                                                       # результат обязан разбираться
    open(dst, "wb").write(out)
    print("записано %s: %d байт, SNI %s" % (dst, len(out), host))
    return 0


def cmd_report():
    files = sorted(glob.glob(os.path.join(BINDIR, "*.bin")), key=lambda p: os.path.basename(p).lower())
    first = {}
    rows = []
    for f in files:
        h = sha(f)
        name = os.path.basename(f)
        dup = ""
        if h in first:
            dup = "совпадает с `%s`" % first[h]
        else:
            first[h] = name
        kind, info, parsed, exts = describe_file(f)
        note = dup
        if parsed and kind == "TLS ClientHello":
            suffix = name[len("tls_clienthello_"):-len(".bin")]
            if parsed["sni"] and parsed["sni"].replace(".", "_").replace("-", "_") != suffix:
                note = (note + "; " if note else "") + "в SNI другое имя, чем в названии файла"
        if parsed and kind == "QUIC Initial" and parsed["version"] != 1:
            note = (note + "; " if note else "") + "нестандартная версия QUIC"
        rows.append((name, kind, info, note))
    lines = [
        "# Поддельные пакеты (vendor/zapret/bin/*.bin)",
        "",
        "Файл создаётся `tools/payload_tool.py report`; не правьте его вручную.",
        "Принцип действия поддельных пакетов описан в [TECHNIQUES.md](TECHNIQUES.md), параметры, которые на них ссылаются, в [OPTIONS.md](OPTIONS.md).",
        "",
        "| Файл | Тип | Что внутри | Заметка |",
        "|---|---|---|---|",
    ]
    for name, kind, info, dup in rows:
        lines.append("| `%s` | %s | %s | %s |" % (name, kind, info, dup))
    lines += ["", "Содержимое QUIC Initial зашифровано, поэтому показаны только открытые поля заголовка; имя сайта указано в названии файла.", ""]
    g = os.path.join(BINDIR, "tls_clienthello_www_google_com.bin")
    if os.path.exists(g):
        p = parse_tls_clienthello(open(g, "rb").read())
        lines += [
            "## Устройство TLS ClientHello на примере `tls_clienthello_www_google_com.bin`",
            "",
            "Запись TLS (5 байт: тип, версия, длина), внутри Handshake ClientHello (тип и длина 3 байта), затем версия клиента, 32 байта random,",
            "session id, список шифров, методы сжатия и расширения. Имя сайта лежит в расширении `server_name`: по нему DPI узнаёт, куда идёт соединение.",
            "",
            "| № | Расширение | Размер данных |",
            "|---|---|---|",
        ]
        for i, e in enumerate(p["exts"], 1):
            lines.append("| %d | %s | %d |" % (i, ext_name(e["type"]), e["len"]))
        lines += [
            "",
            "Чтобы получить такой пакет для другого имени сайта, достаточно заменить `server_name` и пересчитать три длины (запись, Handshake, расширения).",
            "Это делает `python tools/payload_tool.py set-sni`; если в пакете есть `padding`, размер сохраняется. В `winws` то же делает параметр `dpi-desync-fake-tls-mod=sni=...`.",
            "",
        ]
    with open(os.path.join(ROOT, "docs", "PAYLOADS.md"), "w", encoding="utf-8", newline="") as fh:
        fh.write("\n".join(lines))
    print("создан docs/PAYLOADS.md (%d файлов)" % len(rows))
    return 0


def cmd_selfcheck():
    errors = []

    def check(cond, text):
        print(("  ok    " if cond else "  FAIL  ") + text)
        if not cond:
            errors.append(text)

    tls = sorted(glob.glob(os.path.join(BINDIR, "tls_clienthello_*.bin")))
    check(len(tls) > 0, "найдены TLS-пакеты: %d" % len(tls))
    for f in tls:
        data = open(f, "rb").read()
        try:
            p = parse_tls_clienthello(data)
            ok = (p["trailing"] == 0) and (p["hs_len"] + 4 == p["rec_len"]) and bool(p["sni"])
            check(ok, "%s: разбор и согласованность длин (SNI %s)" % (os.path.basename(f), p["sni"]))
        except ParseError as e:
            check(False, "%s: %s" % (os.path.basename(f), e))

    g = os.path.join(BINDIR, "tls_clienthello_www_google_com.bin")
    base = open(g, "rb").read()
    for host in ("www.youtube.com", "a.io", "very-long-subdomain.example-service.com"):
        try:
            out = set_sni(base, host)
            p = parse_tls_clienthello(out)
            check(p["sni"] == host and p["trailing"] == 0 and p["hs_len"] + 4 == p["rec_len"], "set-sni %s: длины согласованы (размер %d -> %d)" % (host, len(base), len(out)))
        except ParseError as e:
            check(False, "set-sni %s: %s" % (host, e))
    # padding в реальных файлах нет: проверяем сохранение размера на искусственном пакете с добавленным padding
    padded = add_padding(base, 60)
    pp = parse_tls_clienthello(padded)
    check(any(e["type"] == 21 for e in pp["exts"]) and pp["trailing"] == 0, "тестовый пакет с padding разбирается")
    for host in ("www.youtube.com", "a.io", "very-long-subdomain.example-service.com"):
        out = set_sni(padded, host)
        po = parse_tls_clienthello(out)
        check(po["sni"] == host and len(out) == len(padded) and po["hs_len"] + 4 == po["rec_len"], "set-sni %s с padding: размер сохранён (%d)" % (host, len(out)))
    same = set_sni(base, parse_tls_clienthello(base)["sni"])
    check(same == base, "set-sni с тем же именем возвращает исходный пакет без изменений")

    quic = sorted(glob.glob(os.path.join(BINDIR, "quic_initial_*.bin")))
    for f in quic:
        try:
            p = parse_quic_initial(open(f, "rb").read())
            # у версии 1 тип пакета Initial = 0; у других версий биты типа значат иное, проверяем только разбор заголовка
            ok = (p["packet_type"] == 0) if p["version"] == 1 else (p["dcid_len"] > 0)
            check(ok, "%s: заголовок QUIC разобран (версия 0x%08x)" % (os.path.basename(f), p["version"]))
        except ParseError as e:
            check(False, "%s: %s" % (os.path.basename(f), e))
    return 1 if errors else 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "inspect" and len(argv) >= 3:
        return cmd_inspect(argv[2:])
    if len(argv) == 5 and argv[1] == "set-sni":
        return cmd_set_sni(argv[2], argv[3], argv[4])
    if len(argv) == 2 and argv[1] == "report":
        return cmd_report()
    if len(argv) == 2 and argv[1] == "selfcheck":
        return cmd_selfcheck()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
