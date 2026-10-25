# Поддельные пакеты (vendor/zapret/bin/*.bin)

Файл создаётся `tools/payload_tool.py report`; не правьте его вручную.
Принцип действия поддельных пакетов описан в [TECHNIQUES.md](TECHNIQUES.md), параметры, которые на них ссылаются, в [OPTIONS.md](OPTIONS.md).

| Файл | Тип | Что внутри | Заметка |
|---|---|---|---|
| `ACTIVE_DISCORD_UDP.bin` | QUIC Initial | версия 0x00000001, DCID 20 байт, 1200 байт |  |
| `ACTIVE_GAME_UDP.bin` | QUIC Initial | версия 0x00000001, DCID 8 байт, 1250 байт |  |
| `quic_initial_4pda_to.bin` | QUIC Initial | версия 0x00000001, DCID 8 байт, 1250 байт | совпадает с `ACTIVE_GAME_UDP.bin` |
| `quic_initial_5ka_ru.bin` | QUIC Initial | версия 0x00000001, DCID 8 байт, 1250 байт |  |
| `quic_initial_rutube_ru.bin` | QUIC Initial | версия 0x00000001, DCID 15 байт, 1357 байт |  |
| `quic_initial_steamcommunity_com.bin` | QUIC Initial | версия 0x00000001, DCID 20 байт, 1200 байт | совпадает с `ACTIVE_DISCORD_UDP.bin` |
| `quic_initial_tencent_com.bin` | QUIC Initial | версия 0xdfd221e2, DCID 214 байт, 1231 байт | нестандартная версия QUIC |
| `quic_initial_www_google_com.bin` | QUIC Initial | версия 0x00000001, DCID 8 байт, 1200 байт |  |
| `stun.bin` | STUN | сообщение тип 0x0001, 100 байт |  |
| `stun2.bin` | STUN | сообщение тип 0x0001, 120 байт |  |
| `tls_clienthello_4pda_to.bin` | TLS ClientHello | SNI `4pda.to`, 284 байт, расширений: 13 |  |
| `tls_clienthello_5ka_ru.bin` | TLS ClientHello | SNI `5ka.ru`, 654 байт, расширений: 15 |  |
| `tls_clienthello_max_ru.bin` | TLS ClientHello | SNI `www.onetrust.com`, 664 байт, расширений: 15 | в SNI другое имя, чем в названии файла |
| `tls_clienthello_sochi_park.bin` | TLS ClientHello | SNI `staging-sochi-park.predict.mail.ru`, 244 байт, расширений: 6 | в SNI другое имя, чем в названии файла |
| `tls_clienthello_www_google_com.bin` | TLS ClientHello | SNI `www.google.com`, 681 байт, расширений: 17 |  |
| `tls_clienthello_www_sferum_ru.bin` | TLS ClientHello | SNI `www.sferum.ru`, 661 байт, расширений: 15 |  |

Содержимое QUIC Initial зашифровано, поэтому показаны только открытые поля заголовка; имя сайта указано в названии файла.

## Устройство TLS ClientHello на примере `tls_clienthello_www_google_com.bin`

Запись TLS (5 байт: тип, версия, длина), внутри Handshake ClientHello (тип и длина 3 байта), затем версия клиента, 32 байта random,
session id, список шифров, методы сжатия и расширения. Имя сайта лежит в расширении `server_name`: по нему DPI узнаёт, куда идёт соединение.

| № | Расширение | Размер данных |
|---|---|---|
| 1 | server_name | 19 |
| 2 | extended_master_secret | 0 |
| 3 | renegotiation_info | 1 |
| 4 | supported_groups | 14 |
| 5 | ec_point_formats | 2 |
| 6 | session_ticket | 0 |
| 7 | alpn | 14 |
| 8 | status_request | 5 |
| 9 | delegated_credentials | 10 |
| 10 | signed_certificate_timestamp | 0 |
| 11 | key_share | 107 |
| 12 | supported_versions | 9 |
| 13 | signature_algorithms | 24 |
| 14 | psk_key_exchange_modes | 2 |
| 15 | record_size_limit | 2 |
| 16 | compress_certificate | 7 |
| 17 | encrypted_client_hello | 281 |

Чтобы получить такой пакет для другого имени сайта, достаточно заменить `server_name` и пересчитать три длины (запись, Handshake, расширения).
Это делает `python tools/payload_tool.py set-sni`; если в пакете есть `padding`, размер сохраняется. В `winws` то же делает параметр `dpi-desync-fake-tls-mod=sni=...`.
