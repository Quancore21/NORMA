# Стратегии

Стратегия это набор аргументов `winws.exe`. NORMA берёт их из трёх мест:

| Источник | Где | Заметки |
|---|---|---|
| zapret | `vendor\zapret\general*.bat` | разбираются автоматически, символ `^` (экранирование .bat) снимается |
| norma | `strategies\norma\*.args` | создаются `tools\gen_strategies.py`, это «тонкие» стратегии только для YouTube |
| user | `strategies\user\*.args` | ваши; пробуются первыми |

## Формат .args

```
# name: Моя стратегия 1
# scope: youtube
# desc: что делает (необязательно)
--wf-tcp=443 --filter-tcp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=...
```

- Строки на `#` с ключами `name`, `scope`, `family`, `desc`, `from` это метаданные; остальные `#` комментарии.
- Остальные строки склеиваются через пробел и передаются в `winws.exe`.
- Подстановки: `%BIN%` (папка `vendor\zapret\bin\`), `%LISTS%` (`vendor\zapret\lists\`),
  `%GameFilterTCP%` и `%GameFilterUDP%` (в NORMA всегда 12, то есть игровой фильтр выключен).
- `scope: youtube` значит стратегия трогает только YouTube/Google и доступна в профиле «YouTube».
  Без `scope` (или `scope: full`) стратегия доступна в обоих профилях.
- `family`: `tcp` или `quic`, влияет только на порядок перебора.
- Имя берётся из `name`, иначе из имени файла. Имена должны быть уникальны.

## Порядок перебора

1. ваши (`user`), по номеру в имени;
2. `norma`, сначала варианты TCP, потом с QUIC;
3. `zapret`: general, ALT, FAKE TLS AUTO, SIMPLE FAKE, EXP.

Ранг считает `Get-StrategyRank` в `lib.ps1`.

## Как создать и проверить свою стратегию

1. Скопируйте `strategies\user\example.args.sample` в `my.args`, поправьте аргументы.
2. Меню NORMA, пункт 4 (выбрать вручную): стратегия видна в списке с пометкой `[user]`.
3. Пункт 3 (бенчмарк) сравнит её с остальными по стабильности, времени ответа и (если есть `yt-dlp`) скорости видео; результат в `data/ranking.json`.
4. Если стратегия получилась хорошей, предложите её в pull request (см. CONTRIBUTING.md): приложите результат бенчмарка, провайдера и регион.

## Генератор

`python tools\gen_strategies.py` (нужен Python 3) собирает уникальные правила TCP 443 по списку `list-google` из всех
`general*.bat` и пишет по две стратегии на правило: только TCP (`NORMA YT-NN`) и с подменой QUIC (`NORMA YT-NNQ`).
Источник каждого правила указан в строке `# from:`. После обновления upstream запустите генератор заново.
