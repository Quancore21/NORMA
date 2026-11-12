# Как NORMA живёт рядом с upstream

Оригинал ([Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)) лежит целиком в `vendor\zapret\`.

## Что менялось относительно оригинала
- Удалены `.github\` (CI оригинала) и `utils\check_updates.enabled` (чтобы `service.bat` не предлагал заменить NORMA оригиналом).
- Больше ничего в файлах оригинала не менялось. Пользовательские списки `lists\*-user.txt` создаются при запуске (как делает и сам оригинал) и не попадают в репозиторий (`.gitignore`).

## Обновление
1. Скачать свежий релиз upstream и распаковать.
2. Заменить содержимое `vendor\zapret\` (кроме `lists\*-user.txt`).
3. Запустить `python tools\gen_strategies.py` и `python tools\payload_tool.py report`: тонкие стратегии, справочник параметров, манифест контрольных сумм
   и описание поддельных пакетов пересоберутся из новых файлов.
4. Запустить `powershell -File tools\selftest.ps1`: проверка, что разбор стратегий не сломался (то же делает CI).
5. Если upstream поменял формат .bat (например, ушёл от одной команды `start ... winws.exe`), чинить нужно только `Read-BatStrategies` в `app\core\lib.ps1`
   и `read_args` в `tools\gen_strategies.py`.

## Обновление списков и проверка версии без нового релиза NORMA

В меню «Дополнительно», «Обновления и списки» есть проверка версии оригинала и обновление списков доменов (`list-general.txt`, `list-google.txt`, `list-exclude.txt`, `ipset-exclude.txt`)
из ветки `main` репозитория оригинала. Все файлы сначала скачиваются и проверяются, потом заменяются; старые версии сохраняются в `data/backup`, при сбое всё откатывается.
Список IPSet (`.service/ipset-service.txt`) обновляется отдельным пунктом и хранится в `ipset-all.txt.backup`; живой `ipset-all.txt` меняется, только если режим IPSet `loaded`.
Файлы `bin` (в том числе поддельные пакеты) с GitHub не обновляются: они входят в контрольные суммы и приходят только с новой версией NORMA.
Стратегии обновляются только вместе с новой версией NORMA: после обновления `vendor\zapret` запустите `python tools/gen_strategies.py`.
