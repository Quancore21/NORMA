# NORMA: самопроверка ядра. Не требует прав администратора и не запускает winws. Единственная запись на диск:
# пустые пользовательские списки в vendor\zapret\lists (их создаёт и обычный запуск NORMA).
# Запуск: powershell -ExecutionPolicy Bypass -File tools\selftest.ps1
# Код возврата = число проваленных проверок.
$env:NORMA_DIR = Split-Path -Parent $PSScriptRoot
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\lib.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\model.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\updates.ps1"), [Text.Encoding]::UTF8)))

$script:fail = 0
function Check([string]$Name, [bool]$Cond) {
    if ($Cond) { Write-Host ("  ok    " + $Name) -ForegroundColor Green }
    else { Write-Host ("  FAIL  " + $Name) -ForegroundColor Red; $script:fail++ }
}

Write-Host "NORMA selftest" -ForegroundColor Cyan
Initialize-NormaFiles
$all = @(Get-Strategies)
$z = @($all | Where-Object { $_.Source -eq "zapret" })
$n = @($all | Where-Object { $_.Source -eq "norma" })
Check ("стратегии zapret разобраны (найдено {0})" -f $z.Count) ($z.Count -ge 20)
Check ("стратегии NORMA загружены (найдено {0})" -f $n.Count) ($n.Count -ge 30)
Check "имена стратегий уникальны" ((@($all | Select-Object -ExpandProperty Name -Unique)).Count -eq $all.Count)
Check "в аргументах не осталось символа ^ (экранирование .bat снято)" (@($all | Where-Object { $_.ArgsTpl.Contains("^") }).Count -eq 0)

$leftTokens = 0
$missingFiles = 0
$unbalanced = 0
foreach ($s in $all) {
    $e = Expand-Args $s.ArgsTpl
    if ($e -match '%[A-Za-z]+%') { $leftTokens++ }
    if (([regex]::Matches($e, '"')).Count % 2 -ne 0) { $unbalanced++ }
    foreach ($m in [regex]::Matches($e, '"([^"]+\.(bin|txt))"')) {
        if (-not (Test-Path -LiteralPath $m.Groups[1].Value)) { $missingFiles++ }
    }
}
Check "после подстановки не осталось %переменных%" ($leftTokens -eq 0)
Check "кавычки в аргументах сбалансированы" ($unbalanced -eq 0)
Check ("все файлы из аргументов (.bin, .txt) существуют; нет: {0}" -f $missingFiles) ($missingFiles -eq 0)

$sorted = @(Get-SortedStrategies "youtube")
Check "первой в переборе идёт тонкая стратегия NORMA (если нет своих)" (($sorted[0].Source -eq "norma") -or ($sorted[0].Source -eq "user"))
$allP = @(Get-SortedStrategies "all")
Check "профиль «YouTube + Discord» не содержит тонких стратегий" (@($allP | Where-Object { $_.Scope -eq "youtube" }).Count -eq 0)
$q = @($sorted | Where-Object { $_.Source -eq "norma" -and $_.Family -eq "quic" })
$t = @($sorted | Where-Object { $_.Source -eq "norma" -and $_.Family -eq "tcp" })
if ($q.Count -gt 0 -and $t.Count -gt 0) {
    Check "TCP-стратегии NORMA идут раньше QUIC-вариантов" ((Get-StrategyRank $t[$t.Count - 1]) -lt (Get-StrategyRank $q[0]))
}
Check "цели проверки загружены" (@(Get-Targets "youtube").Count -gt 0)

# ранжирование бенчмарка
function New-Row([int]$I, [int]$Ok, [double]$Avg, [bool]$Harm) {
    return [pscustomobject]@{ Index = $I; Ok = $Ok; Avg = $Avg; Harm = $Harm }
}
Check "медиана нечётного числа значений" ((Get-Median @(3.0, 1.0, 2.0)) -eq 2.0)
Check "медиана чётного числа значений" ((Get-Median @(1.0, 2.0, 3.0, 4.0)) -eq 2.5)
$rowsT = @((New-Row 1 4 0.30 $false), (New-Row 2 4 0.20 $false), (New-Row 3 4 0.21 $false),
    (New-Row 4 4 0.60 $false), (New-Row 5 2 0.10 $false), (New-Row 6 4 0.10 $true))
Check "ранжирование по времени: ничья в пределах допуска решается порядком перебора" ((@(Sort-StrategyRows $rowsT | ForEach-Object { $_.Index }) -join ",") -eq "2,3,1,4,5")
Check "ломающие остальное стратегии не попадают в рейтинг" (@(Sort-StrategyRows $rowsT | Where-Object { $_.Index -eq 6 }).Count -eq 0)

# модель стратегии: разбор и обратная сборка, ключи эквивалентности, описания, справочник параметров
$mBad = 0
$mUnparsed = 0
foreach ($s in $all) {
    $mdl = ConvertTo-StrategyModel $s.ArgsTpl
    if ((ConvertFrom-StrategyModel $mdl) -ne (@(Split-ArgTokens $s.ArgsTpl) -join " ")) { $mBad++ }
    foreach ($seg in @($mdl.Segments)) { foreach ($o in @($seg.Options)) { if (-not $o.Name) { $mUnparsed++ } } }
}
Check ("модель: разбор и обратная сборка дают тот же текст (расхождений: {0})" -f $mBad) ($mBad -eq 0)
Check ("модель: все токены распознаны как параметры (нераспознанных: {0})" -f $mUnparsed) ($mUnparsed -eq 0)
$zKeys = @{}
foreach ($s in $z) { $k = Get-StrategyYoutubeKey $s; if ($k) { $zKeys[$k] = $true } }
$nTcp = @($n | Where-Object { $_.Family -eq "tcp" })
$noSrc = @($nTcp | Where-Object { -not $zKeys.ContainsKey((Get-StrategyYoutubeKey $_)) }).Count
Check ("модель: правило каждой тонкой стратегии NORMA есть среди стратегий zapret (без источника: {0})" -f $noSrc) ($noSrc -eq 0)
Check "модель: у каждой стратегии есть описание" (@($all | Where-Object { -not (Get-StrategySummary $_) }).Count -eq 0)
$ref = Get-OptionReference
$unk = @{}
foreach ($s in $all) { foreach ($seg in @((ConvertTo-StrategyModel $s.ArgsTpl).Segments)) { foreach ($o in @($seg.Options)) { if ($o.Name -and -not $ref.ContainsKey($o.Name)) { $unk[$o.Name] = $true } } } }
if ($unk.Count -gt 0) { Write-Host ("  ВНИМАНИЕ: у параметров нет описания в app\core\options.txt: " + (@($unk.Keys) -join ", ")) -ForegroundColor Yellow }

# игровой фильтр
Check "игровой фильтр: выключен это порт 12" ((@(Get-GameFilterTokens "off") -join ",") -eq "12,12")
Check "игровой фильтр: TCP и UDP" ((@(Get-GameFilterTokens "all") -join ",") -eq "1024-65535,1024-65535")
Check "игровой фильтр: только TCP" ((@(Get-GameFilterTokens "tcp") -join ",") -eq "1024-65535,12")
Check "игровой фильтр: только UDP" ((@(Get-GameFilterTokens "udp") -join ",") -eq "12,1024-65535")
$script:gameMode = "tcp"
Check "игровой фильтр применяется в аргументах" ((Expand-Args "--wf-tcp=%GameFilterTCP% --wf-udp=%GameFilterUDP%") -eq "--wf-tcp=1024-65535 --wf-udp=12")
$script:gameMode = "off"

# чужие .bat в strategies\user читаются так же, как general*.bat
$batDir = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-bat-" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $batDir -Force | Out-Null
    $batText = "@echo off`r`nstart `"x`" /min `"%~dp0bin\winws.exe`" --wf-tcp=443 ^`r`n  --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=^!`r`n"
    [IO.File]::WriteAllText((Join-Path $batDir "mine.bat"), $batText)
    $ub = @(Read-BatStrategies $batDir "user")
    Check "пользовательский .bat: найден" ($ub.Count -eq 1)
    if ($ub.Count -eq 1) { Check "пользовательский .bat: аргументы разобраны (перенос, ^!)" ($ub[0].ArgsTpl -eq "--wf-tcp=443 --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=!") }
} finally {
    Remove-Item -LiteralPath $batDir -Recurse -Force -ErrorAction SilentlyContinue
}

# версии: сравнение по частям как чисел (0.10 новее 0.9)
Check "версии: 0.10 новее 0.9" ([version]"0.10" -gt [version]"0.9")
Check "версии: 0.11 новее 0.10" ([version]"0.11" -gt [version]"0.10")
Check "версии: 0.9 старее 0.10" ([version]"0.9" -lt [version]"0.10")

# TCP timestamps: разбор вывода netsh, не зависящий от языка
Check "timestamps: английский вывод, выключены" ((Get-TcpTimestampsFromText "RFC 1323 Timestamps                 : disabled") -eq "disabled")
Check "timestamps: английский вывод, включены" ((Get-TcpTimestampsFromText "RFC 1323 Timestamps                 : enabled") -eq "enabled")
Check "timestamps: русский вывод" ((Get-TcpTimestampsFromText "Метки времени RFC 1323          : отключено") -eq "disabled")
Check "timestamps: неизвестный вывод" ((Get-TcpTimestampsFromText "что-то другое") -eq "unknown")
Check "timestamps: строка значения читается независимо от языка" ((Get-TcpTimestampsRawFromText "RFC 1323 Timestamps : Disabled") -eq "disabled")
Check "timestamps: неизвестный язык: значение есть, но не распознано" (((Get-TcpTimestampsRawFromText "Zeitstempel RFC 1323 : deaktiviert") -eq "deaktiviert") -and ((Get-TcpTimestampsFromText "Zeitstempel RFC 1323 : deaktiviert") -eq "unknown"))
Check "timestamps: нет строки со значением" ((Get-TcpTimestampsRawFromText "Receive Window Auto-Tuning Level : normal") -eq "")

# классы HTTP-ответов: отличаем блокировку (нет ответа) от ошибки самого сервера
Check "HTTP: классы ответов" (((Get-HttpClass "000") -eq "noresp") -and ((Get-HttpClass "") -eq "noresp") -and ((Get-HttpClass "204") -eq "ok") -and ((Get-HttpClass "301") -eq "redirect") -and ((Get-HttpClass "404") -eq "client") -and ((Get-HttpClass "503") -eq "server"))

# проверки скачанных списков
$ipLines = @(1..600 | ForEach-Object { "10.{0}.{1}.0/24" -f ($_ % 250), [int][math]::Floor($_ / 250) })
$ips = $ipLines -join "`n"
$doms = (1..40 | ForEach-Object { "d$_.example.com" }) -join "`n"
Check "списки: HTML отвергается" ($null -ne (Test-ListText "<html>x</html>" ""))
Check "списки: пустой ответ отвергается" ($null -ne (Test-ListText "" ""))
Check "списки: нормальный ответ принимается" ($null -eq (Test-ListText "a.com`r`nb.com" ""))
Check "списки: резкое уменьшение отвергается" ($null -ne (Test-ListText "x.com" $doms))
Check "ipset: корректный список принимается" ($null -eq (Test-IpsetText $ips ""))
Check "ipset: слишком мало записей отвергается" ($null -ne (Test-IpsetText "10.0.0.0/24" ""))
$okIp = @("1.2.3.4", "10.0.0.0/8", "255.255.255.255/32", "0.0.0.0/0", "2001:db8::/32", "::1", "2a00:1450::/16", "fe80::1/128")
$badIp = @("999.999.999.999/999", "1.2.3/24", "1.2.3.4/33", "2001:db8::/129", "abc", "1.2.3.4/", "1.2.3.4/-1", "0x1.2.3.4", "1.2.3.4%eth0", "1.2.3.4/24/24", "01.2.3.4", "256.1.1.1", "1.2.3.4/8x", "2001:db8:::1/32")
$okFail = @($okIp | Where-Object { -not (Test-IpEntry $_) })
$badFail = @($badIp | Where-Object { Test-IpEntry $_ })
Check ("ipset: корректные адреса принимаются (отвергнуто: {0})" -f ($okFail -join ", ")) ($okFail.Count -eq 0)
Check ("ipset: некорректные адреса отвергаются (принято: {0})" -f ($badFail -join ", ")) ($badFail.Count -eq 0)
$oneBad = @($ipLines) + @("999.999.999.999/999")
Check "ipset: одна плохая запись среди сотен отклоняет весь список" ($null -ne (Test-IpsetText ($oneBad -join "`n") ""))
Check "ipset: список исключений проверяется так же строго" (($null -eq (Test-IpListText "10.0.0.0/8`n192.168.0.0/16" "")) -and ($null -ne (Test-IpListText "10.0.0.0/8`n1.2.3.4/40" "")))
Check "ipset: мусор отвергается" ($null -ne (Test-IpsetText ((1..200 | ForEach-Object { "not-an-ip-$_" }) -join "`n") ""))

# режимы IPSet (во временной папке)
$oldLists = $script:listsDir
$script:listsDir = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-ipset-" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $script:listsDir -Force | Out-Null
    $live = Join-Path $script:listsDir "ipset-all.txt"
    [IO.File]::WriteAllText($live, "203.0.113.113/32`r`n")
    [IO.File]::WriteAllText(($live + ".backup"), (($ipLines -join "`r`n") + "`r`n"))
    Check "IPSet: заглушка это none" ((Get-IpsetMode) -eq "none")
    [void](Set-IpsetMode "any")
    Check "IPSet: пустой файл это any" ((Get-IpsetMode) -eq "any")
    [void](Set-IpsetMode "loaded")
    Check "IPSet: loaded берёт список из сохранённого" ((Get-IpsetMode) -eq "loaded")
    [void](Switch-IpsetMode)
    Check "IPSet: из loaded переключение даёт none" ((Get-IpsetMode) -eq "none")
    [void](Switch-IpsetMode)
    Check "IPSet: из none переключение даёт any" ((Get-IpsetMode) -eq "any")
    [void](Switch-IpsetMode)
    Check "IPSet: из any переключение даёт loaded" ((Get-IpsetMode) -eq "loaded")
    [void](Set-IpsetMode "none")
    [void](Set-IpsetMode "loaded")
    Check "IPSet: загруженный список не теряется при переключениях" (@(Get-ListLines ([IO.File]::ReadAllText($live))).Count -eq 600)
} finally {
    Remove-Item -LiteralPath $script:listsDir -Recurse -Force -ErrorAction SilentlyContinue
    $script:listsDir = $oldLists
}

# транзакционное обновление файлов (загрузка подменяется, всё во временной папке)
$oldData = $script:dataDir
$tdir = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-upd-" + [Guid]::NewGuid().ToString("N"))
$script:dataDir = Join-Path $tdir "data"
try {
    $dst = Join-Path $tdir "dest"
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    $fa = Join-Path $dst "a.txt"
    $fb = Join-Path $dst "b.txt"
    [IO.File]::WriteAllText($fa, "old1.com`r`nold2.com`r`n")
    [IO.File]::WriteAllText($fb, "oldb.com`r`n")
    $fetch = { param($u) if ($u -eq "u://a") { "new1.com`nnew2.com`nnew3.com" } elseif ($u -eq "u://b") { "newb.com`nnewb2.com" } else { throw "no such url" } }
    $items = @(@{ Name = "a.txt"; Dest = $fa; Url = "u://a"; Check = "list" }, @{ Name = "b.txt"; Dest = $fb; Url = "u://b"; Check = "list" })
    $r = Invoke-FileUpdate $items $fetch
    Check "обновление: успешное применение двух файлов" ($r.Ok -and ($r.Rollback -eq "none") -and (@($r.Details | Where-Object { $_.Status -eq "changed" }).Count -eq 2))
    Check "обновление: содержимое заменено" (@(Get-ListLines ([IO.File]::ReadAllText($fa))) -contains "new3.com")
    Check "обновление: резервная копия создана" ([bool]$r.Backup -and (Test-Path (Join-Path $r.Backup "a.txt")))
    $r2 = Invoke-FileUpdate $items $fetch
    Check "обновление: повтор без изменений" ($r2.Ok -and (@($r2.Details | Where-Object { $_.Status -eq "changed" }).Count -eq 0))
    $before = [IO.File]::ReadAllText($fa)
    $fetchBad = { param($u) if ($u -eq "u://a") { "zzz1.com`nzzz2.com" } else { "<html>blocked</html>" } }
    $r3 = Invoke-FileUpdate $items $fetchBad
    Check "обновление: плохой ответ по одному файлу отменяет всё" ((-not $r3.Ok) -and ($r3.Rollback -eq "none") -and ([IO.File]::ReadAllText($fa) -eq $before))
    $items2 = @(@{ Name = "a.txt"; Dest = $fa; Url = "u://x"; Check = "list" }, @{ Name = "bad.txt"; Dest = (Join-Path $dst "bad|name.txt"); Url = "u://x"; Check = "list" })
    $fetch2 = { param($u) "p1.com`np2.com`np3.com" }
    $r4 = Invoke-FileUpdate $items2 $fetch2
    Check "обновление: сбой записи откатывает уже применённые файлы" ((-not $r4.Ok) -and ($r4.Rollback -eq "ok") -and ([IO.File]::ReadAllText($fa) -eq $before))
    Check "обновление: сообщение об откате не обещает лишнего" ($r4.Error -match "отменены и проверены")
} finally {
    Remove-Item -LiteralPath $tdir -Recurse -Force -ErrorAction SilentlyContinue
    $script:dataDir = $oldData
}

# процессы winws: NORMA узнаёт свои по pid, времени запуска и пути, чужие и однофамильцы не трогаются
$oldPidFile = $script:winwsPidFile
$script:winwsPidFile = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-pids-" + [Guid]::NewGuid().ToString("N") + ".txt")
try {
    $me = Get-SelfStart
    Check "владение winws: время запуска этого процесса читается" ($me -gt 0)
    Save-OwnedEntries @(
        [pscustomobject]@{ Owner = $PID; OwnerStart = $me; Pid = 999997; Start = 1; Path = "C:\x y\winws.exe" },
        [pscustomobject]@{ Owner = 999999; OwnerStart = 1; Pid = 999998; Start = 1; Path = "C:\winws.exe" },
        [pscustomobject]@{ Owner = $PID; OwnerStart = ($me + 1); Pid = 999996; Start = 1; Path = "C:\winws.exe" })
    $read = @(Get-OwnedEntries)
    Check "владение winws: запись и чтение pid-файла с путём из пробелов" (($read.Count -eq 3) -and ($read[0].Path -eq "C:\x y\winws.exe") -and ($read[0].OwnerStart -eq $me))
    Check "владение winws: владелец узнаётся по pid и времени запуска" ((Test-OwnerAlive $read[0]) -and (-not (Test-OwnerAlive $read[1])) -and (-not (Test-OwnerAlive $read[2])))
    Stop-StaleWinws
    $left = @(Get-OwnedEntries)
    Check "владение winws: остатки мёртвого владельца и владельца с чужим временем запуска убраны" (($left.Count -eq 1) -and ($left[0].Pid -eq 999997))
    Check "владение winws: этот экземпляр не считает себя «другим»" (@(Get-OtherNormaOwners).Count -eq 0)
    # однофамилец: запись указывает на живой процесс с тем же pid, но это не winws (здесь текущий PowerShell): трогать нельзя
    $impostor = [pscustomobject]@{ Owner = 999999; OwnerStart = 1; Pid = $PID; Start = 1; Path = "C:\winws.exe" }
    Check "владение winws: чужой процесс с тем же pid не признаётся winws NORMA" ($null -eq (Get-VerifiedWinws $impostor))
    Stop-WinwsEntry $impostor
    Check "владение winws: чужой процесс с тем же pid не завершается" ($null -ne (Get-Process -Id $PID -ErrorAction SilentlyContinue))
    Save-OwnedEntries @()
    Check "владение winws: пустой список удаляет файл" (-not (Test-Path $script:winwsPidFile))
} finally {
    Remove-Item -LiteralPath $script:winwsPidFile -Force -ErrorAction SilentlyContinue
    $script:winwsPidFile = $oldPidFile
}

# контрольные суммы bin совпадают с манифестом
$man = @(Get-ChecksumManifest)
Check ("манифест контрольных сумм загружен (записей: {0})" -f $man.Count) ($man.Count -ge 4)
$badSum = 0
foreach ($e in $man) {
    $fp = Join-Path $script:binDir $e.Name
    if (-not (Test-Path $fp)) { $badSum++; continue }
    if ((Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash -ne $e.Hash) { $badSum++ }
}
Check ("файлы bin совпадают с манифестом (расхождений: {0})" -f $badSum) ($badSum -eq 0)

# версия берётся из файла VERSION
$vf = Join-Path $env:NORMA_DIR "VERSION"
if (Test-Path $vf) { Check "версия в коде совпадает с файлом VERSION" ($script:version -eq ([IO.File]::ReadAllText($vf)).Trim()) }

# память по сетям (во временный файл)
$oldState = $script:statePath
$script:statePath = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    Set-NetworkStrategy "Home|192.168.0.1" "general (ALT)"
    Set-NetworkStrategy "Work|10.0.0.1" "NORMA YT-03"
    Set-NetworkStrategy "Home|192.168.0.1" "general (ALT2)"
    Check "память по сетям: чтение" ((Get-NetworkStrategy "Work|10.0.0.1") -eq "NORMA YT-03")
    Check "память по сетям: перезапись" ((Get-NetworkStrategy "Home|192.168.0.1") -eq "general (ALT2)")
    Check "память по сетям: неизвестная сеть" ((Get-NetworkStrategy "Cafe|1.1.1.1") -eq "")
} finally {
    Remove-Item -LiteralPath $script:statePath -Force -ErrorAction SilentlyContinue
    $script:statePath = $oldState
}

Write-Host ""
if ($script:fail -eq 0) { Write-Host "Все проверки пройдены." -ForegroundColor Green } else { Write-Host ("Провалено проверок: {0}" -f $script:fail) -ForegroundColor Red }
exit $script:fail
