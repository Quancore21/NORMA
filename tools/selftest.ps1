# NORMA: самопроверка ядра. Не требует прав администратора и не запускает winws. Единственная запись на диск:
# пустые пользовательские списки в vendor\zapret\lists (их создаёт и обычный запуск NORMA).
# Запуск: powershell -ExecutionPolicy Bypass -File tools\selftest.ps1
# Код возврата = число проваленных проверок.
$env:NORMA_DIR = Split-Path -Parent $PSScriptRoot
# собственное имя замка движка для самопроверки: она не должна занимать настоящий замок работающей NORMA
$env:NORMA_LEASE_NAME = "Global\NORMA-Selftest-" + [Guid]::NewGuid().ToString("N")
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\lib.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\model.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\updates.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\autostart.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\settings.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\selfupdate.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\plan.ps1"), [Text.Encoding]::UTF8)))

$script:fail = 0
$script:failNames = @()
function Check([string]$Name, [bool]$Cond) {
    if ($Cond) { Write-Host ("  ok    " + $Name) -ForegroundColor Green }
    else { Write-Host ("  FAIL  " + $Name) -ForegroundColor Red; $script:fail++; $script:failNames += $Name }
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

# искажение байтов для проверки строгого разбора (те же операции, что в tools\engine_ref.py)
function Invoke-Mutation([byte[]]$Bytes, [string]$Op) {
    $parts = $Op.Split(":")
    if ($parts[0] -eq "truncate") {
        $n = [int]$parts[1]
        $r = New-Object byte[] $n
        [Array]::Copy($Bytes, $r, $n)
        return ,$r
    }
    $b = [byte[]]$Bytes.Clone()
    $off = [int]$parts[1]
    $val = [int]$parts[2]
    switch ($parts[0]) {
        "set8" { $b[$off] = [byte]($val -band 255) }
        "set16" { $b[$off] = [byte](($val -shr 8) -band 255); $b[$off + 1] = [byte]($val -band 255) }
        "set24" { $b[$off] = [byte](($val -shr 16) -band 255); $b[$off + 1] = [byte](($val -shr 8) -band 255); $b[$off + 2] = [byte]($val -band 255) }
    }
    return ,$b
}

# ---------- планировщик приёмов: C# сверяется с эталоном (tests\engine-golden.json создан tools\engine_ref.py)
Check "планировщик: C# компилируется" (Initialize-Planner)
$cases = @()
if (Initialize-Planner) {
    $goldenPath = Join-Path $env:NORMA_DIR "tests\engine-golden.json"
    Check "планировщик: золотой файл найден" (Test-Path $goldenPath)
    $cases = @([IO.File]::ReadAllText($goldenPath, [Text.Encoding]::UTF8) | ConvertFrom-Json)
    $bad = @()
    $helloCache = @{}
    foreach ($c in $cases) {
        if (-not $helloCache.ContainsKey($c.hello)) { $helloCache[$c.hello] = [IO.File]::ReadAllBytes((Join-Path $script:binDir $c.hello)) }
        $bytes = $helloCache[$c.hello]
        if ($c.kind -eq "positions") { $got = [NormaCore.Planner]::DescribePositions($bytes, [string]$c.spec) }
        elseif ($c.kind -eq "hello") { $got = [NormaCore.Planner]::DescribeHello((Invoke-Mutation $bytes ([string]$c.op))) }
        else { $got = [NormaCore.Planner]::DescribePlan($bytes, [string]$c.modes, [string]$c.splitPos, [int]$c.seqovl, [int]$c.repeats, [string]$c.fooling, [int]$c.fakeLen) }
        if ($got -ne [string]$c.expect) { $bad += ("{0}: ожидалось {1}, получено {2}" -f $c.id, $c.expect, $got) }
    }
    Check ("планировщик: C# совпадает с эталоном (случаев {0}, расхождений {1})" -f $cases.Count, $bad.Count) (($cases.Count -gt 200) -and ($bad.Count -eq 0))
    foreach ($b1 in @($bad | Select-Object -First 5)) { Write-Host ("    " + $b1) -ForegroundColor Yellow }
    $mutBad = @($cases | Where-Object { $_.kind -eq "hello" -and $_.id -notmatch ':control$' -and $_.expect -ne "Ok:0" }).Count
    Check "разбор ClientHello: обрезанные данные, противоречивые длины и имя за пределами расширения дают отказ" (($mutBad -eq 0) -and (@($cases | Where-Object { $_.kind -eq "hello" -and $_.id -notmatch ':control$' }).Count -ge 60))
    Check "разбор ClientHello: настоящие образцы без изменений разбираются" (@($cases | Where-Object { $_.kind -eq "hello" -and $_.id -match ':control$' -and $_.expect -match '^Ok:1;' }).Count -ge 6)

    $sampleBytes = [IO.File]::ReadAllBytes((Join-Path $script:binDir "tls_clienthello_www_google_com.bin"))
    $planBad = 0
    foreach ($c in @($cases | Where-Object { $_.kind -eq "plan" -and $_.hello -eq "tls_clienthello_www_google_com.bin" })) {
        $nm = "NORMA YT-" + $c.id.Split(":")[1].Substring("norma-yt-".Length)
        $st1 = @($all | Where-Object { $_.Name -eq $nm })
        if ($st1.Count -ne 1) { $planBad++; continue }
        $pr = Get-StrategyPlan $st1[0] $sampleBytes
        if ((-not $pr) -or ([NormaCore.Planner]::Describe($pr.Plan) -ne [string]$c.expect)) { $planBad++ }
    }
    Check ("планировщик: план, построенный из модели стратегии, совпадает с эталоном (расхождений: {0})" -f $planBad) ($planBad -eq 0)
}

# ---------- настройки
$oldSettings = $script:settingsPath
$script:settingsPath = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-settings-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    $d0 = Get-Settings
    Check "настройки: значения по умолчанию" (($d0.autoUpdateNorma -eq "auto") -and ($d0.autoUpdateLists -eq $true) -and ($d0.updateCheckHours -eq 24))
    [IO.File]::WriteAllText($script:settingsPath, '{"autoUpdateNorma":"banana","autoUpdateLists":"yes","updateCheckHours":0}')
    $d1 = Get-Settings
    Check "настройки: некорректные значения заменяются значениями по умолчанию" (($d1.autoUpdateNorma -eq "auto") -and ($d1.autoUpdateLists -eq $true) -and ($d1.updateCheckHours -eq 24))
    Check "настройки: режим автообновления переключается по кругу" (((Switch-UpdateMode) -eq "notify") -and ((Switch-UpdateMode) -eq "off") -and ((Switch-UpdateMode) -eq "auto"))
    Check "настройки: автообновление списков переключается" (((Switch-ListsUpdate) -eq $false) -and ((Get-Settings).autoUpdateLists -eq $false) -and ((Switch-ListsUpdate) -eq $true))
    $d2 = Get-Settings
    $d2.updateCheckHours = 6
    [void](Save-Settings $d2)
    Check "настройки: сохранение и чтение" ((Get-Settings).updateCheckHours -eq 6)
} finally {
    Remove-Item -LiteralPath $script:settingsPath -Force -ErrorAction SilentlyContinue
    $script:settingsPath = $oldSettings
}

# ---------- автозапуск и фоновый режим (без обращения к планировщику заданий)
Check "автозапуск: задача запускает app\background.ps1 напрямую (-File), путь в кавычках" ((Get-BackgroundArgs) -eq ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path $script:root "app\background.ps1")))
$oldRoot = $script:root
$script:root = "C:\Users\O'Brien\My Apps\NORMA"
$quoted = Get-BackgroundArgs
$script:root = $oldRoot
Check "автозапуск: путь с пробелом и апострофом остаётся корректным" ($quoted -match '-File "C:\\Users\\O''Brien\\My Apps\\NORMA\\app\\background.ps1"$')
Check "автозапуск: файл-запускатель существует" (Test-Path (Join-Path $script:root "app\background.ps1"))
$oldStatus = $script:statusPath
$oldPidPath = $script:pidPath
$script:statusPath = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-status-" + [Guid]::NewGuid().ToString("N") + ".json")
$script:pidPath = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-bgpid-" + [Guid]::NewGuid().ToString("N") + ".txt")
try {
    Write-BackgroundStatus "running" "проверка" "NORMA YT-01" "net|1.1.1.1"
    $bs = Read-BackgroundStatus
    Check "фон: состояние записывается и читается" (($bs.state -eq "running") -and ($bs.strategy -eq "NORMA YT-01") -and ($bs.pid -eq $PID) -and ($bs.network -eq "net|1.1.1.1"))
    Check "фон: человекочитаемые названия состояний" (((Get-StateText "picking") -eq "подбирает стратегию") -and ((Get-StateText "stopped") -eq "остановлен"))
    Write-BackgroundPid
    $bp = Get-BackgroundProcess
    Check "фон: процесс опознаётся по pid и времени запуска" ($bp -and ($bp.Id -eq $PID))
    [IO.File]::WriteAllText($script:pidPath, ("{0}|{1}" -f $PID, 1))
    Check "фон: чужое время запуска не принимается за фоновый процесс" ($null -eq (Get-BackgroundProcess))
    [IO.File]::WriteAllText($script:pidPath, "мусор")
    Check "фон: повреждённый pid-файл не ломает проверку" ($null -eq (Get-BackgroundProcess))
    # старый формат (только pid) и нулевое время запуска не считаются подтверждением, даже если pid принадлежит живому PowerShell
    [IO.File]::WriteAllText($script:pidPath, [string]$PID)
    Check "фон: pid-файл только с pid текущего PowerShell не распознаётся как фоновый NORMA" ($null -eq (Get-BackgroundProcess))
    [IO.File]::WriteAllText($script:pidPath, ("{0}|0" -f $PID))
    Check "фон: нулевое время запуска не подтверждает владение" ($null -eq (Get-BackgroundProcess))
    $ciSelf = $null
    try { $ciSelf = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = {0}" -f $PID) -ErrorAction Stop } catch { $ciSelf = $null }
    if ($ciSelf -and $ciSelf.CommandLine) { Check "фон: по командной строке текущий процесс не похож на фоновый NORMA" (-not (Test-LooksLikeBackground (Get-Process -Id $PID))) }
} finally {
    Remove-Item -LiteralPath $script:statusPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:pidPath -Force -ErrorAction SilentlyContinue
    $script:statusPath = $oldStatus
    $script:pidPath = $oldPidPath
}

# ---------- реестр экземпляров NORMA и блокировщики обновления
$oldInst = $script:instancesFile
$oldOwn = $script:winwsPidFile
$oldBgPid = $script:pidPath
$script:instancesFile = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-inst-" + [Guid]::NewGuid().ToString("N") + ".txt")
$script:winwsPidFile = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-own-" + [Guid]::NewGuid().ToString("N") + ".txt")
$script:pidPath = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-bg-" + [Guid]::NewGuid().ToString("N") + ".txt")
$helper = $null
try {
    Register-NormaInstance "interactive"
    Check "экземпляры: регистрация и чтение" (@(Get-InstanceEntries | Where-Object { $_.Pid -eq $PID }).Count -eq 1)
    Check "экземпляры: этот процесс не считается «другим»" (@(Get-OtherNormaInstances) -notcontains $PID)
    Check "блокировщики обновления: без других экземпляров их нет" (@(Get-UpdateBlockers | Where-Object { $_ -match "другой экземпляр" }).Count -eq 0)
    $helper = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command Start-Sleep -Seconds 90" -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 700
    $hs = Get-ProcStartTicks $helper
    Check "экземпляры: время запуска чужого процесса читается" ($hs -gt 0)
    Save-InstanceEntries (@(Get-InstanceEntries) + @([pscustomobject]@{ Pid = $helper.Id; Start = $hs; Kind = "background" }))
    Check "экземпляры: другой живой экземпляр обнаруживается" (@(Get-OtherNormaInstances) -contains $helper.Id)
    Check "блокировщики обновления: другой экземпляр останавливает фоновое обновление, чужой процесс не затрагивается" ((@(Get-UpdateBlockers | Where-Object { $_ -match "другой экземпляр" }).Count -ge 1) -and (-not $helper.HasExited))
    Save-InstanceEntries @([pscustomobject]@{ Pid = $helper.Id; Start = 1; Kind = "background" })
    Check "экземпляры: запись с чужим временем запуска игнорируется" (@(Get-OtherNormaInstances) -notcontains $helper.Id)
    Save-InstanceEntries @([pscustomobject]@{ Pid = $helper.Id; Start = 0; Kind = "background" })
    Check "экземпляры: запись без времени запуска игнорируется" (@(Get-OtherNormaInstances) -notcontains $helper.Id)
    [IO.File]::WriteAllText($script:pidPath, ("{0}|{1}" -f $helper.Id, $hs))
    Check "экземпляры: фоновый процесс из pid-файла учитывается как другой экземпляр" (@(Get-OtherNormaInstances) -contains $helper.Id)
    Register-NormaInstance "interactive"
    Unregister-NormaInstance
    Check "экземпляры: снятие с учёта" (@(Get-InstanceEntries | Where-Object { $_.Pid -eq $PID }).Count -eq 0)
} finally {
    if ($helper) { try { $helper.Kill() } catch {} }
    Remove-Item -LiteralPath $script:instancesFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:winwsPidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:pidPath -Force -ErrorAction SilentlyContinue
    $script:instancesFile = $oldInst
    $script:winwsPidFile = $oldOwn
    $script:pidPath = $oldBgPid
}

# ---------- замок движка: взаимное исключение между процессами (настоящие процессы PowerShell)
function Start-LeaseHelper([string]$Body, [long]$AtTicks, [int]$HoldSeconds) {
    $cmd = @'
$ErrorActionPreference = 'Stop'
$t = [IO.File]::ReadAllText((Join-Path $env:NORMA_DIR 'app\core\lib.ps1'), [Text.Encoding]::UTF8)
. ([ScriptBlock]::Create($t))
$wait = [datetime]::FromFileTimeUtc(@AT@) - [datetime]::UtcNow
if ($wait.TotalMilliseconds -gt 0) { Start-Sleep -Milliseconds ([int]$wait.TotalMilliseconds) }
@BODY@
'@
    $cmd = $cmd.Replace("@AT@", [string]$AtTicks).Replace("@HOLD@", [string]$HoldSeconds).Replace("@BODY@", $Body.Replace("@HOLD@", [string]$HoldSeconds))
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $errPath = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-helper-" + [Guid]::NewGuid().ToString("N") + ".err")
    $hp = Start-Process -FilePath "powershell.exe" -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + $enc) -WindowStyle Hidden -PassThru -RedirectStandardError $errPath
    $null = $hp.Handle
    $script:helperErr[[string]$hp.Id] = $errPath
    return $hp
}
$script:helperErr = @{}
# Ждёт завершения вспомогательного процесса и возвращает код выхода. Если он не 0 и не 3 (то есть процесс упал), показывает текст ошибки из его потока ошибок.
function Wait-LeaseHelper($Proc, [int]$Seconds = 120) {
    $code = -1
    if ($Proc.WaitForExit($Seconds * 1000)) { $code = $Proc.ExitCode } else { try { $Proc.Kill() } catch {} }
    $ep = $script:helperErr[[string]$Proc.Id]
    if (($code -ne 0) -and ($code -ne 3) -and $ep -and (Test-Path $ep)) {
        Write-Host ("    вспомогательный процесс завершился с кодом {0}; ошибка:" -f $code) -ForegroundColor Yellow
        try { foreach ($l in @([IO.File]::ReadAllLines($ep) | Select-Object -First 6)) { Write-Host ("      " + $l) -ForegroundColor Yellow } } catch {}
    }
    if ($ep) { Remove-Item -LiteralPath $ep -Force -ErrorAction SilentlyContinue }
    return $code
}
$leaseBody = "if (Enter-EngineLease 0) { Start-Sleep -Seconds @HOLD@; exit 0 } else { exit 3 }"

Check "замок: свободный замок получается" (Enter-EngineLease 0)
$h1 = Start-LeaseHelper $leaseBody 0 1
$c1 = Wait-LeaseHelper $h1
Check ("замок: занятый замок другой процесс не получает (код выхода {0}, ожидался 3)" -f $c1) ($c1 -eq 3)
Check "замок: повторное получение тем же процессом допускается (счётчик 2)" ((Enter-EngineLease 0) -and ($script:leaseDepth -eq 2))
Exit-EngineLease
$h2 = Start-LeaseHelper $leaseBody 0 1
$c2 = Wait-LeaseHelper $h2
Check ("замок: пока счётчик не обнулён, замок занят (код выхода {0}, ожидался 3)" -f $c2) ($c2 -eq 3)
Exit-EngineLease
Check "замок: после полного освобождения счётчик нулевой" ($script:leaseDepth -eq 0)
$h3 = Start-LeaseHelper $leaseBody 0 1
$c3 = Wait-LeaseHelper $h3
Check ("замок: освобождённый замок получает другой процесс (код выхода {0}, ожидался 0)" -f $c3) ($c3 -eq 0)
Check "замок: замок завершившегося процесса достаётся следующему (брошенный замок не зависает)" (Enter-EngineLease 0)
Exit-EngineLease

# одновременный старт четырёх экземпляров: ровно один получает замок
$atRace = [datetime]::UtcNow.AddSeconds(5).ToFileTimeUtc()
$raceProcs = @(1..4 | ForEach-Object { Start-LeaseHelper $leaseBody $atRace 6 })
$raceCodes = @($raceProcs | ForEach-Object { Wait-LeaseHelper $_ 120 })
$winners = @($raceCodes | Where-Object { $_ -eq 0 }).Count
$losers = @($raceCodes | Where-Object { $_ -eq 3 }).Count
Check ("замок: при одновременном старте четырёх экземпляров замок получает ровно один (получили: {0}, отказ: {1})" -f $winners, $losers) (($winners -eq 1) -and ($losers -eq 3))

# одновременная регистрация четырёх экземпляров не теряет записей
$oldInst2 = $script:instancesFile
$script:instancesFile = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-race-" + [Guid]::NewGuid().ToString("N") + ".txt")
$env:NORMA_INSTANCES_FILE = $script:instancesFile
$regProcs = @()
try {
    $atReg = [datetime]::UtcNow.AddSeconds(5).ToFileTimeUtc()
    $regBody = "Register-NormaInstance 'interactive'; Start-Sleep -Seconds @HOLD@; exit 0"
    $regProcs = @(1..4 | ForEach-Object { Start-LeaseHelper $regBody $atReg 8 })
    $regSw = [Diagnostics.Stopwatch]::StartNew()
    while ($regSw.Elapsed.TotalSeconds -lt 30) {
        if (@(Get-InstanceEntries).Count -ge 4) { break }
        Start-Sleep -Milliseconds 300
    }
    $regIds = @($regProcs | ForEach-Object { $_.Id })
    $found = @(Get-InstanceEntries | Where-Object { $regIds -contains $_.Pid })
    Check ("реестр: четыре одновременные регистрации не теряют записей (найдено: {0})" -f $found.Count) ($found.Count -eq 4)
} finally {
    foreach ($rp in $regProcs) { try { if (-not $rp.HasExited) { $rp.Kill() } } catch {} }
    Remove-Item -LiteralPath $script:instancesFile -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\NORMA_INSTANCES_FILE -ErrorAction SilentlyContinue
    $script:instancesFile = $oldInst2
}

# ---------- автообновление: срок проверки, сумма, безопасная распаковка, проверка пакета, замена папок
$fmt = "yyyy-MM-dd HH:mm:ss"
Check "обновления: срок проверки" ((Test-UpdateDue "" 24) -and (-not (Test-UpdateDue (Get-Date -Format $fmt) 24)) -and (Test-UpdateDue ((Get-Date).AddHours(-30).ToString($fmt)) 24) -and (Test-UpdateDue ((Get-Date).AddDays(5).ToString($fmt)) 24) -and (Test-UpdateDue "не дата" 24))
Check "обновления: контрольная сумма берётся из файла «hex  имя»" ((Get-Sha256FromText ("{0}  NORMA-0.12.zip" -f ("ab" * 32))) -eq ("AB" * 32))
Check "обновления: текст без суммы даёт пустое значение" ((Get-Sha256FromText "нет суммы") -eq "")

$utmp = Join-Path ([IO.Path]::GetTempPath()) ("norma-selftest-upd2-" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $utmp -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # безопасная распаковка: нормальный архив распаковывается, архив с выходом за пределы папки отвергается
    $zipOk = Join-Path $utmp "ok.zip"
    $zipEvil = Join-Path $utmp "evil.zip"
    foreach ($spec in @(@($zipOk, "pkg\sub\file.txt"), @($zipEvil, "..\evil.txt"))) {
        $za = [IO.Compression.ZipFile]::Open($spec[0], [IO.Compression.ZipArchiveMode]::Create)
        $en = $za.CreateEntry($spec[1])
        $sw = New-Object IO.StreamWriter($en.Open())
        $sw.Write("data")
        $sw.Dispose()
        $za.Dispose()
    }
    Check "распаковка: тестовые архивы созданы" ((Test-Path $zipOk) -and (Test-Path $zipEvil))
    $outOk = Join-Path $utmp "out-ok"
    try { Expand-ZipSafe $zipOk $outOk } catch { Write-Host ("    Expand-ZipSafe: " + $_.Exception.Message) -ForegroundColor Yellow }
    Check "распаковка: обычный архив распаковывается" (Test-Path (Join-Path $outOk "pkg\sub\file.txt"))
    $threw = $false
    try { Expand-ZipSafe $zipEvil (Join-Path $utmp "out-evil") } catch { $threw = $true }
    Check "распаковка: имя с выходом за пределы папки отвергается" ($threw -and (-not (Test-Path (Join-Path $utmp "evil.txt"))))

    # пакет: текущая папка проекта сама является корректным пакетом
    Check "пакет: структура, версия и контрольные суммы текущей папки проходят проверку" ($null -eq (Test-PackageTree $env:NORMA_DIR $script:version))
    Check "пакет: чужой номер версии отвергается" ($null -ne (Test-PackageTree $env:NORMA_DIR "99.99"))
    $tamper = Join-Path $utmp "tamper"
    New-Item -ItemType Directory -Path (Join-Path $tamper "app\core") -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:NORMA_DIR "app\core\checksums.txt") -Destination (Join-Path $tamper "app\core\checksums.txt")
    New-Item -ItemType Directory -Path (Join-Path $tamper "vendor\zapret") -Force | Out-Null
    Copy-Item -LiteralPath $script:binDir -Destination (Join-Path $tamper "vendor\zapret\bin") -Recurse
    Check "пакет: контрольные суммы копии bin совпадают" (@(Get-BinMismatches $tamper).Count -eq 0)
    $victim = Join-Path $tamper "vendor\zapret\bin\WinDivert64.sys"
    $vb = [IO.File]::ReadAllBytes($victim)
    $vb[100] = [byte](($vb[100] + 1) % 256)
    [IO.File]::WriteAllBytes($victim, $vb)
    Check "пакет: изменённый файл bin обнаруживается" (@(Get-BinMismatches $tamper) -contains "WinDivert64.sys")

    # замена папок на синтетических деревьях
    function New-Tree([string]$Dir, [string]$Tag) {
        foreach ($rel in @("app", "vendor", "strategies\norma", "strategies\user", "data")) { New-Item -ItemType Directory -Path (Join-Path $Dir $rel) -Force | Out-Null }
        [IO.File]::WriteAllText((Join-Path $Dir "app\a.txt"), $Tag)
        [IO.File]::WriteAllText((Join-Path $Dir "vendor\v.txt"), ("v" + $Tag))
        [IO.File]::WriteAllText((Join-Path $Dir ("strategies\norma\" + $Tag + ".args")), $Tag)
        [IO.File]::WriteAllText((Join-Path $Dir "NORMA.bat"), ("bat" + $Tag))
        [IO.File]::WriteAllText((Join-Path $Dir "VERSION"), $Tag)
    }
    # A: обычная замена
    $rA = Join-Path $utmp "A-root"; $nA = Join-Path $utmp "A-new"; $bA = Join-Path $utmp "A-backup"
    New-Tree $rA "old"; New-Tree $nA "new"
    [IO.File]::WriteAllText((Join-Path $rA "strategies\user\mine.args"), "mine")
    [IO.File]::WriteAllText((Join-Path $rA "data\keep.txt"), "keep")
    [IO.File]::WriteAllText((Join-Path $nA "data\bad.txt"), "bad")
    New-Item -ItemType Directory -Path (Join-Path $nA "tests") -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $nA "tests\t.txt"), "t")
    $swA = Invoke-TreeSwap $nA $rA $bA $false
    Check "замена папок: успешна" ($swA.Ok -and ($swA.Rollback -eq "none"))
    Check "замена папок: файлы новой версии на месте, лишнего не осталось" (([IO.File]::ReadAllText((Join-Path $rA "app\a.txt")) -eq "new") -and ([IO.File]::ReadAllText((Join-Path $rA "VERSION")) -eq "new") -and (Test-Path (Join-Path $rA "strategies\norma\new.args")) -and (-not (Test-Path (Join-Path $rA "strategies\norma\old.args"))) -and (Test-Path (Join-Path $rA "tests\t.txt")))
    Check "замена папок: данные пользователя не тронуты" ((Test-Path (Join-Path $rA "strategies\user\mine.args")) -and (Test-Path (Join-Path $rA "data\keep.txt")) -and (-not (Test-Path (Join-Path $rA "data\bad.txt"))))
    Check "замена папок: старая версия сохранена в резервной копии" (([IO.File]::ReadAllText((Join-Path $bA "app\a.txt")) -eq "old") -and ([IO.File]::ReadAllText((Join-Path $bA "VERSION")) -eq "old"))
    # B: NORMA.bat не заменяется, если окно запущено из него
    $rB = Join-Path $utmp "B-root"; $nB = Join-Path $utmp "B-new"
    New-Tree $rB "old"; New-Tree $nB "new"
    $swB = Invoke-TreeSwap $nB $rB (Join-Path $utmp "B-backup") $true
    Check "замена папок: NORMA.bat пропускается, остальное заменяется" ($swB.Ok -and ([IO.File]::ReadAllText((Join-Path $rB "NORMA.bat")) -eq "batold") -and ([IO.File]::ReadAllText((Join-Path $rB "app\a.txt")) -eq "new"))
    # C: сбой посередине (в резервной папке на месте vendor лежит файл): откат всего
    $rC = Join-Path $utmp "C-root"; $nC = Join-Path $utmp "C-new"; $bC = Join-Path $utmp "C-backup"
    New-Tree $rC "old"; New-Tree $nC "new"
    New-Item -ItemType Directory -Path (Join-Path $nC "tests") -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $nC "tests\t.txt"), "t")
    New-Item -ItemType Directory -Path $bC -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $bC "vendor"), "блокирует перемещение")
    $swC = Invoke-TreeSwap $nC $rC $bC $false
    Check "замена папок: сбой не проходит молча" ((-not $swC.Ok) -and ($swC.Rollback -eq "ok"))
    Check "замена папок: после сбоя прежняя версия восстановлена полностью" (([IO.File]::ReadAllText((Join-Path $rC "app\a.txt")) -eq "old") -and ([IO.File]::ReadAllText((Join-Path $rC "VERSION")) -eq "old") -and ([IO.File]::ReadAllText((Join-Path $rC "NORMA.bat")) -eq "batold") -and ([IO.File]::ReadAllText((Join-Path $rC "vendor\v.txt")) -eq "vold") -and (Test-Path (Join-Path $rC "strategies\norma\old.args")) -and (-not (Test-Path (Join-Path $rC "tests"))))
    # данные пользователя переносятся в новый пакет
    $uRoot = Join-Path $utmp "U-root"; $uNew = Join-Path $utmp "U-new"
    New-Item -ItemType Directory -Path (Join-Path $uRoot "vendor\zapret\lists") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $uNew "vendor\zapret") -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $uRoot "vendor\zapret\lists\list-general-user.txt"), "my.example")
    [IO.File]::WriteAllText((Join-Path $uRoot "vendor\zapret\lists\ipset-all.txt"), "10.0.0.0/8")
    Copy-UserDataToPackage $uRoot $uNew
    Check "обновление: пользовательские списки и режим IPSet переносятся в новый пакет" (([IO.File]::ReadAllText((Join-Path $uNew "vendor\zapret\lists\list-general-user.txt")) -eq "my.example") -and ([IO.File]::ReadAllText((Join-Path $uNew "vendor\zapret\lists\ipset-all.txt")) -eq "10.0.0.0/8"))
} finally {
    Remove-Item -LiteralPath $utmp -Recurse -Force -ErrorAction SilentlyContinue
}

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
if ($script:fail -eq 0) { Write-Host "Все проверки пройдены." -ForegroundColor Green }
else {
    Write-Host ("Провалено проверок: {0}" -f $script:fail) -ForegroundColor Red
    foreach ($fn in $script:failNames) { Write-Host ("  FAILED: " + $fn) -ForegroundColor Red }
}
exit $script:fail
