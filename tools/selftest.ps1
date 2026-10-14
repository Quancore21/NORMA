# NORMA: самопроверка ядра. Не требует прав администратора и не запускает winws. Единственная запись на диск:
# пустые пользовательские списки в vendor\zapret\lists (их создаёт и обычный запуск NORMA).
# Запуск: powershell -ExecutionPolicy Bypass -File tools\selftest.ps1
# Код возврата = число проваленных проверок.
$env:NORMA_DIR = Split-Path -Parent $PSScriptRoot
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\lib.ps1"), [Text.Encoding]::UTF8)))
. ([ScriptBlock]::Create([IO.File]::ReadAllText((Join-Path $env:NORMA_DIR "app\core\model.ps1"), [Text.Encoding]::UTF8)))

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
