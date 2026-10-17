# NORMA: включает обход для YouTube. Работает, пока открыто это окно; при закрытии всё возвращается как было.
# Принципы: 1) трогаем только то, что реально заблокировано (определяется проверкой);
#           2) перед включением приём проверяется, в том числе на обычных сайтах, и если он их ломает, не включается;
#           3) во время работы идёт контроль, и при поломке обычных сайтов обход отключается сам.
$root = $env:NORMA_DIR
if (-not $root) { $root = (Get-Location).Path }
$log = New-Object 'System.Collections.Generic.List[string]'
function Say([string]$Text, [string]$Color = "Gray") { Write-Host $Text -ForegroundColor $Color; $log.Add($Text) }

Say "NORMA: обход для YouTube" "Cyan"
Say ("Дата: {0}; Windows {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm"), [Environment]::OSVersion.VersionString)

# ---------- проверки
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Say "Нужны права администратора: запустите NORMA.bat заново." "Red"; return }
if (-not [Environment]::Is64BitProcess) { Say "Нужен 64-битный PowerShell." "Red"; return }

$wd = Join-Path $root "vendor\zapret\bin"
$dll = Join-Path $wd "WinDivert.dll"
if (-not (Test-Path $dll) -or -not (Test-Path (Join-Path $wd "WinDivert64.sys"))) {
    Say "Не найден WinDivert. WinDivert должен лежать в папке bin (идёт вместе с NORMA)." "Red"; return
}

$running = @(Get-Process -Name "goodbyedpi", "winws" -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Say ("Запущено: {0}. Они конфликтуют с NORMA." -f (($running | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ", ")) "Yellow"
    $a = Read-Host "Остановить их? (д/н)"
    if ($a -match "^[дДyY]") { $running | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
    else { Say "Тогда включить NORMA нельзя." "Red"; return }
}

if (-not ("Norma.Lab" -as [type])) {
    Say "Подготавливаю движок..."
    try {
        $cs = [IO.File]::ReadAllText((Join-Path $root "app\native\NormaLab.cs"), [Text.Encoding]::UTF8)
        Add-Type -TypeDefinition $cs -Language CSharp
    } catch {
        Say ("ОШИБКА КОМПИЛЯЦИИ: " + $_.Exception.Message) "Red"
        if ($_.Exception.InnerException) { Say $_.Exception.InnerException.Message "Red" }
        return
    }
}
$initErr = [Norma.Lab]::Init($dll)
if ($initErr) { Say "Не удалось загрузить WinDivert.dll: $initErr" "Red"; return }

# ---------- кандидаты: (суффикс домена, хост для проверки)
$cands = @(
    @("youtube.com", "www.youtube.com"), @("googlevideo.com", "redirector.googlevideo.com"), @("ytimg.com", "i.ytimg.com"),
    @("ggpht.com", "yt3.ggpht.com"), @("youtu.be", "youtu.be"), @("youtubei.googleapis.com", "youtubei.googleapis.com"),
    @("gstatic.com", "www.gstatic.com"), @("googleusercontent.com", "lh3.googleusercontent.com"), @("google.com", "www.google.com")
)
$extra = @()
$hp = Join-Path $root "app\native\youtube-hosts.txt"
if (Test-Path $hp) {
    $extra = @([IO.File]::ReadAllLines($hp, [Text.Encoding]::UTF8) | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -and -not $_.StartsWith("#") })
}

$googleRanges = @(
    @("142.250.0.0", "142.251.255.255"), @("172.217.0.0", "172.217.255.255"), @("74.125.0.0", "74.125.255.255"),
    @("64.233.160.0", "64.233.191.255"), @("173.194.0.0", "173.194.255.255"), @("216.58.192.0", "216.58.223.255"),
    @("209.85.128.0", "209.85.255.255"), @("108.177.0.0", "108.177.127.255"), @("192.178.0.0", "192.179.255.255"),
    @("216.239.32.0", "216.239.63.255"), @("172.253.0.0", "172.253.255.255")
)
function Get-RangeParts { $googleRanges | ForEach-Object { "(ip.DstAddr >= {0} and ip.DstAddr <= {1})" -f $_[0], $_[1] } }

function Get-Ips([string]$HostName) {
    try { return @([System.Net.Dns]::GetHostAddresses($HostName) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | ForEach-Object { $_.ToString() }) } catch { return @() }
}

$targets = @{}
$allIps = New-Object System.Collections.ArrayList
foreach ($c in $cands) {
    $ips = @(Get-Ips $c[1])
    foreach ($ip in ($ips | Select-Object -First 6)) { if (-not $allIps.Contains($ip)) { [void]$allIps.Add($ip) } }
    $targets[$c[1]] = $null
    foreach ($ip in ($ips | Select-Object -First 4)) { if ([Norma.Lab]::TcpOk($ip, 443, 2500)) { $targets[$c[1]] = $ip; break } }
}

# фильтр ядра: только пакеты с данными к серверам Google; остальной интернет вообще не затрагивается
$parts = New-Object System.Collections.ArrayList
foreach ($p in (Get-RangeParts)) { [void]$parts.Add($p) }
foreach ($ip in ($allIps | Select-Object -First 30)) { [void]$parts.Add("ip.DstAddr == $ip") }
$engineFilter = "outbound and ip and tcp.DstPort == 443 and tcp.PayloadLength > 0 and (" + ($parts -join " or ") + ")"

$allSuffixes = @($cands | ForEach-Object { $_[0] }) + $extra
$e = $null
try { $e = [Norma.Divert]::OpenEngine($engineFilter, [string[]]$allSuffixes) }
catch {
    $m = $_.Exception.Message
    if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
    Say "Не удалось открыть WinDivert ($m): нет прав или драйвер заблокирован (антивирус/Защитник)." "Red"
    return
}
$quic = $null
$finalNote = ""
try {
    # ---------- шаг 1: что реально заблокировано (движок пока ничего не меняет)
    Say ""
    Say "Шаг 1. Проверяю, что у вас заблокировано..." "Cyan"
    $blocked = @()
    $open = @()
    foreach ($c in $cands) {
        $ip = $targets[$c[1]]
        if (-not $ip) { Say ("  {0,-30} нет TCP-соединения (пропускаю)" -f $c[1]) "DarkGray"; continue }
        $r = [Norma.Lab]::TestOne($ip, $c[1], 3000)
        if ($r.Ok) { Say ("  {0,-30} открывается без обхода" -f $c[1]) "Green"; $open += ,$c }
        else { Say ("  {0,-30} ЗАБЛОКИРОВАН" -f $c[1]) "Yellow"; $blocked += ,$c }
    }
    if ($blocked.Count -eq 0) {
        Say ""
        Say "Всё проверенное открывается и без обхода. NORMA сейчас не нужна." "Green"
        return
    }
    $ytHost = $blocked[0][1]
    $ytIp = $targets[$ytHost]
    $applyList = @($blocked | ForEach-Object { $_[0] }) + $extra
    $e.Hosts = [string[]]$applyList
    Say ("  Обход будет применяться только к: {0}" -f ($applyList -join ", "))

    # контрольный (обычный, незаблокированный) сайт: обход не имеет права его ломать
    $ctrlHost = $null; $ctrlIp = $null
    foreach ($c in $open) { if ($c[0] -eq "google.com") { $ctrlHost = $c[1]; $ctrlIp = $targets[$c[1]] } }
    if (-not $ctrlHost -and $open.Count -gt 0) { $ctrlHost = $open[0][1]; $ctrlIp = $targets[$ctrlHost] }
    $ctrlBigValid = $false
    if ($ctrlHost) { $ctrlBigValid = ([Norma.Lab]::RawHelloProbe($ctrlIp, $ctrlHost, 1800, $true, 3000) -eq "OK") }

    # ---------- шаг 2: подбор приёма и режима, с проверкой на «браузерных» (большых) рукопожатиях и на контроле
    Say ""
    Say "Шаг 2. Подбираю приём (проверка на обычных и на больших рукопожатиях, как у браузера)..." "Cyan"
    $names = New-Object System.Collections.ArrayList
    $jp = Join-Path $root "data\lab-result.json"
    if (Test-Path $jp) {
        try {
            $j = [IO.File]::ReadAllText($jp, [Text.Encoding]::UTF8) | ConvertFrom-Json
            foreach ($r in @($j.results)) { if ($r.strategy -and -not $names.Contains([string]$r.strategy)) { [void]$names.Add([string]$r.strategy) } }
        } catch {}
    }
    foreach ($d in @("fake(badsum,x1) + disorder@host-mid", "fake(badsum,x1) + split@host-mid", "fake(badsum,x4) + disorder@host-mid", "fake(badsum,x4) + split@host-mid")) {
        if (-not $names.Contains($d)) { [void]$names.Add($d) }
    }

    $best = $null; $bestAssemble = $true; $bestScore = -1; $bestTotal = 0
    $tested = 0
    foreach ($n in ($names | Select-Object -First 4)) {
        $s = [Norma.Lab]::FindByName($n)
        if (-not $s) { continue }
        foreach ($asm in @($true, $false)) {
            $tested++
            $e.Assemble = $asm
            $e.Cur = $s
            $score = 0; $total = 0; $harm = $false
            # а) обычное рукопожатие на заблокированных хостах
            $hostsA = @($blocked | Select-Object -First 4)
            foreach ($c in $hostsA) {
                $ip = $targets[$c[1]]; $total++
                if ([Norma.Lab]::TestOne($ip, $c[1], 3000).Ok) { $score++ }
            }
            # б) большое рукопожатие (в нескольких пакетах): имя в первом пакете и во втором
            $total += 2
            if ([Norma.Lab]::RawHelloProbe($ytIp, $ytHost, 1800, $false, 3000) -eq "OK") { $score++ }
            if ([Norma.Lab]::RawHelloProbe($ytIp, $ytHost, 1800, $true, 3000) -eq "OK") { $score++ }
            # в) контроль: обычный сайт не должен пострадать
            $ctrlTxt = "нет контроля"
            if ($ctrlHost) {
                $c1 = [Norma.Lab]::TestOne($ctrlIp, $ctrlHost, 3000).Ok
                $c2 = $true
                if ($ctrlBigValid) { $c2 = ([Norma.Lab]::RawHelloProbe($ctrlIp, $ctrlHost, 1800, $true, 3000) -eq "OK") }
                if (-not ($c1 -and $c2)) { $harm = $true }
                $ctrlTxt = if ($harm) { "КОНТРОЛЬ СЛОМАН" } else { "контроль ок" }
            }
            $modeTxt = if ($asm) { "со сборкой" } else { "без сборки" }
            $col = "DarkGray"; if ($harm) { $col = "Red" } elseif ($score -eq $total) { $col = "Green" }
            Say ("  {0,-36} {1,-11} {2}/{3}; {4}" -f $n, $modeTxt, $score, $total, $ctrlTxt) $col
            if (-not $harm -and $score -gt $bestScore) { $best = $s; $bestAssemble = $asm; $bestScore = $score; $bestTotal = $total }
            if (-not $harm -and $score -eq $total) { break }
        }
        if ($bestScore -eq $bestTotal -and $bestScore -gt 0) { break }
    }
    $e.Cur = $null
    if (-not $best -or $bestScore -le 0) {
        Say ""
        Say "Не удалось подобрать приём, который работает и не ломает обычные сайты. Обход НЕ включён." "Red"
        $finalNote = "не включено"
        return
    }
    $e.Assemble = $bestAssemble
    $e.Cur = $best
    if ($bestScore -lt $bestTotal) { Say ("  Внимание: работает не всё ({0} из {1}); часть соединений браузера может не открыться." -f $bestScore, $bestTotal) "Yellow" }

    # ---------- QUIC: браузеры пробуют Google по UDP; чтобы они сразу шли на TCP (где работает обход), UDP к Google отключаем
    $qf = "outbound and ip and udp.DstPort == 443 and (" + ((Get-RangeParts) -join " or ") + ")"
    try { $quic = [Norma.Dropper]::Open($qf); Say "QUIC к серверам Google отключён на время работы (браузер перейдёт на обычное соединение)." } catch { Say "QUIC отключить не удалось (не страшно)." "Yellow" }

    Say ""
    Say ("NORMA РАБОТАЕТ. Приём: {0} ({1})" -f $best.Name, $(if ($bestAssemble) { "со сборкой" } else { "без сборки" })) "Green"
    Say "Откройте YouTube в браузере (лучше перезапустить браузер)."
    Say "Чтобы выключить NORMA, нажмите любую клавишу в этом окне или закройте его." "Yellow"
    Say ""
    $t0 = Get-Date
    $lastCheck = Get-Date
    $bad = 0
    while ($true) {
        Start-Sleep -Milliseconds 700
        $line = "  работает {0:mm\:ss} | обход: {1} | другие: {2} | без имени: {3} | потери: {4}      " -f ((Get-Date) - $t0), $e.HellosMatched, $e.HellosOther, $e.HellosUnknown, $e.SendFail
        Write-Host ("`r" + $line) -NoNewline
        $pressed = $false
        try { if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); $pressed = $true } } catch { [void](Read-Host); $pressed = $true }
        if ($pressed) { break }
        # сторож: обычный сайт должен открываться; если нет, обход отключается сам
        if ($ctrlHost -and ((Get-Date) - $lastCheck).TotalSeconds -ge 25) {
            $lastCheck = Get-Date
            $ok = [Norma.Lab]::TestOne($ctrlIp, $ctrlHost, 3000).Ok
            if (-not $ok) { $ok = [Norma.Lab]::TestOne($ctrlIp, $ctrlHost, 3000).Ok }
            if ($ok) { $bad = 0 } else { $bad++ }
            if ($bad -ge 2) {
                $e.Cur = $null
                Write-Host ""
                Say "ВНИМАНИЕ: обычный сайт ($ctrlHost) перестал открываться. NORMA выключила обход, чтобы ничего не ломать." "Red"
                $finalNote = "отключено сторожем"
                break
            }
        }
    }
}
finally {
    if ($quic) { $quic.Dispose() }
    if ($e) {
        Write-Host ""
        Say ("Счётчики: обход={0}; другие={1}; без имени={2}; потеряно пакетов={3} (код {4}); ошибок чтения={5}" -f $e.HellosMatched, $e.HellosOther, $e.HellosUnknown, $e.SendFail, $e.LastSendErr, $e.Errors)
        $log.Add("")
        $log.Add("== Журнал движка ==")
        $log.Add($e.DumpLog())
        $e.Dispose()
    }
    $lp = Join-Path $root "data\logs\norma-engine.log"
    try { [IO.File]::WriteAllLines($lp, $log, (New-Object Text.UTF8Encoding($true))) } catch {}
    try { Set-Clipboard -Value ($log -join "`r`n") } catch {}
    Say "NORMA выключена. Сеть работает как обычно." "Green"
    Say "Журнал сохранён в data\logs\norma-engine.log и скопирован в буфер обмена." "DarkGray"
}
