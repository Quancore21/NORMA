# NORMA: лаборатория. Подбирает приёмы на уровне пакетов, которые проходят DPI вашего провайдера для YouTube.
# Во время теста перехватываются ТОЛЬКО исходящие TCP:443-пакеты к одному выбранному IP. Остальное в системе не трогается.
param([switch]$Quick)

$root = $env:NORMA_DIR
if (-not $root) { $root = (Get-Location).Path }
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$Text, [string]$Color = "Gray") { Write-Host $Text -ForegroundColor $Color; $log.Add($Text) }

L "NORMA: лаборатория (подбор приёмов обхода для YouTube)" "Cyan"
L ("Дата: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm"))
try { L ("Windows: {0}; PowerShell {1}" -f [Environment]::OSVersion.VersionString, $PSVersionTable.PSVersion) } catch {}

# ---------- проверки
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { L "Нужны права администратора: закройте окно и запустите NORMA.bat заново." "Red"; return }
if (-not [Environment]::Is64BitProcess) { L "Нужен 64-битный PowerShell." "Red"; return }

$wd = Join-Path $root "vendor\zapret\bin"
$dll = Join-Path $wd "WinDivert.dll"
if (-not (Test-Path $dll) -or -not (Test-Path (Join-Path $wd "WinDivert64.sys"))) {
    L "Не найден WinDivert. WinDivert должен лежать в папке bin (идёт вместе с NORMA)." "Red"
    return
}

$running = @(Get-Process -Name "goodbyedpi", "winws" -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    L ("Запущено: {0}. Они конфликтуют с лабораторией." -f (($running | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ", ")) "Yellow"
    L "Записываю, с какими параметрами они запущены (если у вас всё открывается, это готовая рабочая стратегия):" "Cyan"
    foreach ($rp0 in $running) {
        try {
            $ci = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $rp0.Id)
            L ("  [{0}] путь: {1}" -f $rp0.ProcessName, $ci.ExecutablePath)
            L ("  [{0}] параметры: {1}" -f $rp0.ProcessName, $ci.CommandLine)
        } catch { L ("  [{0}] не удалось прочитать параметры: {1}" -f $rp0.ProcessName, $_.Exception.Message) "Yellow" }
    }
    $a = Read-Host "Остановить их на время теста? (д/н)"
    if ($a -match "^[дДyY]") { $running | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 }
    else { L "Тогда лабораторию запустить нельзя." "Red"; return }
}

# ---------- компиляция C#-части (делается на вашем компьютере, ничего устанавливать не нужно)
if (-not ("Norma.Lab" -as [type])) {
    L "Компилирую модуль лаборатории..."
    try {
        $cs = [IO.File]::ReadAllText((Join-Path $root "app\native\NormaLab.cs"), [Text.Encoding]::UTF8)
        Add-Type -TypeDefinition $cs -Language CSharp
    } catch {
        L ("ОШИБКА КОМПИЛЯЦИИ: " + $_.Exception.Message) "Red"
        if ($_.Exception.InnerException) { L $_.Exception.InnerException.Message "Red" }
        return
    }
}
$initErr = [Norma.Lab]::Init($dll)
if ($initErr) { L ("Не удалось загрузить WinDivert.dll: $initErr (антивирус мог его удалить или заблокировать)") "Red"; return }

# ---------- вспомогательное
function Get-Target([string]$HostName) {
    $ips = @()
    try { $ips = @([System.Net.Dns]::GetHostAddresses($HostName) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | ForEach-Object { $_.ToString() }) } catch {}
    foreach ($ip in ($ips | Select-Object -First 4)) { if ([Norma.Lab]::TcpOk($ip, 443, 2500)) { return $ip } }
    return $null
}

function Open-Divert([string]$Ip) {
    $filter = "outbound and ip.DstAddr == $Ip and tcp.DstPort == 443"
    try { return [Norma.Divert]::Open($filter) }
    catch {
        $m = $_.Exception.Message
        if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
        $code = 0
        if ($m -match "error (\d+)") { $code = [int]$Matches[1] }
        $why = "код $code"
        switch ($code) {
            5    { $why = "нет прав администратора" }
            2    { $why = "рядом с WinDivert.dll нет WinDivert64.sys" }
            87   { $why = "ошибка фильтра" }
            577  { $why = "Windows не принял подпись драйвера" }
            1275 { $why = "драйвер заблокирован (Защитник Windows, антивирус или политика безопасности)" }
        }
        L "Не удалось открыть WinDivert: $why." "Red"
        return $null
    }
}

function Invoke-Test($Div, [string]$Ip, [string]$HostName, $Strategy) {
    $Div.Cur = $Strategy
    $Div.Host = $HostName
    $r = [Norma.Lab]::TestOne($Ip, $HostName, 2500)
    $Div.Cur = $null
    Start-Sleep -Milliseconds 250
    return $r
}

function Say-Err($r) {
    $e = [string]$r.Error
    if ($e -match "безуспешной|did not properly respond|timed out|timeout") { $e = "нет ответа" }
    elseif ($e -match "forcibly closed|принудительно|reset") { $e = "соединение сброшено" }
    elseif ($e.Length -gt 50) { $e = $e.Substring(0, 50) }
    return ("{0}: {1}" -f $r.Stage, $e)
}

# ---------- этап 0: контроль механики на нейтральном сервере
# На Cloudflare ничего не блокируется: любой приём, который не ломает обычное соединение, обязан здесь пройти.
# Если нет, значит сам приём (а не DPI) портит соединение, и его результатам на YouTube верить нельзя.
$allMatrix = [Norma.Lab]::BuildMatrix($Quick.IsPresent)
$ctrlNames = @("split@1", "disorder@host-mid", "fake(ttl=3,x1) + no-split", "fake(md5sig,x1) + no-split",
               "fake(badsum,x1) + no-split", "fake(badseq,x1) + no-split", "fake(ttl=3,x1) + disorder@host-mid")
$cip = $null
foreach ($c in @("1.1.1.1", "1.0.0.1")) { if ([Norma.Lab]::TcpOk($c, 443, 2500)) { $cip = $c; break } }
$badMech = @()
if ($cip) {
    L ""
    L "Этап 0: контроль механики на нейтральном сервере ($cip), здесь всё должно открываться" "Cyan"
    $cd = Open-Divert $cip
    if (-not $cd) { return }
    try {
        foreach ($cn in $ctrlNames) {
            $cs0 = $allMatrix | Where-Object { $_.Name -eq $cn } | Select-Object -First 1
            if (-not $cs0) { continue }
            $cr = Invoke-Test $cd $cip "one.one.one.one" $cs0
            if ($cr.Ok) { L ("  {0,-36} OK ({1} мс)" -f $cn, $cr.Ms) "Green" }
            else { L ("  {0,-36} ЛОМАЕТ СОЕДИНЕНИЕ ({1})" -f $cn, (Say-Err $cr)) "Red"; $badMech += $cn }
        }
        L ("  Перехвачено рукопожатий: {0}; ошибок драйвера: {1}" -f $cd.HellosSeen, $cd.Errors)
    } finally { $cd.Dispose() }
    if ($badMech.Count -eq 0) { L "  Механика подмены пакетов исправна." "Green" }
    else { L "  Внимание: приёмы из списка выше ломают даже обычное соединение. Их провал на YouTube ничего не доказывает." "Yellow" }
} else {
    L "Этап 0 пропущен: нейтральные серверы Cloudflare недоступны." "Yellow"
}

# ---------- этап 1: перебор на www.youtube.com
$ytHost = "www.youtube.com"
$ip = Get-Target $ytHost
if (-not $ip) { L "Не удалось установить TCP-соединение с $ytHost ни по одному адресу." "Red"; return }
L ""
L "Этап 1: перебор приёмов на $ytHost ($ip)" "Cyan"

$winners = New-Object System.Collections.ArrayList
$d = Open-Divert $ip
if (-not $d) { return }
try {
    $b = Invoke-Test $d $ip $ytHost $null
    if ($b.Ok) {
        L "Без всякого обхода $ytHost уже открывается ($($b.Ms) мс). Подбирать нечего: либо сеть другая, либо блок снят." "Green"
        return
    }
    L ("Контроль без обхода: не открывается ({0}), как и ожидалось." -f (Say-Err $b)) "Yellow"

    $matrix = $allMatrix
    $total = $matrix.Count
    L ("Приёмов к проверке: $total. Это займёт примерно {0} мин." -f [math]::Max(1, [int]($total * 3 / 60)))
    $i = 0
    foreach ($s in $matrix) {
        $i++
        $r = Invoke-Test $d $ip $ytHost $s
        if ($r.Ok) {
            L ("[{0}/{1}] {2,-36} РАБОТАЕТ ({3} мс)" -f $i, $total, $s.Name, $r.Ms) "Green"
            [void]$winners.Add([pscustomobject]@{ S = $s; Name = $s.Name; Ms = $r.Ms })
        } else {
            Write-Host ("[{0}/{1}] {2,-36} нет ({3})" -f $i, $total, $s.Name, (Say-Err $r)) -ForegroundColor DarkGray
            $log.Add(("[{0}/{1}] {2} нет ({3})" -f $i, $total, $s.Name, (Say-Err $r)))
        }
        if ($i -eq 3 -and $d.HellosSeen -eq 0) {
            L "Драйвер не видит ни одного ClientHello: перехват не работает. Проверьте антивирус и повторите." "Red"
            return
        }
    }
    L ""
    L ("Перехвачено рукопожатий: {0}; ошибок драйвера: {1}" -f $d.HellosSeen, $d.Errors)

    # повторная проверка: плавающие результаты нам не нужны
    $stable = New-Object System.Collections.ArrayList
    if ($winners.Count -gt 0) {
        L ""
        L "Проверяю стабильность (ещё 2 попытки каждому)..." "Cyan"
        foreach ($w in ($winners | Sort-Object Ms | Select-Object -First 8)) {
            $okCount = 1
            for ($k = 0; $k -lt 2; $k++) { if ((Invoke-Test $d $ip $ytHost $w.S).Ok) { $okCount++ } }
            $col = "DarkGray"; if ($okCount -ge 2) { $col = "Green"; [void]$stable.Add($w) }
            L ("  {0,-36} {1} из 3" -f $w.Name, $okCount) $col
        }
    }
}
finally { $d.Dispose() }

if ($stable.Count -eq 0) {
    L ""
    L "Ни один из приёмов не прошёл стабильно. Это тоже результат: для YouTube на вашей сети нужен другой подход (узел)." "Yellow"
}

# ---------- этап 2: проверка победителей на других адресах YouTube
$perHost = @{}
foreach ($w in $stable) { $perHost[$w.Name] = @($ytHost) }
if ($stable.Count -gt 0) {
    L ""
    L "Этап 2: проверка лучших приёмов на других доменах YouTube" "Cyan"
    foreach ($oh in @("redirector.googlevideo.com", "i.ytimg.com")) {
        $oip = Get-Target $oh
        if (-not $oip) { L "  $oh : нет TCP-соединения" "Yellow"; continue }
        $od = Open-Divert $oip
        if (-not $od) { continue }
        try {
            $bb = Invoke-Test $od $oip $oh $null
            if ($bb.Ok) { L "  $oh : открывается и без обхода" "Green"; continue }
            foreach ($w in ($stable | Select-Object -First 5)) {
                $r = Invoke-Test $od $oip $oh $w.S
                if (-not $r.Ok) { $r = Invoke-Test $od $oip $oh $w.S }
                if ($r.Ok) { $perHost[$w.Name] += $oh; L ("  {0,-26} {1,-36} РАБОТАЕТ" -f $oh, $w.Name) "Green" }
                else { L ("  {0,-26} {1,-36} нет" -f $oh, $w.Name) "DarkGray" }
            }
        }
        finally { $od.Dispose() }
    }
}

# ---------- итог
L ""
L "== Итог ==" "Cyan"
$summary = @()
foreach ($w in ($stable | Sort-Object Ms)) {
    $hosts = @($perHost[$w.Name])
    L ("  {0,-36} домены: {1}" -f $w.Name, ($hosts -join ", ")) "Green"
    $summary += [pscustomobject]@{ strategy = $w.Name; ms = $w.Ms; hosts = $hosts }
}
if ($summary.Count -eq 0) { L "  Рабочих приёмов не найдено." "Yellow" }

try {
    $json = (@{ date = (Get-Date -Format "s"); results = $summary } | ConvertTo-Json -Depth 5)
    [IO.File]::WriteAllText((Join-Path $root "data\lab-result.json"), $json, (New-Object Text.UTF8Encoding($true)))
} catch {}
$rp = Join-Path $root "data\logs\norma-lab-report.txt"
try { [IO.File]::WriteAllLines($rp, $log, (New-Object Text.UTF8Encoding($true))) } catch {}
$copied = $false
try { Set-Clipboard -Value ($log -join "`r`n"); $copied = $true } catch {}
Write-Host ""
Write-Host "Отчёт сохранён: $rp" -ForegroundColor Green
if ($copied) { Write-Host "И скопирован в буфер обмена: вставьте его в чат целиком." -ForegroundColor Green }
