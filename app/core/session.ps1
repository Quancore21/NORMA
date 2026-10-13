# NORMA: рабочая сессия. Пока окно открыто (или работает фоновый режим), обход включён; закрыли окно, и winws.exe завершается.
# Сторож раз в 45 секунд проверяет нужные сайты и смену сети; если стратегия «протухла» или сеть другая,
# NORMA сама подбирает подходящую (для знакомой сети сначала пробует то, что работало в ней раньше).

function Show-Probe {
    param([string]$Prof = "youtube")
    Say "Замер сети без обхода." "Cyan"
    if (-not (Get-Command "curl.exe" -ErrorAction SilentlyContinue)) { Say "Не найден curl.exe (нужна Windows 10 1803+)." "Red"; return }
    Stop-Winws
    $targets = @(Get-Targets $Prof)
    $r = Test-Urls @($targets | ForEach-Object { $_.Url })
    $bad = 0
    foreach ($t in $targets) {
        if ($r[$t.Url]) { Say ("  {0,-24} открывается" -f $t.Key) "Green" }
        else { Say ("  {0,-24} НЕ ОТКРЫВАЕТСЯ" -f $t.Key) "Yellow"; $bad++ }
    }
    Say ""
    if ($bad -eq 0) { Say "Всё проверенное открывается без обхода." "Green" }
    else { Say ("Не открывается: {0} из {1}. Пункт 1 меню подберёт обход." -f $bad, $targets.Count) "Yellow" }
}

# Подбор новой стратегии во время работы; Stop = $true значит «выключаемся»
function Invoke-Repick([string]$Prof, [string]$Prefer, [string]$Sig) {
    $res = Invoke-AutoPick -Prof $Prof -Prefer $Prefer
    if ($res.Status -eq "ok" -or $res.Status -eq "partial") {
        $st = Get-State
        $st.strategy = $res.Strategy.Name
        Save-State $st
        Set-NetworkStrategy $Sig $res.Strategy.Name
        Say ("Теперь работает: {0}" -f $res.Strategy.Name) "Green"
        return [pscustomobject]@{ Stop = $false; Name = $res.Strategy.Name; Urls = @($res.RequiredUrls) }
    }
    if ($res.Status -eq "none-needed") {
        Say "Сайты открываются без обхода. Обход выключен." "Green"
        return [pscustomobject]@{ Stop = $true; Name = ""; Urls = @() }
    }
    Say "Подобрать замену не удалось. Обход выключен, чтобы ничего не ломать." "Red"
    return [pscustomobject]@{ Stop = $true; Name = ""; Urls = @() }
}

# Основной цикл работы. Возвращает причину выхода: key | exited | failed
function Watch-Session {
    param([string]$Name, $WatchUrls, [string]$Prof, [string]$Sig, [switch]$Background)
    $WatchUrls = @($WatchUrls)
    $t0 = Get-Date
    $lastCheck = Get-Date
    $lastRepick = Get-Date "2000-01-01"
    $bad = 0
    while ($true) {
        Start-Sleep -Milliseconds 700
        if (-not $Background) {
            Write-Host ("`r  работает {0:mm\:ss} | стратегия: {1}      " -f ((Get-Date) - $t0), $Name) -NoNewline
            $pressed = $false
            try { if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); $pressed = $true } } catch { }
            if ($pressed) { Write-Host ""; return "key" }
        }

        if ($script:winws -and $script:winws.HasExited) {
            Write-Host ""
            Say ("winws.exe неожиданно завершился (код {0})." -f $script:winws.ExitCode) "Red"
            return "exited"
        }

        if (((Get-Date) - $lastCheck).TotalSeconds -lt 45) { continue }
        $lastCheck = Get-Date

        # 1) смена сети (ноутбук переехал из дома в офис или на другой Wi-Fi)
        $sig2 = Get-NetworkSignature
        if ($sig2 -ne $Sig -and $sig2 -ne "offline" -and $sig2 -ne "unknown") {
            Write-Host ""
            Say ("Сеть изменилась: {0}. Подбираю стратегию для неё..." -f $sig2) "Cyan"
            $rp = Invoke-Repick $Prof (Get-NetworkStrategy $sig2) $sig2
            if ($Background) { [void](Save-NormaLog "background") }
            if ($rp.Stop) { return "failed" }
            $Name = $rp.Name
            $WatchUrls = @($rp.Urls)
            $Sig = $sig2
            $bad = 0
            $lastCheck = Get-Date
            continue
        }

        # 2) здоровье: нужные сайты должны открываться
        if ($WatchUrls.Count -eq 0) { continue }
        $r = Test-Urls $WatchUrls
        $okCnt = @($WatchUrls | Where-Object { $r[$_] }).Count
        if ($okCnt * 2 -lt $WatchUrls.Count) { $bad++ } else { $bad = 0 }
        if ($bad -ge 2) {
            Write-Host ""
            Say "ВНИМАНИЕ: нужные сайты перестали открываться. Стратегии со временем перестают работать." "Yellow"
            if (((Get-Date) - $lastRepick).TotalMinutes -ge 10) {
                $lastRepick = Get-Date
                Say "NORMA подбирает другую стратегию..." "Cyan"
                $rp = Invoke-Repick $Prof "" $Sig
                if ($Background) { [void](Save-NormaLog "background") }
                if ($rp.Stop) { return "failed" }
                $Name = $rp.Name
                $WatchUrls = @($rp.Urls)
            }
            $bad = 0
        }
    }
}

function Invoke-Session {
    param(
        [string]$Mode = "auto",      # auto: сначала то, что работало в этой сети; repick: полный перебор; manual: выбранная стратегия; bench: бенчмарк
        $Manual = $null,
        [switch]$Force,
        [switch]$Background          # фоновый режим (автозапуск): без вопросов, работает, пока не остановят
    )

    $script:log.Clear()
    Say ("NORMA {0}: обход на основе zapret" -f $script:version) "Cyan"
    Say (("Дата: {0}; Windows {1}") -f (Get-Date -Format "yyyy-MM-dd HH:mm"), [Environment]::OSVersion.VersionString)

    if (-not (Test-Admin)) { Say "Нужны права администратора: запустите NORMA.bat заново." "Red"; return }
    if (-not [Environment]::Is64BitProcess) { Say "Нужен 64-битный PowerShell." "Red"; return }
    if (-not (Test-Path (Join-Path $script:binDir "winws.exe"))) { Say "Не найден vendor\zapret\bin\winws.exe. Папки vendor и app должны лежать рядом с NORMA.bat." "Red"; return }
    if ($script:root -match '[^\x00-\x7F]') {
        Say "Внимание: в пути к папке NORMA есть кириллица или спецсимволы. Если winws не стартует, перенесите папку, например, в C:\NORMA." "Yellow"
    }

    Initialize-NormaCore
    Initialize-NormaFiles
    if (-not (Resolve-Conflicts -Silent:$Background)) { [void](Save-NormaLog "session"); return }
    & netsh.exe interface tcp set global timestamps=enabled 2>&1 | Out-Null   # нужно ряду стратегий (как в upstream)

    if ($Background) { try { [IO.File]::WriteAllText($script:pidPath, [string]$PID) } catch {} }

    $st = Get-State
    $prof = $st.profile
    $first = $true
    try {
        while ($true) {
            $sig = Get-NetworkSignature
            $name = ""
            $watchUrls = @()

            if ($first -and $Mode -eq "manual" -and $Manual) {
                Say ("Запускаю выбранную стратегию: {0}" -f $Manual.Name)
                $p = Start-Winws $Manual
                if (-not $p) { break }
                Start-Sleep -Milliseconds 2500
                if ($p.HasExited) { Say ("winws завершился (код {0}). Запустите соответствующий .bat вручную, чтобы увидеть ошибку." -f $p.ExitCode) "Red"; break }
                $name = $Manual.Name
                $watchUrls = @(Get-Targets $prof | Where-Object { $_.Key -match '^YouTube' } | ForEach-Object { $_.Url })
            }
            else {
                $prefer = Get-NetworkStrategy $sig
                if (-not $prefer) { $prefer = [string]$st.strategy }
                if ($Mode -eq "repick" -and $first) { $prefer = "" }
                if ($Mode -eq "bench" -and $first) {
                    $res = Invoke-AutoPick -Prof $prof -Benchmark
                } else {
                    $res = Invoke-AutoPick -Prof $prof -Prefer $prefer -Force:($Force -and $first)
                }
                if ($res.Status -eq "none-needed" -or $res.Status -eq "failed") {
                    Stop-Winws
                    if (-not $Background) { break }
                    Say "Повторная попытка через 5 минут." "DarkGray"
                    Start-Sleep -Seconds 300
                    $first = $false
                    continue
                }
                $name = $res.Strategy.Name
                $watchUrls = @($res.RequiredUrls)
            }
            $first = $false

            $st = Get-State
            $st.strategy = $name
            Save-State $st
            Set-NetworkStrategy $sig $name

            Say ""
            Say ("NORMA РАБОТАЕТ. Стратегия: {0}" -f $name) "Green"
            if (-not $Background) {
                Say "Откройте YouTube в браузере (лучше перезапустить браузер)."
                Say "Окно должно оставаться открытым. Чтобы выключить NORMA, нажмите любую клавишу или закройте окно." "Yellow"
            }
            Say ""
            if ($Background) { [void](Save-NormaLog "background") }

            $why = Watch-Session -Name $name -WatchUrls $watchUrls -Prof $prof -Sig $sig -Background:$Background
            if (-not $Background) { break }
            if ($why -eq "key") { break }
            Say "Фоновый режим: перезапускаю подбор через 10 секунд." "DarkGray"
            Stop-Winws
            Start-Sleep -Seconds 10
        }
    }
    finally {
        Write-Host ""
        Stop-Winws
        if ($Background) { try { Remove-Item -LiteralPath $script:pidPath -Force -ErrorAction SilentlyContinue } catch {} }
        Say "NORMA выключена. Сеть работает как обычно." "Green"
        $lp = Save-NormaLog "session"
        if (-not $Background) {
            try { Set-Clipboard -Value ($script:log -join "`r`n") } catch {}
            if ($lp) { Say ("Журнал: {0} (и в буфере обмена)." -f $lp) "DarkGray" }
        }
    }
}
