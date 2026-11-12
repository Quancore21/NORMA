# NORMA: фоновый режим и автозапуск при входе в Windows.
#
# Автозапуск = задача планировщика «NORMA»: запускается при входе пользователя с задержкой 30 секунд (сеть успевает подняться),
# с высшими правами (окно UAC не появляется), перезапускается при сбое (3 попытки с интервалом в минуту) и запускает app\background.ps1.
# Фоновый режим работает без окна: подбирает стратегию, следит за сетью и сайтами, по расписанию обновляет списки и саму NORMA,
# пишет журнал в data\logs и своё состояние в data\background-status.json (его показывает меню «Фоновый режим»).
# Идентификатор процесса хранится в data\norma.pid вместе со временем запуска, чтобы не принять чужой процесс за фоновый NORMA.

$script:taskName = "NORMA"
$script:statusPath = Join-Path $script:dataDir "background-status.json"
$script:bgStarted = ""

# ---------- аргументы запуска
# Задача запускает app\background.ps1 напрямую (-File): без длинной команды в строке и без проблем с кавычками в пути
function Get-BackgroundArgs {
    return ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path $script:root "app\background.ps1"))
}

# ---------- задача планировщика
function Get-AutostartTask {
    try { return (Get-ScheduledTask -TaskName $script:taskName -ErrorAction Stop) } catch { return $null }
}

# Exists: задача есть; Current: она указывает на эту папку и использует нынешний формат; Legacy: старый формат из версий до 0.12
function Get-AutostartInfo {
    $info = [pscustomobject]@{ Exists = $false; Current = $false; Legacy = $false; Args = "" }
    $t = Get-AutostartTask
    if (-not $t) { return $info }
    $info.Exists = $true
    try { $info.Args = [string](@($t.Actions)[0].Arguments) } catch { $info.Args = "" }
    $info.Legacy = ($info.Args -match '-Command')
    $info.Current = ((-not $info.Legacy) -and ($info.Args -eq (Get-BackgroundArgs)))
    return $info
}

function Get-AutostartState { return [bool](Get-AutostartTask) }

# Включает автозапуск (или чинит: пересоздаёт задачу для этой папки). С -StartNow сразу запускает фоновый режим.
function Enable-Autostart([switch]$StartNow) {
    if (-not (Test-Admin)) { Say "Нужны права администратора." "Red"; return $false }
    if (-not (Test-Path (Join-Path $script:root "app\background.ps1"))) { Say "Не найден app\background.ps1." "Red"; return $false }
    try {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument (Get-BackgroundArgs) -WorkingDirectory $script:root
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $trigger.Delay = "PT30S"
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $script:taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description "NORMA: обход блокировок в фоне" -Force -ErrorAction Stop | Out-Null
    } catch {
        Say ("Не удалось создать задачу автозапуска: " + $_.Exception.Message) "Red"
        return $false
    }
    $chk = Get-AutostartInfo
    if (-not ($chk.Exists -and $chk.Current)) { Say "Задача создана, но её параметры не совпали с ожидаемыми. Проверьте её в планировщике заданий." "Yellow"; return $false }
    Say "Автозапуск включён: NORMA будет стартовать в фоне через 30 секунд после входа в Windows." "Green"
    if ($StartNow) { Start-Background }
    return $true
}

# Выключает автозапуск и останавливает фоновый режим
function Disable-Autostart {
    if (Get-BackgroundProcess) { Stop-Background }
    try {
        if (Get-AutostartTask) {
            Unregister-ScheduledTask -TaskName $script:taskName -Confirm:$false -ErrorAction Stop
            Say "Автозапуск выключен." "Green"
        } else { Say "Автозапуск и не был включён." "DarkGray" }
    } catch { Say ("Не удалось удалить задачу: " + $_.Exception.Message) "Red" }
}

# ---------- процесс фонового режима
function Write-BackgroundPid {
    try { [IO.File]::WriteAllText($script:pidPath, ("{0}|{1}" -f $PID, (Get-SelfStart))) } catch {}
}

# Возвращает процесс фонового NORMA или $null. Принимается только pid-файл формата «pid|время запуска» и только если у процесса
# с этим pid то же время запуска. Старый формат (только pid) подтверждением владения не считается: pid мог достаться другому процессу PowerShell.
function Get-BackgroundProcess {
    try {
        if (-not (Test-Path $script:pidPath)) { return $null }
        $m = [regex]::Match(([IO.File]::ReadAllText($script:pidPath)).Trim(), '^(\d+)\|(\d+)$')
        if (-not $m.Success) { return $null }
        $ticks = [long]$m.Groups[2].Value
        if ($ticks -le 0) { return $null }
        $p = Get-Process -Id ([int]$m.Groups[1].Value) -ErrorAction Stop
        if ($p.ProcessName -notmatch 'powershell|pwsh') { return $null }
        if ((Get-ProcStartTicks $p) -ne $ticks) { return $null }
        return $p
    } catch { return $null }
}

# Дополнительный признак перед остановкой: командная строка процесса содержит background.ps1 (если её удалось прочитать).
# Если прочитать нельзя, остаётся строгая проверка pid и времени запуска.
function Test-LooksLikeBackground($Proc) {
    try {
        $ci = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = {0}" -f $Proc.Id) -ErrorAction Stop
        $cl = [string]$ci.CommandLine
        if ($cl) { return ($cl -match 'background\.ps1') }
    } catch {}
    return $true
}

# Запускает фоновый процесс. WaitPid: подождать, пока завершится указанный процесс (при перезапуске после обновления).
function Start-NewBackground([int]$WaitPid = 0) {
    $a = Get-BackgroundArgs
    if ($WaitPid -gt 0) { $a += (" -WaitPid {0}" -f $WaitPid) }
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $a -WorkingDirectory $script:root -WindowStyle Hidden
        return $true
    } catch {
        Say ("Не удалось запустить фоновый процесс: " + $_.Exception.Message) "Red"
        return $false
    }
}

function Start-Background {
    if (-not (Test-Admin)) { Say "Нужны права администратора." "Red"; return }
    if (Get-BackgroundProcess) { Say "Фоновый режим уже работает." "Yellow"; return }
    Stop-StaleWinws
    $others = @(Get-OtherNormaInstances)
    if ($others.Count -gt 0) {
        Say ("Уже работает другой экземпляр NORMA (процесс {0}). Второй не запущен, чтобы они не мешали друг другу." -f ($others -join ", ")) "Yellow"
        return
    }
    $foreign = @(Get-ForeignDpiProcesses)
    if ($foreign.Count -gt 0) {
        Say ("Уже работает {0}, запущенный не NORMA. Чтобы не трогать чужой процесс, фоновый режим не запущен." -f (($foreign | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ", ")) "Yellow"
        Say "Остановите его сами (или запустите NORMA из меню, она спросит) и повторите." "DarkGray"
        return
    }
    if (Start-NewBackground) { Say "Фоновый режим запущен. Подбор занимает от 10 секунд до нескольких минут; ход работы виден в меню «Фоновый режим»." "Green" }
}

function Stop-Background {
    $p = Get-BackgroundProcess
    if (-not $p) { Say "Фоновый режим не запущен." "DarkGray"; return }
    if (-not (Test-LooksLikeBackground $p)) { Say "Процесс из pid-файла не похож на фоновый NORMA (командная строка): ничего не завершаю." "Yellow"; return }
    try {
        $ownerPid = $p.Id
        Stop-Process -Id $ownerPid -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 800
        Stop-WinwsOwnedBy $ownerPid
        Remove-Item -LiteralPath $script:pidPath -Force -ErrorAction SilentlyContinue
        Write-BackgroundStatus "stopped" "остановлен из меню"
        Restore-TcpTimestamps
        Say "Фоновый режим остановлен." "Green"
    } catch { Say ("Не удалось остановить: " + $_.Exception.Message) "Red" }
}

# ---------- состояние фонового режима (для меню)
# State: starting | picking | running | waiting | updating | stopped
function Write-BackgroundStatus([string]$State, [string]$Message = "", [string]$Strategy = "", [string]$Network = "") {
    try {
        Initialize-Dirs
        if (-not $script:bgStarted) { $script:bgStarted = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
        $o = [pscustomobject]@{
            pid = $PID; version = $script:version; state = $State; message = $Message; strategy = $Strategy; network = $Network
            started = $script:bgStarted; updated = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        [IO.File]::WriteAllText($script:statusPath, (ConvertTo-Json -InputObject $o), (New-Object Text.UTF8Encoding($false)))
    } catch {}
}

function Read-BackgroundStatus {
    try {
        if (Test-Path $script:statusPath) { return ([IO.File]::ReadAllText($script:statusPath, [Text.Encoding]::UTF8) | ConvertFrom-Json) }
    } catch {}
    return $null
}

function Get-BackgroundLogTail([int]$Lines = 20) {
    try {
        $f = Get-ChildItem -LiteralPath $script:logDir -Filter "norma-background-*.log" -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($f) { return @([IO.File]::ReadAllLines($f.FullName) | Select-Object -Last $Lines) }
    } catch {}
    return @()
}

function Get-StateText([string]$State) {
    switch ($State) {
        "starting" { return "запускается" }
        "picking" { return "подбирает стратегию" }
        "running" { return "работает" }
        "waiting" { return "ждёт (повторная попытка позже)" }
        "updating" { return "обновляется" }
        "stopped" { return "остановлен" }
        default { return $State }
    }
}

# Сводка для экрана «Фоновый режим»
function Show-BackgroundStatus {
    $ai = Get-AutostartInfo
    $p = Get-BackgroundProcess
    $st = Read-BackgroundStatus
    if ($ai.Exists -and $ai.Current) { Write-Host "  Автозапуск: включён (при входе в Windows, через 30 секунд)" -ForegroundColor Green }
    elseif ($ai.Exists -and $ai.Legacy) { Write-Host "  Автозапуск: включён в старом формате (пункт 1 исправит)" -ForegroundColor Yellow }
    elseif ($ai.Exists) { Write-Host "  Автозапуск: указывает на другую папку (пункт 1 исправит)" -ForegroundColor Yellow }
    else { Write-Host "  Автозапуск: выключен" -ForegroundColor DarkGray }
    if ($p) {
        Write-Host ("  Фоновый NORMA: работает (процесс {0})" -f $p.Id) -ForegroundColor Green
        if ($st) {
            Write-Host ("  Состояние: {0}" -f (Get-StateText $st.state)) -ForegroundColor Gray
            if ($st.strategy) { Write-Host ("  Стратегия: {0}" -f $st.strategy) -ForegroundColor Gray }
            if ($st.network) { Write-Host ("  Сеть: {0}" -f $st.network) -ForegroundColor Gray }
            if ($st.message) { Write-Host ("  Сообщение: {0}" -f $st.message) -ForegroundColor DarkGray }
            Write-Host ("  Запущен: {0}; обновлено: {1}" -f $st.started, $st.updated) -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  Фоновый NORMA: не запущен" -ForegroundColor DarkGray
        if ($st -and $st.state -ne "stopped") { Write-Host ("  Последнее известное состояние: {0} ({1})" -f (Get-StateText $st.state), $st.updated) -ForegroundColor DarkGray }
    }
}

# ---------- безопасность очистки
# Что мешает безопасной очистке (выгрузке драйвера): работающие экземпляры NORMA. Только перечисляет, ничего не останавливает.
function Get-NormaBlockers {
    $res = @()
    foreach ($o in @(Get-OtherNormaInstances)) { $res += ("другой экземпляр NORMA (процесс {0})" -f $o) }
    return $res
}

# Проверка перед очисткой (выгрузкой драйвера и возвратом TCP timestamps). Фоновый NORMA останавливается только с согласия пользователя;
# чужой winws тоже: выгрузка драйвера нарушила бы его работу.
function Confirm-CleanupSafe {
    if (Get-BackgroundProcess) {
        Say "Работает фоновый NORMA: очистка нарушила бы его работу." "Yellow"
        $a = Read-Host "Остановить фоновый NORMA и продолжить очистку? (д/н)"
        if ($a -notmatch '^[дДyY]') { Say "Очистка отменена." "Yellow"; return $false }
        Stop-Background
        if (Get-BackgroundProcess) { Say "Не удалось остановить фоновый NORMA. Очистка отменена." "Red"; return $false }
    }
    $others = @(Get-OtherNormaInstances)
    if ($others.Count -gt 0) {
        Say ("Работает другой экземпляр NORMA (процесс {0}): закройте его и повторите очистку." -f ($others -join ", ")) "Yellow"
        return $false
    }
    $foreign = @(Get-ForeignDpiProcesses)
    if ($foreign.Count -gt 0) {
        Say ("Работает {0}, запущенный не NORMA: выгрузка драйвера нарушит его работу." -f (($foreign | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ", ")) "Yellow"
        $a = Read-Host "Всё равно продолжить? (д/н)"
        if ($a -notmatch '^[дДyY]') { Say "Очистка отменена." "Yellow"; return $false }
    }
    return $true
}
