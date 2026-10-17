# NORMA: фоновый режим и автозапуск при входе в Windows.
# Автозапуск = задача планировщика «NORMA» с высшими правами (окно UAC при входе не появляется).
# Фоновый режим работает без окна: подбирает стратегию, следит за сетью и сайтами, пишет журнал в data\logs.
# Остановить его можно из меню (пункт про фоновый режим) или завершив процесс powershell, указанный в data\norma.pid.

$script:taskName = "NORMA"

# Аргументы для powershell.exe: скрытое окно, запуск app\norma.ps1 в фоновом режиме
function Get-BackgroundArgs {
    $q = $script:root.Replace("'", "''")
    $cmd = "`$env:NORMA_DIR='$q'; `$env:NORMA_MODE='background'; `$t=[IO.File]::ReadAllText('$q\app\norma.ps1',[Text.Encoding]::UTF8); & ([ScriptBlock]::Create(`$t))"
    return ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "' + $cmd + '"')
}

function Get-AutostartState {
    try { return [bool](Get-ScheduledTask -TaskName $script:taskName -ErrorAction Stop) } catch { return $false }
}

function Install-Autostart {
    if (-not (Test-Admin)) { Say "Нужны права администратора." "Red"; return }
    try {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument (Get-BackgroundArgs) -WorkingDirectory $script:root
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
        Register-ScheduledTask -TaskName $script:taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "NORMA: обход блокировок в фоне" -Force | Out-Null
        Say "Автозапуск включён: NORMA будет стартовать в фоне при входе в Windows." "Green"
        Say "Журналы фоновой работы: data\logs. Остановить: пункт меню «Фоновый режим»." "DarkGray"
    } catch {
        Say ("Не удалось создать задачу автозапуска: " + $_.Exception.Message) "Red"
    }
}

function Remove-Autostart {
    try {
        if (Get-AutostartState) {
            Unregister-ScheduledTask -TaskName $script:taskName -Confirm:$false -ErrorAction Stop
            Say "Автозапуск выключен." "Green"
        } else { Say "Автозапуск и не был включён." "DarkGray" }
    } catch { Say ("Не удалось удалить задачу: " + $_.Exception.Message) "Red" }
}

# Возвращает процесс фонового NORMA или $null
function Get-BackgroundProcess {
    try {
        if (-not (Test-Path $script:pidPath)) { return $null }
        $id = 0
        if (-not [int]::TryParse(([IO.File]::ReadAllText($script:pidPath)).Trim(), [ref]$id)) { return $null }
        $p = Get-Process -Id $id -ErrorAction Stop
        if ($p.ProcessName -match 'powershell|pwsh') { return $p }
    } catch {}
    return $null
}

function Start-Background {
    if (-not (Test-Admin)) { Say "Нужны права администратора." "Red"; return }
    if (Get-BackgroundProcess) { Say "Фоновый режим уже работает." "Yellow"; return }
    Stop-StaleWinws
    $foreign = @(Get-ForeignDpiProcesses)
    if ($foreign.Count -gt 0) {
        Say ("Уже работает {0}, запущенный не NORMA. Чтобы не трогать чужой процесс, фоновый режим не запущен." -f (($foreign | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ", ")) "Yellow"
        Say "Остановите его сами (или запустите NORMA из меню, она спросит) и повторите." "DarkGray"
        return
    }
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList (Get-BackgroundArgs) -WorkingDirectory $script:root -WindowStyle Hidden
        Say "Фоновый режим запущен. Подбор занимает от 10 секунд до нескольких минут; ход работы виден в data\logs." "Green"
    } catch { Say ("Не удалось запустить: " + $_.Exception.Message) "Red" }
}

function Stop-Background {
    $p = Get-BackgroundProcess
    if (-not $p) { Say "Фоновый режим не запущен." "DarkGray"; return }
    try {
        $ownerPid = $p.Id
        Stop-Process -Id $ownerPid -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 800
        Stop-WinwsOwnedBy $ownerPid
        Remove-Item -LiteralPath $script:pidPath -Force -ErrorAction SilentlyContinue
        Restore-TcpTimestamps
        Say "Фоновый режим остановлен." "Green"
    } catch { Say ("Не удалось остановить: " + $_.Exception.Message) "Red" }
}

# Что мешает безопасной очистке (выгрузке драйвера): работающие экземпляры NORMA. Только перечисляет, ничего не останавливает.
function Get-NormaBlockers {
    $res = @()
    if (Get-BackgroundProcess) { $res += "фоновый NORMA" }
    foreach ($o in @(Get-OtherNormaOwners)) { $res += ("другое окно NORMA (процесс {0})" -f $o) }
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
    if (@(Get-OtherNormaOwners).Count -gt 0) {
        Say "Работает другое окно NORMA: закройте его и повторите очистку." "Yellow"
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
