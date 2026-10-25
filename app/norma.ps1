# NORMA - Node for Obfuscated Routing and Masked Access. Версия 0.7.
$script:normaRoot = $env:NORMA_DIR
if (-not $script:normaRoot) { $script:normaRoot = (Get-Location).Path }
$script:normaRoot = $script:normaRoot.TrimEnd('\')

# Загружаем ядро в текущую область видимости (dot-source), чтобы функции были доступны меню.
foreach ($rel in @("app\core\lib.ps1", "app\core\model.ps1", "app\core\autopick.ps1", "app\core\session.ps1", "app\core\doctor.ps1", "app\core\autostart.ps1", "app\core\updates.ps1", "app\core\settings.ps1", "app\core\selfupdate.ps1", "app\core\plan.ps1")) {
    $p = Join-Path $script:normaRoot $rel
    if (-not (Test-Path $p)) { Write-Host "Не найден файл: $p" -ForegroundColor Red; Read-Host "Нажмите Enter"; return }
    . ([ScriptBlock]::Create([IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)))
}

# Фоновый режим (автозапуск): без меню и вопросов
if ($env:NORMA_MODE -eq "background") {
    Invoke-Session -Mode "auto" -Background
    return
}

# Скрипты собственного движка запускаются как отдельные части
function Invoke-Part([string]$Rel, [hashtable]$Params = @{}) {
    $p = Join-Path $script:normaRoot $Rel
    if (-not (Test-Path $p)) { Write-Host "Не найден файл: $p" -ForegroundColor Red; return }
    $t = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
    $sb = [ScriptBlock]::Create($t)
    & $sb @Params
}
function Wait-Menu { Write-Host ""; [void](Read-Host "Нажмите Enter, чтобы вернуться в меню") }

function Show-StrategyPicker([string]$Prof) {
    $all = @(Get-SortedStrategies $Prof)
    if ($all.Count -eq 0) { Write-Host "Не найдено ни одной стратегии." -ForegroundColor Red; return $null }
    Write-Host ""
    for ($i = 0; $i -lt $all.Count; $i++) {
        $sum = Get-StrategySummary $all[$i]
        if ($sum.Length -gt 78) { $sum = $sum.Substring(0, 75) + "..." }
        Write-Host ("  {0,2}. {1,-30} [{2}]" -f ($i + 1), $all[$i].Name, $all[$i].Source) -NoNewline
        Write-Host ("  " + $sum) -ForegroundColor DarkGray
    }
    Write-Host ""
    $n = Read-Host "Номер стратегии (Enter - отмена)"
    $idx = 0
    if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $all.Count) { return $all[$idx - 1] }
    return $null
}

function Show-BackgroundMenu {
    while ($true) {
        Clear-Host
        Write-Host "  Фоновый режим и автозапуск" -ForegroundColor Cyan
        Write-Host "  Фоновый режим работает без окна: подбирает обход, следит за сетью и обновляет списки." -ForegroundColor DarkGray
        Write-Host ""
        Show-BackgroundStatus
        Write-Host ""
        Write-Host "  1. Включить автозапуск и запустить сейчас (или исправить его)"
        Write-Host "  2. Выключить автозапуск и остановить фоновый режим"
        Write-Host "  3. Запустить фоновый режим сейчас (без автозапуска)"
        Write-Host "  4. Остановить фоновый режим"
        Write-Host "  5. Показать журнал фонового режима"
        Write-Host "  0. Назад"
        Write-Host ""
        $c = Read-Host "Выберите пункт"
        switch ($c) {
            "1" { [void](Enable-Autostart -StartNow); Wait-Menu }
            "2" { Disable-Autostart; Wait-Menu }
            "3" { Start-Background; Wait-Menu }
            "4" { Stop-Background; Wait-Menu }
            "5" {
                $lines = @(Get-BackgroundLogTail 25)
                if ($lines.Count -gt 0) { foreach ($l in $lines) { Write-Host $l } } else { Write-Host "Журнала фонового режима пока нет." }
                Wait-Menu
            }
            "0" { return }
        }
    }
}

# Собственный движок тоже работает через драйвер WinDivert: действия с ним выполняются под замком движка
function Invoke-WithEngineLease([scriptblock]$Action) {
    if (-not (Enter-EngineLease 0)) {
        Write-Host "Обход сейчас занят другим экземпляром NORMA: действие отменено." -ForegroundColor Yellow
        return
    }
    try { & $Action } finally { Exit-EngineLease }
}

function Show-NativeMenu {
    while ($true) {
        Clear-Host
        Write-Host "  Собственный движок NORMA (эксперимент, из версии 0.5)" -ForegroundColor Cyan
        Write-Host "  Нужен для разработки: основной обход делает winws из zapret." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1. Включить собственный движок для YouTube"
        Write-Host "  2. Замер: что блокирует провайдер (YouTube, Telegram)"
        Write-Host "  3. Лаборатория подбора приёмов (полная, около 5 минут)"
        Write-Host "  4. Лаборатория, быстрый режим (1-2 минуты)"
        Write-Host "  0. Назад"
        Write-Host ""
        $c = Read-Host "Выберите пункт"
        switch ($c) {
            "1" { Invoke-WithEngineLease { Stop-Winws; Invoke-Part "app\native\run.ps1" }; Wait-Menu }
            "2" { Invoke-Part "app\native\probe.ps1"; Wait-Menu }
            "3" { Invoke-WithEngineLease { Stop-Winws; Invoke-Part "app\native\lab.ps1" }; Wait-Menu }
            "4" { Invoke-WithEngineLease { Stop-Winws; Invoke-Part "app\native\lab.ps1" @{ Quick = $true } }; Wait-Menu }
            "0" { return }
        }
    }
}

function Show-UpdatesMenu {
    while ($true) {
        Clear-Host
        $ipMode = Get-IpsetMode
        $ipText = "выключен (none)"
        if ($ipMode -eq "any") { $ipText = "любые адреса (any)" } elseif ($ipMode -eq "loaded") { $ipText = "загружен полный список (loaded)" }
        Write-Host "  Обновления и списки" -ForegroundColor Cyan
        Write-Host ("  Версия NORMA: {0}; режим IPSet: {1}" -f $script:version, $ipText) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1. Проверить новую версию NORMA"
        Write-Host "  2. Проверить версию оригинала (zapret-discord-youtube)"
        Write-Host "  3. Обновить списки доменов из оригинала"
        Write-Host "  4. Режим IPSet: переключить (none, any, loaded)"
        Write-Host "  5. Обновить список IPSet из оригинала"
        Write-Host "  0. Назад"
        Write-Host ""
        $c = Read-Host "Выберите пункт"
        switch ($c) {
            "1" { if (Show-NormaUpdate) { Wait-Menu; exit }; Wait-Menu }
            "2" { [void](Show-UpstreamVersion); Wait-Menu }
            "3" { [void](Update-Lists); Wait-Menu }
            "4" { [void](Switch-IpsetMode) }
            "5" { [void](Update-Ipset); Wait-Menu }
            "0" { return }
        }
    }
}

function Show-ExtraMenu {
    while ($true) {
        Clear-Host
        $gf = [string](Get-State).gameFilter
        $gfText = "выключен"
        if ($gf -eq "all") { $gfText = "TCP и UDP" } elseif ($gf -eq "tcp") { $gfText = "только TCP" } elseif ($gf -eq "udp") { $gfText = "только UDP" }
        Write-Host "  Дополнительно" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  1. Сервис zapret: служба Windows, списки, hosts (service.bat)"
        Write-Host "  2. Собственный движок NORMA (эксперимент)"
        Write-Host "  3. Очистка: выгрузить драйвер WinDivert, вернуть TCP timestamps"
        Write-Host "  4. Открыть папку со своими стратегиями (strategies\user)"
        Write-Host "  5. Открыть папку журналов (data\logs)"
        Write-Host ("  6. Игровой фильтр zapret: {0} (нажмите, чтобы переключить)" -f $gfText)
        Write-Host "  7. Обновления и списки (версии, домены, IPSet)"
        Write-Host "  8. Разобрать стратегию: что она делает с пакетом"
        Write-Host "  0. Назад"
        Write-Host ""
        $c = Read-Host "Выберите пункт"
        switch ($c) {
            "1" {
                Start-Process -FilePath (Join-Path $script:vendor "service.bat") -WorkingDirectory $script:vendor
                Write-Host "service.bat открыт в отдельном окне." -ForegroundColor DarkGray
                Wait-Menu
            }
            "2" { Show-NativeMenu }
            "3" {
                if (Confirm-CleanupSafe) {
                    # замок движка берётся непосредственно перед действиями: пока он у нас, никто не начнёт работу с драйвером
                    if (Enter-EngineLease 0) {
                        try {
                            if (@(Get-NormaBlockers).Count -eq 0) { Stop-Winws; Restore-TcpTimestamps; Invoke-Part "app\native\unload-driver.ps1" }
                            else { Write-Host "Пока шла проверка, запустился другой экземпляр NORMA: очистка отменена." -ForegroundColor Yellow }
                        } finally { Exit-EngineLease }
                    } else { Write-Host "Обход сейчас занят другим экземпляром NORMA: очистка отменена." -ForegroundColor Yellow }
                }
                Wait-Menu
            }
            "4" { Initialize-Dirs; Start-Process explorer.exe (Join-Path $script:stratDir "user") }
            "5" { Initialize-Dirs; Start-Process explorer.exe $script:logDir }
            "6" { [void](Switch-GameFilter) }
            "7" { Show-UpdatesMenu }
            "8" {
                $sp = Show-StrategyPicker ((Get-State).profile)
                if ($sp) { Clear-Host; Show-StrategyPlan $sp }
                Wait-Menu
            }
            "0" { return }
        }
    }
}

# проверка обновлений при запуске (не чаще раза в сутки; отключается в настройках)
try {
    if (Invoke-StartupUpdateCheck) { [void](Read-Host "Нажмите Enter, чтобы закрыть окно"); exit }
} catch { }

while ($true) {
    $st = Get-State
    $upd = ""
    try { if ($st.updateAvailable -and ([version][string]$st.updateAvailable -gt [version]$script:version)) { $upd = [string]$st.updateAvailable } } catch { $upd = "" }
    $profTxt = "YouTube"
    if ($st.profile -eq "all") { $profTxt = "YouTube + Discord" }
    $lastTxt = "ещё не подбиралась"
    if ($st.strategy) { $lastTxt = $st.strategy }

    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ("  NORMA {0}  (на основе zapret)" -f $script:version) -ForegroundColor Cyan
    Write-Host "  Node for Obfuscated Routing and Masked Access" -ForegroundColor DarkCyan
    Write-Host "  github.com/Quancore21/NORMA" -ForegroundColor DarkGray
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Профиль проверки: $profTxt" -ForegroundColor DarkGray
    Write-Host "  Последняя рабочая стратегия: $lastTxt" -ForegroundColor DarkGray
    if ($upd) { Write-Host ("  Доступна новая версия NORMA: {0} (меню 9, пункт 7)" -f $upd) -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "  1. ВКЛЮЧИТЬ NORMA (автоматически)" -ForegroundColor Green
    Write-Host "  2. Подобрать стратегию заново (полный перебор)"
    Write-Host "  3. Бенчмарк: проверить все стратегии, выбрать лучшую по скорости"
    Write-Host "  4. Выбрать стратегию вручную"
    Write-Host "  5. Замер сети: что не открывается без обхода"
    Write-Host "  6. Доктор: диагностика компьютера и сети"
    Write-Host "  7. Фоновый режим и автозапуск"
    Write-Host "  8. Настройки (автообновление, автозапуск, профиль, фильтры)"
    Write-Host "  9. Дополнительно"
    Write-Host "  0. Выход"
    Write-Host ""
    $c = Read-Host "Выберите пункт"
    switch ($c) {
        "1" { Invoke-Session -Mode "auto"; Wait-Menu }
        "2" { Invoke-Session -Mode "repick" -Force; Wait-Menu }
        "3" { Invoke-Session -Mode "bench"; Wait-Menu }
        "4" {
            $s = Show-StrategyPicker $st.profile
            if ($s) { Invoke-Session -Mode "manual" -Manual $s; Wait-Menu }
        }
        "5" { Show-Probe -Prof $st.profile; Wait-Menu }
        "6" { Invoke-Doctor; Wait-Menu }
        "7" { Show-BackgroundMenu }
        "8" { Show-SettingsMenu }
        "9" { Show-ExtraMenu }
        "0" { return }
    }
}
