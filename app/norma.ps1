# NORMA - Node for Obfuscated Routing and Masked Access. Версия 0.7.
$script:normaRoot = $env:NORMA_DIR
if (-not $script:normaRoot) { $script:normaRoot = (Get-Location).Path }
$script:normaRoot = $script:normaRoot.TrimEnd('\')

# Загружаем ядро в текущую область видимости (dot-source), чтобы функции были доступны меню.
foreach ($rel in @("app\core\lib.ps1", "app\core\autopick.ps1", "app\core\session.ps1", "app\core\doctor.ps1", "app\core\autostart.ps1")) {
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
        $src = $all[$i].Source
        Write-Host ("  {0,2}. {1,-34} [{2}]" -f ($i + 1), $all[$i].Name, $src)
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
        $auto = "выключен"
        if (Get-AutostartState) { $auto = "ВКЛЮЧЁН" }
        $bg = "не запущен"
        if (Get-BackgroundProcess) { $bg = "РАБОТАЕТ" }
        Write-Host "  Фоновый режим и автозапуск" -ForegroundColor Cyan
        Write-Host "  Автозапуск при входе в Windows: $auto" -ForegroundColor DarkGray
        Write-Host "  Фоновый NORMA сейчас: $bg" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  1. Включить автозапуск (в фоне, без окна)"
        Write-Host "  2. Выключить автозапуск"
        Write-Host "  3. Запустить фоновый режим сейчас"
        Write-Host "  4. Остановить фоновый режим"
        Write-Host "  0. Назад"
        Write-Host ""
        $c = Read-Host "Выберите пункт"
        switch ($c) {
            "1" { Install-Autostart; Wait-Menu }
            "2" { Remove-Autostart; Wait-Menu }
            "3" { Start-Background; Wait-Menu }
            "4" { Stop-Background; Wait-Menu }
            "0" { return }
        }
    }
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
            "1" { Stop-Winws; Invoke-Part "app\native\run.ps1"; Wait-Menu }
            "2" { Invoke-Part "app\native\probe.ps1"; Wait-Menu }
            "3" { Stop-Winws; Invoke-Part "app\native\lab.ps1"; Wait-Menu }
            "4" { Stop-Winws; Invoke-Part "app\native\lab.ps1" @{ Quick = $true }; Wait-Menu }
            "0" { return }
        }
    }
}

function Show-ExtraMenu {
    while ($true) {
        Clear-Host
        Write-Host "  Дополнительно" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  1. Сервис zapret: служба Windows, списки, hosts (service.bat)"
        Write-Host "  2. Собственный движок NORMA (эксперимент)"
        Write-Host "  3. Выгрузить драйвер WinDivert (очистка)"
        Write-Host "  4. Открыть папку со своими стратегиями (strategies\user)"
        Write-Host "  5. Открыть папку журналов (data\logs)"
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
            "3" { Stop-Winws; Invoke-Part "app\native\unload-driver.ps1"; Wait-Menu }
            "4" { Initialize-Dirs; Start-Process explorer.exe (Join-Path $script:stratDir "user") }
            "5" { Initialize-Dirs; Start-Process explorer.exe $script:logDir }
            "0" { return }
        }
    }
}

while ($true) {
    $st = Get-State
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
    Write-Host ""
    Write-Host "  1. ВКЛЮЧИТЬ NORMA (автоматически)" -ForegroundColor Green
    Write-Host "  2. Подобрать стратегию заново (полный перебор)"
    Write-Host "  3. Бенчмарк: проверить все стратегии, выбрать лучшую по скорости"
    Write-Host "  4. Выбрать стратегию вручную"
    Write-Host "  5. Замер сети: что не открывается без обхода"
    Write-Host "  6. Доктор: диагностика компьютера и сети"
    Write-Host "  7. Фоновый режим и автозапуск"
    Write-Host "  8. Переключить профиль (YouTube / YouTube + Discord)"
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
        "8" {
            if ($st.profile -eq "all") { $st.profile = "youtube" } else { $st.profile = "all" }
            Save-State $st
        }
        "9" { Show-ExtraMenu }
        "0" { return }
    }
}
