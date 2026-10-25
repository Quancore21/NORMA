# NORMA: настройки пользователя (data\settings.json) и экран «Настройки».
# Состояние работы (последняя стратегия, память по сетям, отметки времени) хранится отдельно в data\state.json.
#
#   autoUpdateNorma   auto (проверять и ставить сами), notify (только сообщать), off (не проверять)
#   autoUpdateLists   плановое обновление списков доменов и IPSet
#   updateCheckHours  как часто проверять обновления (часов)

$script:settingsPath = Join-Path $script:dataDir "settings.json"

function Get-DefaultSettings {
    return [pscustomobject]@{ autoUpdateNorma = "auto"; autoUpdateLists = $true; updateCheckHours = 24 }
}

# Читает настройки; недостающие и некорректные значения заменяются значениями по умолчанию
function Get-Settings {
    $d = Get-DefaultSettings
    $s = $null
    try {
        if (Test-Path $script:settingsPath) { $s = [IO.File]::ReadAllText($script:settingsPath, [Text.Encoding]::UTF8) | ConvertFrom-Json }
    } catch { $s = $null }
    if ($s) {
        if (@("auto", "notify", "off") -contains [string]$s.autoUpdateNorma) { $d.autoUpdateNorma = [string]$s.autoUpdateNorma }
        if ($s.autoUpdateLists -is [bool]) { $d.autoUpdateLists = [bool]$s.autoUpdateLists }
        $h = 0
        if ([int]::TryParse([string]$s.updateCheckHours, [ref]$h) -and $h -ge 1 -and $h -le 720) { $d.updateCheckHours = $h }
    }
    return $d
}

function Save-Settings($Settings) {
    try {
        Initialize-Dirs
        [IO.File]::WriteAllText($script:settingsPath, (ConvertTo-Json -InputObject $Settings), (New-Object Text.UTF8Encoding($false)))
        return $true
    } catch { return $false }
}

function Switch-UpdateMode {
    $s = Get-Settings
    switch ($s.autoUpdateNorma) {
        "auto" { $s.autoUpdateNorma = "notify" }
        "notify" { $s.autoUpdateNorma = "off" }
        default { $s.autoUpdateNorma = "auto" }
    }
    [void](Save-Settings $s)
    return $s.autoUpdateNorma
}

function Switch-ListsUpdate {
    $s = Get-Settings
    $s.autoUpdateLists = (-not $s.autoUpdateLists)
    [void](Save-Settings $s)
    return $s.autoUpdateLists
}

function Get-UpdateModeText([string]$Mode) {
    switch ($Mode) {
        "auto" { return "автоматически (проверять и устанавливать)" }
        "notify" { return "только уведомлять" }
        default { return "выключено" }
    }
}

function Show-SettingsMenu {
    while ($true) {
        Clear-Host
        $s = Get-Settings
        $st = Get-State
        $listsText = "выключено"
        if ($s.autoUpdateLists) { $listsText = ("включено, раз в {0} ч." -f $s.updateCheckHours) }
        $autoText = "выключен"
        $ai = Get-AutostartInfo
        if ($ai.Exists -and $ai.Current) { $autoText = "включён" }
        elseif ($ai.Exists) { $autoText = "включён, но требует обновления (пункт 3 исправит)" }
        $profText = "YouTube"
        if ($st.profile -eq "all") { $profText = "YouTube + Discord" }
        $gf = "выключен"
        if ($st.gameFilter -eq "all") { $gf = "TCP и UDP" } elseif ($st.gameFilter -eq "tcp") { $gf = "только TCP" } elseif ($st.gameFilter -eq "udp") { $gf = "только UDP" }
        Write-Host "  Настройки" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ("  1. Автообновление NORMA: {0}" -f (Get-UpdateModeText $s.autoUpdateNorma))
        Write-Host ("  2. Автообновление списков (домены и IPSet): {0}" -f $listsText)
        Write-Host ("  3. Автозапуск при входе в Windows: {0}" -f $autoText)
        Write-Host ("  4. Профиль проверки: {0}" -f $profText)
        Write-Host ("  5. Игровой фильтр zapret: {0}" -f $gf)
        Write-Host ("  6. Режим IPSet: {0}" -f (Get-IpsetMode))
        Write-Host "  0. Назад"
        Write-Host ""
        Write-Host "  Пункт переключает значение по кругу." -ForegroundColor DarkGray
        $c = Read-Host "Выберите пункт"
        switch ($c) {
            "1" { [void](Switch-UpdateMode) }
            "2" { [void](Switch-ListsUpdate) }
            "3" {
                if ($ai.Exists -and $ai.Current) { Disable-Autostart } else { [void](Enable-Autostart -StartNow) }
                Wait-Menu
            }
            "4" {
                if ($st.profile -eq "all") { $st.profile = "youtube" } else { $st.profile = "all" }
                Save-State $st
            }
            "5" { [void](Switch-GameFilter) }
            "6" { [void](Switch-IpsetMode) }
            "0" { return }
        }
    }
}
