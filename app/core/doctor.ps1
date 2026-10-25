# NORMA «Доктор»: проверка окружения. Ничего не меняет, только показывает, что не так и что с этим делать.
# Отчёт сохраняется в data\logs\norma-doctor-*.log и копируется в буфер обмена (удобно прислать при вопросах).

function Add-Check([string]$Level, [string]$Text, [string]$Hint = "") {
    $color = "Gray"
    $tag = "INFO"
    switch ($Level) {
        "ok" { $color = "Green"; $tag = " OK " }
        "warn" { $color = "Yellow"; $tag = "WARN" }
        "fail" { $color = "Red"; $tag = "FAIL" }
    }
    Say ("[{0}] {1}" -f $tag, $Text) $color
    if ($Hint) { Say ("       -> {0}" -f $Hint) "DarkGray" }
}

function Test-PrivateIp([string]$Ip) {
    return ($Ip -match '^(127\.|0\.|10\.|192\.168\.|169\.254\.)' -or $Ip -match '^172\.(1[6-9]|2\d|3[01])\.')
}

function Invoke-Doctor {
    $script:log.Clear()
    Say ("NORMA {0}: Доктор. Дата: {1}" -f $script:version, (Get-Date -Format "yyyy-MM-dd HH:mm")) "Cyan"
    Say ""

    # --- система
    $build = [Environment]::OSVersion.Version.Build
    Add-Check "info" ("Windows: {0} (сборка {1})" -f [Environment]::OSVersion.VersionString, $build)
    if ($build -lt 17134) { Add-Check "fail" "Windows слишком старая: нужна 10 версии 1803 (сборка 17134) или новее" "Без curl.exe проверки сайтов не работают" }
    if (Test-Admin) { Add-Check "ok" "Права администратора есть" } else { Add-Check "fail" "Нет прав администратора" "Запускайте NORMA.bat: он сам запросит права" }
    if ([Environment]::Is64BitProcess) { Add-Check "ok" "64-битный PowerShell" } else { Add-Check "fail" "32-битный PowerShell" "winws и WinDivert64 работают только в 64-битной среде" }
    if (Get-Command "curl.exe" -ErrorAction SilentlyContinue) { Add-Check "ok" "curl.exe найден" } else { Add-Check "fail" "curl.exe не найден" "Нужна Windows 10 1803+" }
    if ($script:root -match '[^\x00-\x7F]') { Add-Check "warn" ("Путь содержит кириллицу или спецсимволы: " + $script:root) "Перенесите папку, например, в C:\NORMA" }
    else { Add-Check "ok" ("Путь к папке без кириллицы: " + $script:root) }

    # --- файлы движка (антивирус мог их удалить)
    Say ""
    foreach ($f in @("winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll")) {
        $p = Join-Path $script:binDir $f
        if (Test-Path $p) { Add-Check "ok" ("Файл {0}: {1:N0} байт" -f $f, (Get-Item -LiteralPath $p).Length) }
        else { Add-Check "fail" ("Нет файла vendor\zapret\bin\{0}" -f $f) "Антивирус мог удалить его: добавьте папку NORMA в исключения и распакуйте архив заново" }
    }
    # контрольные суммы всех файлов bin сверяются с манифестом app\core\checksums.txt (его создаёт генератор из оригинала)
    $man = @(Get-ChecksumManifest)
    if ($man.Count -eq 0) {
        Add-Check "warn" "Нет манифеста контрольных сумм app\core\checksums.txt" "Распакуйте архив заново"
    } else {
        $core = @("winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll")
        $good = 0
        $problems = 0
        foreach ($e in $man) {
            $fp = Join-Path $script:binDir $e.Name
            if (-not (Test-Path $fp)) {
                if ($core -notcontains $e.Name) { Add-Check "warn" ("Нет файла bin\{0} из манифеста" -f $e.Name) "Распакуйте архив заново"; $problems++ }
                continue
            }
            $h = ""
            try { $h = (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash } catch {}
            if ($h -eq $e.Hash) { $good++; continue }
            $problems++
            $lvl = "warn"
            if ($core -contains $e.Name) { $lvl = "fail" }
            Add-Check $lvl ("Контрольная сумма bin\{0} не совпадает с ожидаемой" -f $e.Name) "Файл повреждён, изменён или заменён другой версией. Если вы его не меняли, распакуйте архив заново"
        }
        if ($problems -eq 0) { Add-Check "ok" ("Контрольные суммы файлов bin совпали с манифестом: {0} файлов" -f $good) }
    }
    $sys = Join-Path $script:binDir "WinDivert64.sys"
    if (Test-Path $sys) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $sys
            if ($sig.Status -eq "Valid") { Add-Check "ok" "Подпись драйвера WinDivert64.sys действительна" }
            else { Add-Check "warn" ("Подпись драйвера WinDivert64.sys: {0}" -f $sig.Status) "Файл мог быть изменён или повреждён: распакуйте архив заново" }
        } catch {}
    }

    # --- стратегии
    Say ""
    $all = @(Get-Strategies)
    $nz = @($all | Where-Object { $_.Source -eq "zapret" }).Count
    $nn = @($all | Where-Object { $_.Source -eq "norma" }).Count
    $nu = @($all | Where-Object { $_.Source -eq "user" }).Count
    if ($all.Count -gt 0) { Add-Check "ok" ("Стратегий: {0} (zapret: {1}, NORMA: {2}, ваши: {3})" -f $all.Count, $nz, $nn, $nu) }
    else { Add-Check "fail" "Не найдено ни одной стратегии" "Проверьте папки vendor\zapret и strategies" }

    # --- конфликты
    Say ""
    $run = @(Get-Process -Name "goodbyedpi", "winws" -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
    if ($run.Count -gt 0) {
        Add-Check "warn" ("Уже запущено: {0}" -f ($run -join ", ")) "Остановите перед включением NORMA (NORMA спросит сама)"
        foreach ($cl in @(Get-RunningCommandLines @("winws", "goodbyedpi"))) { Add-Check "info" $cl }
    }
    else { Add-Check "ok" "Других обходчиков (winws, goodbyedpi) не запущено" }
    $svc = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
    if ($svc) { Add-Check "warn" ("Установлена служба zapret (состояние: {0})" -f $svc.Status) "Она конфликтует с NORMA. Удалить: меню NORMA, пункт service.bat, Remove Services" }
    $wd = @(Get-Service -Name "WinDivert*" -ErrorAction SilentlyContinue)
    foreach ($w in $wd) { Add-Check "info" ("Служба драйвера {0}: {1}" -f $w.Name, $w.Status) }
    $vpn = @(Get-Process -Name "xray", "v2ray", "sing-box", "clash", "clash-verge", "mihomo", "nekoray", "hiddify", "openvpn", "wireguard", "outline" -ErrorAction SilentlyContinue |
            ForEach-Object { $_.ProcessName } | Select-Object -Unique)
    if ($vpn.Count -gt 0) { Add-Check "warn" ("Запущены VPN или прокси: {0}" -f ($vpn -join ", ")) "Они могут перехватывать трафик раньше NORMA или вместе с ней. Если подбор не помогает, отключите их на время проверки" }
    else { Add-Check "ok" "Известных VPN и прокси не запущено" }

    # --- сеть и DNS
    Say ""
    try {
        $ips = @([System.Net.Dns]::GetHostAddresses("www.youtube.com") | ForEach-Object { $_.IPAddressToString })
        if ($ips.Count -eq 0) { Add-Check "fail" "www.youtube.com не резолвится" "Включите Secure DNS (DNS через HTTPS) в браузере или в настройках сети Windows 11" }
        elseif (@($ips | Where-Object { Test-PrivateIp $_ }).Count -gt 0) {
            Add-Check "warn" ("DNS подменяет адрес youtube.com: {0}" -f ($ips -join ", ")) "Включите Secure DNS: без него обход пакетами не поможет"
        }
        else { Add-Check "ok" ("DNS отвечает для youtube.com: {0}" -f (($ips | Select-Object -First 3) -join ", ")) }
    } catch { Add-Check "fail" "Не удалось получить адрес www.youtube.com" "Проверьте интернет и включите Secure DNS" }
    $doh = $null
    try { $doh = @(Get-DnsClientDohServerAddress -ErrorAction Stop) } catch { $doh = $null }
    if ($doh -and $doh.Count -gt 0) { Add-Check "info" "В Windows настроен DNS через HTTPS" }
    else { Add-Check "info" "Secure DNS в Windows не найден (если он включён в браузере, это нормально)" }
    try {
        $v6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike "fe80*" -and $_.IPAddress -ne "::1" })
        if ($v6.Count -gt 0) { Add-Check "info" "У адаптера есть глобальный IPv6" "Если YouTube открывается мимо обхода, попробуйте отключить IPv6 у сетевого адаптера" }
        else { Add-Check "info" "Глобального IPv6 нет" }
    } catch {}
    if (Get-Command "curl.exe" -ErrorAction SilentlyContinue) {
        $r = Test-Urls @("https://www.google.com", "https://www.cloudflare.com")
        if ($r["https://www.google.com"] -or $r["https://www.cloudflare.com"]) { Add-Check "ok" "Интернет работает" }
        else { Add-Check "fail" "Интернет не отвечает (или curl блокируется)" "Проверьте подключение" }
    }

    # --- данные NORMA
    Say ""
    try {
        Initialize-Dirs
        $tp = Join-Path $script:dataDir "write-test.tmp"
        [IO.File]::WriteAllText($tp, "ok"); Remove-Item -LiteralPath $tp -Force
        Add-Check "ok" "Папка data доступна для записи"
    } catch { Add-Check "fail" "Нельзя записывать в папку data" "Перенесите NORMA из защищённой папки (Program Files) в C:\NORMA" }
    $st = Get-State
    $last = "ещё не подбиралась"
    if ($st.strategy) { $last = $st.strategy }
    Add-Check "info" ("Последняя рабочая стратегия: {0}" -f $last)
    Add-Check "info" ("Игровой фильтр zapret: {0}; режим IPSet: {1}" -f $st.gameFilter, (Get-IpsetMode))
    if ($st.tsRestore) { Add-Check "warn" ("TCP timestamps: после прошлого запуска NORMA остался незавершённый возврат исходного значения ({0})" -f $st.tsRestore) "Выполнится при следующем выходе из NORMA или в меню «Дополнительно», пункт «Очистка»" }
    Add-Check "info" ("Версия zapret-discord-youtube в сборке: {0}" -f (Get-LocalUpstreamVersion))
    Add-Check "info" ("Текущая сеть: {0}" -f (Get-NetworkSignature))
    $ai = Get-AutostartInfo
    if (-not $ai.Exists) { Add-Check "info" "Автозапуск NORMA выключен" }
    elseif ($ai.Current) { Add-Check "ok" "Автозапуск NORMA включён и указывает на эту папку" }
    elseif ($ai.Legacy) { Add-Check "warn" "Автозапуск включён в старом формате" "Меню «Фоновый режим», пункт 1 пересоздаст его" }
    else { Add-Check "warn" "Автозапуск указывает на другую папку (NORMA перенесена?)" "Меню «Фоновый режим», пункт 1 исправит" }
    $sets = Get-Settings
    Add-Check "info" ("Автообновление NORMA: {0}; автообновление списков: {1}" -f $sets.autoUpdateNorma, $sets.autoUpdateLists)
    if ($st.updateAvailable) { Add-Check "info" ("Доступна новая версия NORMA: {0}" -f $st.updateAvailable) }

    Say ""
    $lp = Save-NormaLog "doctor"
    try { Set-Clipboard -Value ($script:log -join "`r`n") } catch {}
    if ($lp) { Say ("Отчёт: {0} (и в буфере обмена)." -f $lp) "DarkGray" }
}
