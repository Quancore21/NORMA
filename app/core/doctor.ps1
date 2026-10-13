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
    foreach ($f in @("winws.exe", "WinDivert64.sys")) {
        $p = Join-Path $script:binDir $f
        if (Test-Path $p) {
            try { Add-Check "info" ("SHA256 {0}: {1}" -f $f, (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash) } catch {}
        }
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
    Add-Check "info" ("Текущая сеть: {0}" -f (Get-NetworkSignature))
    if (Get-AutostartState) { Add-Check "info" "Автозапуск NORMA включён" } else { Add-Check "info" "Автозапуск NORMA выключен" }

    Say ""
    $lp = Save-NormaLog "doctor"
    try { Set-Clipboard -Value ($script:log -join "`r`n") } catch {}
    if ($lp) { Say ("Отчёт: {0} (и в буфере обмена)." -f $lp) "DarkGray" }
}
