# NORMA: обновления. Проверка версий (NORMA и оригинала zapret-discord-youtube), обновление списков доменов, режимы и обновление IPSet.
# Источник данных оригинала: ветка main репозитория Flowseal/zapret-discord-youtube на raw.githubusercontent.com.
# Если GitHub у провайдера недоступен, загрузка не удастся: это не ошибка NORMA (в vendor\zapret\.service\hosts есть адреса для GitHub).
#
# Все обновления файлов идут через Invoke-FileUpdate: сначала всё скачивается и проверяется во временной папке,
# и только если проверка прошла для всех файлов, они заменяются (с резервной копией и откатом при сбое).

$script:upstreamRaw = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main"
$script:normaRaw = "https://raw.githubusercontent.com/Quancore21/NORMA/main"
$script:normaReleases = "https://github.com/Quancore21/NORMA/releases/latest"
$script:updatableLists = @("list-general.txt", "list-google.txt", "list-exclude.txt", "ipset-exclude.txt")
$script:ipsetPlaceholder = "203.0.113.113/32"

function Get-TextFromUrl([string]$Url) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = "SilentlyContinue"
    $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 60
    if ($r.Content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($r.Content) }
    return [string]$r.Content
}

function Get-ListLines([string]$Text) {
    return @($Text -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

function Test-PathSafe([string]$Path) {
    try { return (Test-Path -LiteralPath $Path) } catch { return $false }
}

# ---------- проверки скачанных списков (возвращают текст ошибки или $null)
function Test-ListText([string]$Text, [string]$Old) {
    if ($Text -match '<html|<!DOCTYPE') { return "ответ не похож на список (HTML)" }
    $new = @(Get-ListLines $Text)
    if ($new.Count -lt 1) { return "список пуст" }
    $oldN = @(Get-ListLines $Old).Count
    if ($oldN -ge 20 -and $new.Count -lt ($oldN / 2)) { return ("новый список более чем вдвое меньше старого ({0} против {1})" -f $new.Count, $oldN) }
    return $null
}

# Строгая проверка записи IPSet: адрес IPv4 или IPv6 и, если есть, допустимая длина префикса (до 32 и до 128)
function Test-IpEntry([string]$Entry) {
    $parts = $Entry.Split("/")
    if ($parts.Count -gt 2) { return $false }
    $addr = $parts[0]
    $hasPrefix = ($parts.Count -eq 2)
    $prefix = -1
    if ($hasPrefix) {
        if ($parts[1] -notmatch '^\d{1,3}$') { return $false }
        $prefix = [int]$parts[1]
    }
    if ($addr.Contains(":")) {
        if ($addr -notmatch '^[0-9a-fA-F:.]+$') { return $false }
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($addr, [ref]$ip)) { return $false }
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $false }
        if ($hasPrefix -and $prefix -gt 128) { return $false }
        return $true
    }
    if ($addr -notmatch '^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$') { return $false }
    if ($hasPrefix -and $prefix -gt 32) { return $false }
    return $true
}

# Проверяет все строки; возвращает текст ошибки или $null. Любая некорректная запись отклоняет весь список.
function Test-IpLines($Lines) {
    $bad = @()
    $count = 0
    foreach ($l in $Lines) {
        if (-not (Test-IpEntry $l)) { $count++; if ($bad.Count -lt 3) { $bad += $l } }
    }
    if ($count -gt 0) { return ("некорректных записей: {0}, например: {1}" -f $count, ($bad -join ", ")) }
    return $null
}

# Большой список IPSet (десятки тысяч записей)
function Test-IpsetText([string]$Text, [string]$Old) {
    if ($Text -match '<html|<!DOCTYPE') { return "ответ не похож на список (HTML)" }
    $lines = @(Get-ListLines $Text)
    if ($lines.Count -lt 100) { return ("слишком мало записей: {0}" -f $lines.Count) }
    $err = Test-IpLines $lines
    if ($err) { return $err }
    $oldN = @(Get-ListLines $Old).Count
    if ($oldN -ge 1000 -and $lines.Count -lt ($oldN / 2)) { return ("новый список более чем вдвое меньше старого ({0} против {1})" -f $lines.Count, $oldN) }
    return $null
}

# Небольшой список адресов (например, исключения IPSet)
function Test-IpListText([string]$Text, [string]$Old) {
    if ($Text -match '<html|<!DOCTYPE') { return "ответ не похож на список (HTML)" }
    $lines = @(Get-ListLines $Text)
    if ($lines.Count -lt 1) { return "список пуст" }
    $err = Test-IpLines $lines
    if ($err) { return $err }
    $oldN = @(Get-ListLines $Old).Count
    if ($oldN -ge 20 -and $lines.Count -lt ($oldN / 2)) { return ("новый список более чем вдвое меньше старого ({0} против {1})" -f $lines.Count, $oldN) }
    return $null
}

# ---------- транзакционное обновление набора файлов
# Item (hashtable): Name, Dest, Url, Check = "list" | "iplist" | "ipset".
# Fetch (необязательно): scriptblock { param($url) ... } для подмены загрузки (в самопроверке).
# Результат: { Ok; Error; Rollback = none | ok | failed; Details = [ { Name; Status = changed|unchanged; Count; Added; Removed } ]; Backup }
#   Rollback: none (файлы не менялись), ok (применённое отменено и проверено), failed (восстановить не удалось: см. Error и резервные копии).
# Все файловые операции с -ErrorAction Stop: сбой любой из них прерывает применение, а не остаётся незамеченным.
function New-UpdateResult([bool]$Ok, [string]$ErrorText, [string]$Rollback, $Details, [string]$Backup) {
    return [pscustomobject]@{ Ok = $Ok; Error = $ErrorText; Rollback = $Rollback; Details = @($Details); Backup = $Backup }
}

function Invoke-FileUpdate($Items, [scriptblock]$Fetch = $null) {
    if (-not $Fetch) { $Fetch = { param($u) Get-TextFromUrl $u } }
    $stamp = (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 6)
    $tmp = Join-Path $script:dataDir ("tmp\update-" + $stamp)
    $backup = Join-Path $script:dataDir ("backup\update-" + $stamp)
    $utf8 = New-Object Text.UTF8Encoding($false)
    $details = @()
    $cache = @{}
    try {
        New-Item -ItemType Directory -Path $tmp -Force -ErrorAction Stop | Out-Null

        # 1) скачать и проверить ВСЕ; при любой ошибке ничего не меняется
        $plan = @()
        foreach ($it in @($Items)) {
            $text = ""
            try {
                if ($cache.ContainsKey($it.Url)) { $text = $cache[$it.Url] }
                else { $text = [string](& $Fetch $it.Url); $cache[$it.Url] = $text }
            } catch {
                return (New-UpdateResult $false ("{0}: не скачался ({1}); файлы не изменялись" -f $it.Name, $_.Exception.Message) "none" @() "")
            }
            $old = ""
            if (Test-PathSafe $it.Dest) { try { $old = [IO.File]::ReadAllText($it.Dest, [Text.Encoding]::UTF8) } catch { $old = "" } }
            $err = $null
            switch ($it.Check) {
                "ipset" { $err = Test-IpsetText $text $old }
                "iplist" { $err = Test-IpListText $text $old }
                default { $err = Test-ListText $text $old }
            }
            if ($err) { return (New-UpdateResult $false ("{0}: {1}; файлы не изменялись" -f $it.Name, $err) "none" @() "") }

            $newLines = @(Get-ListLines $text)
            $oldLines = @(Get-ListLines $old)
            $oldSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($l in $oldLines) { [void]$oldSet.Add($l) }
            $newSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($l in $newLines) { [void]$newSet.Add($l) }
            $added = 0
            foreach ($l in $newLines) { if (-not $oldSet.Contains($l)) { $added++ } }
            $removed = 0
            foreach ($l in $oldLines) { if (-not $newSet.Contains($l)) { $removed++ } }
            $changed = (($added -gt 0) -or ($removed -gt 0) -or -not (Test-PathSafe $it.Dest))
            $status = "unchanged"
            if ($changed) { $status = "changed" }
            $details += [pscustomobject]@{ Name = $it.Name; Status = $status; Count = $newLines.Count; Added = $added; Removed = $removed }
            if ($changed) {
                $tmpFile = Join-Path $tmp ([Guid]::NewGuid().ToString("N") + ".txt")
                [IO.File]::WriteAllText($tmpFile, (($newLines -join "`r`n") + "`r`n"), $utf8)
                $plan += [pscustomobject]@{ Item = $it; TmpFile = $tmpFile }
            }
        }

        # 2) применить: резервная копия, запись рядом и замена, проверка записи; при сбое откат всех уже применённых
        $applied = @()
        try {
            foreach ($step in $plan) {
                $dest = $step.Item.Dest
                $hadOld = Test-PathSafe $dest
                if ($hadOld) {
                    if (-not (Test-Path $backup)) { New-Item -ItemType Directory -Path $backup -Force -ErrorAction Stop | Out-Null }
                    $bfile = Join-Path $backup $step.Item.Name
                    Copy-Item -LiteralPath $dest -Destination $bfile -Force -ErrorAction Stop
                    if (-not (Test-Path -LiteralPath $bfile) -or ((Get-Item -LiteralPath $bfile -ErrorAction Stop).Length -ne (Get-Item -LiteralPath $dest -ErrorAction Stop).Length)) {
                        throw ("резервная копия {0} не создана" -f $step.Item.Name)
                    }
                }
                $applied += [pscustomobject]@{ Dest = $dest; Name = $step.Item.Name; HadOld = $hadOld }
                $stage = $dest + ".new"
                $newText = [IO.File]::ReadAllText($step.TmpFile, $utf8)
                [IO.File]::WriteAllText($stage, $newText, $utf8)
                Move-Item -LiteralPath $stage -Destination $dest -Force -ErrorAction Stop
                if ([IO.File]::ReadAllText($dest, $utf8) -ne $newText) { throw ("проверка записи не прошла: {0}" -f $step.Item.Name) }
            }
        } catch {
            $why = $_.Exception.Message
            $failedBack = @()
            for ($k = $applied.Count - 1; $k -ge 0; $k--) {
                $a = $applied[$k]
                try {
                    if ($a.HadOld) {
                        $bfile = Join-Path $backup $a.Name
                        Copy-Item -LiteralPath $bfile -Destination $a.Dest -Force -ErrorAction Stop
                        if ([IO.File]::ReadAllText($a.Dest, $utf8) -ne [IO.File]::ReadAllText($bfile, $utf8)) { throw "после восстановления содержимое не совпало с копией" }
                    } elseif (Test-PathSafe $a.Dest) {
                        Remove-Item -LiteralPath $a.Dest -Force -ErrorAction Stop
                    }
                    if (Test-PathSafe ($a.Dest + ".new")) { Remove-Item -LiteralPath ($a.Dest + ".new") -Force -ErrorAction Stop }
                } catch { $failedBack += $a.Name }
            }
            if ($failedBack.Count -gt 0) {
                return (New-UpdateResult $false ("замена файлов не удалась ({0}); ВОССТАНОВИТЬ НЕ УДАЛОСЬ: {1}. Резервные копии: {2}" -f $why, ($failedBack -join ", "), $backup) "failed" $details $backup)
            }
            if ($applied.Count -gt 0) {
                return (New-UpdateResult $false ("замена файлов не удалась ({0}); применённые изменения отменены и проверены" -f $why) "ok" $details $backup)
            }
            return (New-UpdateResult $false ("замена файлов не удалась ({0}); файлы не изменялись" -f $why) "none" $details "")
        }

        # хранить только последние 10 резервных копий (это уборка: её сбой на результат не влияет)
        try {
            $bdir = Join-Path $script:dataDir "backup"
            if (Test-Path $bdir) {
                Get-ChildItem -LiteralPath $bdir -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
                    Select-Object -Skip 10 | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
            }
        } catch {}
        $bk = ""
        if (Test-Path $backup) { $bk = $backup }
        return (New-UpdateResult $true "" "none" $details $bk)
    }
    catch {
        return (New-UpdateResult $false ("обновление прервано: {0}; файлы не изменялись" -f $_.Exception.Message) "none" $details "")
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Show-UpdateResult($R) {
    if (-not $R.Ok) {
        if ($R.Rollback -eq "failed") { Say ("ВНИМАНИЕ: обновление не выполнено, и откат тоже не удался. " + $R.Error) "Red" }
        else { Say ("Обновление не выполнено: " + $R.Error) "Red" }
        return
    }
    $changed = 0
    foreach ($d in @($R.Details)) {
        if ($d.Status -eq "changed") {
            $changed++
            Say ("  {0,-24} обновлён: {1} записей (+{2}, -{3})" -f $d.Name, $d.Count, $d.Added, $d.Removed) "Green"
        } else {
            Say ("  {0,-24} без изменений ({1} записей)" -f $d.Name, $d.Count) "DarkGray"
        }
    }
    if ($changed -gt 0) {
        $msg = ("Обновлено файлов: {0}." -f $changed)
        if ($R.Backup) { $msg += (" Старые версии: " + $R.Backup) }
        Say $msg "Green"
    } else { Say "Всё актуально, файлы не изменились." "Gray" }
}

# ---------- списки доменов
function Update-Lists {
    Initialize-Dirs
    $items = @()
    foreach ($name in $script:updatableLists) {
        $chk = "list"
        if ($name -like "ipset*") { $chk = "iplist" }
        $items += @{ Name = $name; Dest = (Join-Path $script:listsDir $name); Url = ("{0}/lists/{1}" -f $script:upstreamRaw, $name); Check = $chk }
    }
    Say "Обновление списков доменов (все файлы проверяются перед заменой)..." "Cyan"
    $r = Invoke-FileUpdate $items
    Show-UpdateResult $r
    return $r
}

# ---------- IPSet: режимы none / any / loaded (как в service.bat оригинала)
#   none    файл содержит только заглушку 203.0.113.113/32: правила по IPSet ничего не затрагивают;
#   any     файл пуст: правила действуют на любые адреса;
#   loaded  загружен полный список адресов.
# Загруженный список хранится в ipset-all.txt.backup, чтобы режимы можно было переключать без повторной загрузки.
function Get-IpsetMode {
    $f = Join-Path $script:listsDir "ipset-all.txt"
    if (-not (Test-PathSafe $f)) { return "any" }
    if ((Get-Item -LiteralPath $f).Length -gt 4096) { return "loaded" }
    $lines = @(Get-ListLines ([IO.File]::ReadAllText($f, [Text.Encoding]::UTF8)))
    if ($lines.Count -eq 0) { return "any" }
    if ($lines -contains $script:ipsetPlaceholder) { return "none" }
    return "loaded"
}

function Set-IpsetMode([string]$Mode) {
    $f = Join-Path $script:listsDir "ipset-all.txt"
    $b = $f + ".backup"
    $cur = Get-IpsetMode
    if ($Mode -eq $cur) { return $true }
    try {
        if ($Mode -eq "loaded") {
            if (-not (Test-PathSafe $b)) { Say "Нет сохранённого списка IPSet: сначала обновите его (пункт «Обновить IPSet»)." "Yellow"; return $false }
            Copy-Item -LiteralPath $b -Destination $f -Force
            return $true
        }
        if ($cur -eq "loaded") { Copy-Item -LiteralPath $f -Destination $b -Force }   # загруженный список сохраняется
        $utf8 = New-Object Text.UTF8Encoding($false)
        if ($Mode -eq "none") { [IO.File]::WriteAllText($f, ($script:ipsetPlaceholder + "`r`n"), $utf8) }
        else { [IO.File]::WriteAllText($f, "", $utf8) }
        return $true
    } catch {
        Say ("Не удалось переключить режим IPSet: " + $_.Exception.Message) "Red"
        return $false
    }
}

# Переключает по кругу как в оригинале: loaded, none, any, loaded
function Switch-IpsetMode {
    $next = "loaded"
    switch (Get-IpsetMode) {
        "loaded" { $next = "none" }
        "none" { $next = "any" }
        default { $next = "loaded" }
    }
    [void](Set-IpsetMode $next)
    return (Get-IpsetMode)
}

# Обновляет сохранённый список IPSet; живой файл обновляется, только если сейчас режим loaded
function Update-Ipset {
    Initialize-Dirs
    $url = $script:upstreamRaw + "/.service/ipset-service.txt"
    $live = Join-Path $script:listsDir "ipset-all.txt"
    $items = @(@{ Name = "ipset-all.txt.backup"; Dest = ($live + ".backup"); Url = $url; Check = "ipset" })
    if ((Get-IpsetMode) -eq "loaded") { $items += @{ Name = "ipset-all.txt"; Dest = $live; Url = $url; Check = "ipset" } }
    Say "Обновление списка IPSet (около 600 КБ)..." "Cyan"
    $r = Invoke-FileUpdate $items
    Show-UpdateResult $r
    Say ("Режим IPSet сейчас: {0}" -f (Get-IpsetMode)) "Gray"
    return $r
}

# ---------- версии
function Get-LocalUpstreamVersion {
    $p = Join-Path $script:vendor ".service\version.txt"
    try { if (Test-Path $p) { return ([IO.File]::ReadAllText($p)).Trim() } } catch {}
    return ""
}

# Сравнивает версию оригинала в vendor с последней на GitHub; возвращает последнюю версию или пустую строку
function Show-UpstreamVersion {
    $local = Get-LocalUpstreamVersion
    Say ("Версия zapret-discord-youtube в этой сборке NORMA: {0}" -f $local) "Gray"
    $remote = ""
    try { $remote = (Get-TextFromUrl ($script:upstreamRaw + "/.service/version.txt")).Trim() }
    catch {
        Say ("Не удалось проверить: {0}" -f $_.Exception.Message) "Yellow"
        Say "Если GitHub недоступен, в vendor\zapret\.service\hosts есть адреса для него (раздел hosts в service.bat)." "DarkGray"
        return ""
    }
    Say ("Последняя версия на GitHub: {0}" -f $remote) "Gray"
    $newer = $false
    try { $newer = ([version]$remote -gt [version]$local) } catch { $newer = ($remote -ne $local) }
    if ($newer) {
        Say "Вышла новая версия оригинала: в ней могут быть новые стратегии и списки." "Yellow"
        Say "Списки можно обновить сразу (пункт «Обновить списки»); стратегии придут с новой версией NORMA." "DarkGray"
    } else {
        Say "У вас актуальная версия оригинала." "Green"
    }
    return $remote
}
