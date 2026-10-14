# NORMA: обновления. Проверка версии оригинала (zapret-discord-youtube) и обновление списков доменов.
# Источник: ветка main репозитория Flowseal/zapret-discord-youtube на raw.githubusercontent.com.
# Если GitHub у провайдера недоступен, загрузка не удастся: это не ошибка NORMA (в vendor\zapret\.service\hosts есть адреса для GitHub).

$script:upstreamRaw = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main"
$script:updatableLists = @("list-general.txt", "list-google.txt", "list-exclude.txt", "ipset-exclude.txt")

function Get-TextFromUrl([string]$Url) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = "SilentlyContinue"
    $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
    if ($r.Content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($r.Content) }
    return [string]$r.Content
}

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

function Get-ListLines([string]$Text) {
    return @($Text -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
}

# Обновляет списки доменов из main оригинала. Старые файлы сохраняются в data\backup\lists-ДАТА.
function Update-Lists {
    Initialize-Dirs
    $backup = Join-Path $script:dataDir ("backup\lists-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    $updated = 0
    foreach ($name in $script:updatableLists) {
        $dest = Join-Path $script:listsDir $name
        $text = ""
        try { $text = Get-TextFromUrl ("{0}/lists/{1}" -f $script:upstreamRaw, $name) }
        catch { Say ("  {0,-22} не скачался: {1}" -f $name, $_.Exception.Message) "Red"; continue }

        $new = Get-ListLines $text
        if ($text -match '<html|<!DOCTYPE' -or $new.Count -lt 1) {
            Say ("  {0,-22} ответ не похож на список, пропускаю" -f $name) "Red"
            continue
        }
        $old = @()
        if (Test-Path $dest) { $old = Get-ListLines ([IO.File]::ReadAllText($dest, [Text.Encoding]::UTF8)) }
        if ($old.Count -ge 20 -and $new.Count -lt ($old.Count / 2)) {
            Say ("  {0,-22} новый список более чем вдвое меньше старого ({1} против {2}), пропускаю" -f $name, $new.Count, $old.Count) "Red"
            continue
        }

        $oldSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($l in $old) { [void]$oldSet.Add($l) }
        $newSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($l in $new) { [void]$newSet.Add($l) }
        $added = 0
        foreach ($l in $new) { if (-not $oldSet.Contains($l)) { $added++ } }
        $removed = 0
        foreach ($l in $old) { if (-not $newSet.Contains($l)) { $removed++ } }

        if ($added -eq 0 -and $removed -eq 0) {
            Say ("  {0,-22} без изменений ({1} записей)" -f $name, $new.Count) "DarkGray"
            continue
        }
        try {
            if (Test-Path $dest) {
                if (-not (Test-Path $backup)) { New-Item -ItemType Directory -Path $backup -Force | Out-Null }
                Copy-Item -LiteralPath $dest -Destination (Join-Path $backup $name) -Force
            }
            [IO.File]::WriteAllText($dest, (($new -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
            $updated++
            Say ("  {0,-22} обновлён: {1} записей (+{2}, -{3})" -f $name, $new.Count, $added, $removed) "Green"
        } catch {
            Say ("  {0,-22} не удалось записать: {1}" -f $name, $_.Exception.Message) "Red"
        }
    }
    Say ""
    if ($updated -gt 0) { Say ("Обновлено списков: {0}. Старые версии: {1}" -f $updated, $backup) "Green" }
    else { Say "Списки не изменились." "Gray" }
}
