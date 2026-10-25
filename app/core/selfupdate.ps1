# NORMA: обновление самой программы и плановое обслуживание (списки, версии).
#
# Принципы безопасности (обновление выполняется только если проходит ВСЕ шаги, иначе установленная версия не меняется):
#   1. Берётся только последний стабильный релиз из github.com/Quancore21/NORMA, номер версии должен быть выше установленного.
#   2. Скачанный архив сверяется с контрольной суммой SHA-256 из того же релиза (файл NORMA-ВЕРСИЯ.zip.sha256). Нет суммы: автоустановки нет.
#   3. Архив распаковывается во временную папку с защитой от выхода за её пределы; структура, номер версии и контрольные суммы
#      файлов bin внутри архива проверяются.
#   4. Самопроверка (tools\selftest.ps1) запускается из новой версии на этом компьютере. Не прошла: установка отменяется.
#   5. Работающий обход останавливается, драйвер WinDivert выгружается (иначе его файл занят), затем папки заменяются
#      переименованием: старые уходят в data\backup\selfupdate-..., новые встают на место. Любой сбой: откат и проверка отката.
#   6. Ваши данные не затрагиваются: data, strategies\user, пользовательские списки (*-user.txt), режим IPSet.

$script:normaApi = "https://api.github.com/repos/Quancore21/NORMA/releases/latest"

# ---------- вспомогательные функции
function Test-UpdateDue([string]$Stamp, [int]$Hours) {
    if (-not $Stamp) { return $true }
    $dt = [datetime]::MinValue
    if (-not [datetime]::TryParse($Stamp, [ref]$dt)) { return $true }
    $now = Get-Date
    if ($dt -gt $now.AddDays(1)) { return $true }          # отметка из будущего (сбились часы): проверяем сразу
    return (($now - $dt).TotalHours -ge $Hours)
}

# Первое 64-символьное шестнадцатеричное значение из текста файла «hex  имя»
function Get-Sha256FromText([string]$Text) {
    $m = [regex]::Match($Text, '(?i)\b([0-9a-f]{64})\b')
    if ($m.Success) { return $m.Groups[1].Value.ToUpper() }
    return ""
}

# Отметка времени в состоянии. AgeHours делает отметку «старше», чтобы повторная проверка наступила раньше (например, через 2 часа после неудачи)
function Set-StateStamp([string]$Field, [int]$AgeHours = 0) {
    $st = Get-State
    $when = (Get-Date).AddHours(-1 * $AgeHours)
    $st | Add-Member -NotePropertyName $Field -NotePropertyValue ($when.ToString("yyyy-MM-dd HH:mm:ss")) -Force
    Save-State $st
}

# Что мешает обновлению: другие работающие экземпляры NORMA (в том числе фоновый или окно, если обновляется другой) и чужие winws.
# Свой процесс не считается, чужие не затрагиваются.
function Get-UpdateBlockers {
    $res = @()
    foreach ($o in @(Get-OtherNormaInstances)) { $res += ("другой экземпляр NORMA (процесс {0})" -f $o) }
    $foreign = @(Get-ForeignDpiProcesses)
    if ($foreign.Count -gt 0) { $res += ("работает {0}, запущенный не NORMA" -f (($foreign | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ", ")) }
    return $res
}

function Invoke-GitHubDownload([string]$Url, [string]$OutFile) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 600 -Headers @{ "User-Agent" = "NORMA" }
}

# ---------- последний релиз
# Возвращает { Version; Tag; ZipUrl; ShaUrl; ZipName; HasSha } или $null (причина записана в журнал)
function Get-LatestRelease([int]$TimeoutSec = 30) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = "SilentlyContinue"
        $r = Invoke-RestMethod -Uri $script:normaApi -TimeoutSec $TimeoutSec -Headers @{ "User-Agent" = "NORMA"; "Accept" = "application/vnd.github+json" }
    } catch {
        Say ("Не удалось получить сведения о релизе: " + $_.Exception.Message) "Yellow"
        return $null
    }
    $tag = [string]$r.tag_name
    $ver = $tag.TrimStart("v", "V")
    if ($ver -notmatch '^\d+(\.\d+)+$') { Say ("Номер версии релиза не распознан: " + $tag) "Yellow"; return $null }
    $zipName = "NORMA-{0}.zip" -f $ver
    $zip = @($r.assets | Where-Object { $_.name -eq $zipName } | Select-Object -First 1)
    $sha = @($r.assets | Where-Object { $_.name -eq ($zipName + ".sha256") } | Select-Object -First 1)
    $res = [pscustomobject]@{ Version = $ver; Tag = $tag; ZipName = $zipName; ZipUrl = ""; ShaUrl = ""; HasSha = $false; HasZip = $false }
    if ($zip.Count -eq 1) { $res.ZipUrl = [string]$zip[0].browser_download_url; $res.HasZip = $true }
    if ($sha.Count -eq 1) { $res.ShaUrl = [string]$sha[0].browser_download_url; $res.HasSha = $true }
    return $res
}

# Проверка наличия обновления: { Available; Release }
function Get-NormaUpdateInfo([int]$TimeoutSec = 30) {
    $rel = Get-LatestRelease $TimeoutSec
    $info = [pscustomobject]@{ Available = $false; Release = $rel }
    if (-not $rel) { return $info }
    try { $info.Available = ([version]$rel.Version -gt [version]$script:version) } catch { $info.Available = $false }
    return $info
}

# ---------- проверка пакета
# Распаковывает zip с защитой от выхода за пределы папки (имена с .. или абсолютные пути отвергаются)
function Expand-ZipSafe([string]$Zip, [string]$Dest) {
    $ErrorActionPreference = "Stop"             # любая ошибка здесь должна прерывать распаковку, а не оставаться незамеченной
    # в Windows PowerShell 5.1 сборки не подгружаются сами: ZipArchiveMode лежит в System.IO.Compression, ZipFile в System.IO.Compression.FileSystem
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destFull = [IO.Path]::GetFullPath($Dest).TrimEnd('\') + '\'
    $archive = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        foreach ($e in $archive.Entries) {
            $name = $e.FullName.Replace('/', '\')
            if ($name -match '(^|\\)\.\.(\\|$)' -or $name -match '^[A-Za-z]:' -or $name.StartsWith('\')) { throw ("недопустимое имя в архиве: " + $e.FullName) }
            $target = [IO.Path]::GetFullPath((Join-Path $Dest $name))
            if (-not $target.StartsWith($destFull, [StringComparison]::OrdinalIgnoreCase)) { throw ("имя в архиве выходит за пределы папки: " + $e.FullName) }
            if ($name.EndsWith('\') -or $e.Name -eq "") {
                if (-not (Test-Path -LiteralPath $target)) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
                continue
            }
            $dir = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $true)
        }
    } finally { $archive.Dispose() }
}

# Корень пакета: папка, в которой лежит VERSION (сам каталог распаковки или единственная вложенная папка)
function Get-PackageRoot([string]$Dir) {
    if (Test-Path -LiteralPath (Join-Path $Dir "VERSION")) { return $Dir }
    foreach ($d in @(Get-ChildItem -LiteralPath $Dir -Directory -ErrorAction SilentlyContinue)) {
        if (Test-Path -LiteralPath (Join-Path $d.FullName "VERSION")) { return $d.FullName }
    }
    return ""
}

# Сверяет файлы vendor\zapret\bin пакета с манифестом внутри пакета; возвращает список расхождений
function Get-BinMismatches([string]$PkgRoot) {
    $bad = @()
    $man = Join-Path $PkgRoot "app\core\checksums.txt"
    if (-not (Test-Path -LiteralPath $man)) { return @("нет app\core\checksums.txt") }
    $entries = 0
    foreach ($l in [IO.File]::ReadAllLines($man, [Text.Encoding]::UTF8)) {
        $m = [regex]::Match($l.Trim(), '^([0-9A-Fa-f]{64})\s+(\S.*)$')
        if (-not $m.Success) { continue }
        $entries++
        $f = Join-Path $PkgRoot ("vendor\zapret\bin\" + $m.Groups[2].Value.Trim())
        if (-not (Test-Path -LiteralPath $f)) { $bad += $m.Groups[2].Value.Trim(); continue }
        if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne $m.Groups[1].Value.ToUpper()) { $bad += $m.Groups[2].Value.Trim() }
    }
    if ($entries -lt 4) { $bad += "манифест слишком короткий" }
    return $bad
}

# Проверяет структуру пакета; возвращает текст ошибки или $null
function Test-PackageTree([string]$PkgRoot, [string]$ExpectedVersion) {
    $required = @("VERSION", "NORMA.bat", "app\norma.ps1", "app\background.ps1", "app\core\lib.ps1", "app\core\checksums.txt",
        "tools\selftest.ps1", "vendor\zapret\bin\winws.exe", "vendor\zapret\bin\WinDivert64.sys")
    foreach ($r in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $PkgRoot $r))) { return ("в пакете нет файла " + $r) }
    }
    $v = ([IO.File]::ReadAllText((Join-Path $PkgRoot "VERSION"))).Trim()
    if ($v -notmatch '^\d+(\.\d+)+$') { return ("в пакете некорректный номер версии: " + $v) }
    if ($v -ne $ExpectedVersion) { return ("версия в пакете ({0}) не совпадает с версией релиза ({1})" -f $v, $ExpectedVersion) }
    $bad = @(Get-BinMismatches $PkgRoot)
    if ($bad.Count -gt 0) { return ("контрольные суммы файлов bin в пакете не совпали: " + ($bad -join ", ")) }
    return $null
}

# Запускает самопроверку из пакета отдельным процессом; true, если она прошла
function Invoke-PackageSelftest([string]$PkgRoot) {
    $script = Join-Path $PkgRoot "tools\selftest.ps1"
    $out = Join-Path $script:dataDir ("tmp\selftest-" + [Guid]::NewGuid().ToString("N").Substring(0, 8) + ".txt")
    try {
        $p = Start-Process -FilePath "powershell.exe" -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $script) `
            -WorkingDirectory $PkgRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $out
        $null = $p.Handle                       # без этого ExitCode после WaitForExit может быть пустым
        if (-not $p.WaitForExit(300000)) { try { $p.Kill() } catch {}; Say "Самопроверка нового релиза не уложилась в 5 минут." "Red"; return $false }
        $code = $p.ExitCode
        if ($code -ne 0) {
            Say ("Самопроверка нового релиза не прошла (код {0})." -f $code) "Red"
            try { foreach ($l in @([IO.File]::ReadAllLines($out) | Select-Object -Last 12)) { Say ("  " + $l) "DarkGray" } } catch {}
            return $false
        }
        return $true
    } catch {
        Say ("Не удалось запустить самопроверку: " + $_.Exception.Message) "Red"
        return $false
    } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
}

# ---------- замена файлов
function Move-WithRetry([string]$From, [string]$To) {
    for ($i = 1; $i -le 4; $i++) {
        try { Move-Item -LiteralPath $From -Destination $To -ErrorAction Stop; return } catch {
            if ($i -eq 4) { throw }
            Start-Sleep -Milliseconds 600
        }
    }
}

# Отменяет замену: возвращает старые элементы на место; возвращает список элементов, которые восстановить не удалось
function Undo-TreeSwap($Done) {
    $failed = @()
    $recs = @($Done)
    for ($k = $recs.Count - 1; $k -ge 0; $k--) {
        $r = $recs[$k]
        try {
            if ($r.Placed) { Move-WithRetry $r.Dest $r.Src }
            if ($r.Moved) { Move-WithRetry $r.Bk $r.Dest }
        } catch { $failed += $r.Rel }
    }
    return $failed
}

# Заменяет элементы установленной папки элементами нового пакета переименованием. Старые уходят в Backup.
# Список элементов: все верхние элементы пакета, кроме data, служебных файлов git и strategies; вместо strategies заменяется strategies\norma.
# SkipBat: не трогать NORMA.bat (его читает работающий cmd; обновится при следующем обновлении из фонового режима).
# Результат: { Ok; Error; Rollback = none | ok | failed; Done (записи для Undo-TreeSwap) }
function Invoke-TreeSwap([string]$NewRoot, [string]$Root, [string]$Backup, [bool]$SkipBat) {
    $items = @()
    foreach ($i in @(Get-ChildItem -LiteralPath $NewRoot -Force)) {
        $n = $i.Name
        if ($n -eq "data" -or $n -like ".git*") { continue }
        if ($n -eq "NORMA.bat" -and $SkipBat) { continue }
        if ($n -eq "strategies") { $items += "strategies\norma"; continue }
        $items += $n
    }
    $done = @()
    try {
        New-Item -ItemType Directory -Path $Backup -Force -ErrorAction Stop | Out-Null
        foreach ($rel in $items) {
            $src = Join-Path $NewRoot $rel
            if (-not (Test-Path -LiteralPath $src)) { continue }
            $dest = Join-Path $Root $rel
            $bk = Join-Path $Backup $rel
            $rec = [pscustomobject]@{ Rel = $rel; Src = $src; Dest = $dest; Bk = $bk; Moved = $false; Placed = $false }
            $done += $rec
            if (Test-Path -LiteralPath $dest) {
                $bkParent = Split-Path -Parent $bk
                if (-not (Test-Path -LiteralPath $bkParent)) { New-Item -ItemType Directory -Path $bkParent -Force -ErrorAction Stop | Out-Null }
                Move-WithRetry $dest $bk
                $rec.Moved = $true
            } else {
                $dp = Split-Path -Parent $dest
                if (-not (Test-Path -LiteralPath $dp)) { New-Item -ItemType Directory -Path $dp -Force -ErrorAction Stop | Out-Null }
            }
            Move-WithRetry $src $dest
            $rec.Placed = $true
        }
        return [pscustomobject]@{ Ok = $true; Error = ""; Rollback = "none"; Done = $done }
    } catch {
        $why = $_.Exception.Message
        $failed = @(Undo-TreeSwap $done)
        if ($failed.Count -gt 0) {
            return [pscustomobject]@{ Ok = $false; Error = ("замена файлов не удалась ({0}); ВОССТАНОВИТЬ НЕ УДАЛОСЬ: {1}. Прежние файлы лежат в {2}" -f $why, ($failed -join ", "), $Backup); Rollback = "failed"; Done = @() }
        }
        $rb = "none"
        if ($done.Count -gt 0) { $rb = "ok" }
        return [pscustomobject]@{ Ok = $false; Error = ("замена файлов не удалась ({0}); прежняя версия восстановлена" -f $why); Rollback = $rb; Done = @() }
    }
}

# Копирует в новый пакет то, что принадлежит пользователю: пользовательские списки и сохранённый режим IPSet
function Copy-UserDataToPackage([string]$Root, [string]$NewRoot) {
    $oldLists = Join-Path $Root "vendor\zapret\lists"
    $newLists = Join-Path $NewRoot "vendor\zapret\lists"
    if (-not (Test-Path -LiteralPath $oldLists)) { return }
    if (-not (Test-Path -LiteralPath $newLists)) { New-Item -ItemType Directory -Path $newLists -Force | Out-Null }
    $names = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $oldLists -File -Filter "*-user.txt" -ErrorAction SilentlyContinue)) { $names += $f.Name }
    $names += @("ipset-all.txt", "ipset-all.txt.backup")
    foreach ($n in $names) {
        $s = Join-Path $oldLists $n
        if (Test-Path -LiteralPath $s) { Copy-Item -LiteralPath $s -Destination (Join-Path $newLists $n) -Force -ErrorAction Stop }
    }
}

# Выгружает службу драйвера WinDivert (без этого файл драйвера занят и папку vendor не заменить)
function Remove-WinDivertService {
    & sc.exe stop WinDivert 2>&1 | Out-Null
    & sc.exe delete WinDivert 2>&1 | Out-Null
}

# ---------- установка обновления
# Возвращает { Ok; Error; Version; Rollback }
# Установка выполняется под замком движка: пока он у нас, другой экземпляр не может начать работу с движком и драйвером (ни окно, ни фон).
# В фоновом режиме замок уже удерживается сеансом и просто берётся повторно.
function Install-NormaUpdate([switch]$Background) {
    if (-not (Enter-EngineLease 0)) {
        $holders = @(Get-OtherNormaInstances)
        $who = ""
        if ($holders.Count -gt 0) { $who = (" (процесс {0})" -f ($holders -join ", ")) }
        return [pscustomobject]@{ Ok = $false; Error = ("обход сейчас занят другим экземпляром NORMA{0}: обновление отложено; остановите его (фоновый режим останавливается в меню «Фоновый режим») и повторите" -f $who); Version = ""; Rollback = "none" }
    }
    try { return (Install-NormaUpdateLocked -Background:$Background) }
    finally { Exit-EngineLease }
}

function Install-NormaUpdateLocked([switch]$Background) {
    $fail = { param($msg) return [pscustomobject]@{ Ok = $false; Error = $msg; Version = ""; Rollback = "none" } }
    if (-not (Test-EngineLeaseHeld)) { return (& $fail "замок движка не удерживается") }
    if (-not (Test-Admin)) { return (& $fail "нужны права администратора") }

    # условия: никто другой не должен пользоваться обходом и драйвером (проверяется и в фоновом режиме: свой процесс не считается)
    $blockers = @(Get-UpdateBlockers)
    if ($blockers.Count -gt 0) {
        return (& $fail ("обновление отложено: " + ($blockers -join "; ") + ". Чужие процессы не затрагиваются; закройте их (фоновый режим останавливается в меню «Фоновый режим») и повторите"))
    }

    Say "Проверяю последний релиз..." "Cyan"
    $info = Get-NormaUpdateInfo
    if (-not $info.Release) { return (& $fail "не удалось получить сведения о релизе") }
    if (-not $info.Available) { Say ("Установлена последняя версия: {0}." -f $script:version) "Green"; return [pscustomobject]@{ Ok = $true; Error = ""; Version = ""; Rollback = "none" } }
    $rel = $info.Release
    if (-not $rel.HasZip) { return (& $fail ("в релизе {0} нет архива {1}" -f $rel.Tag, $rel.ZipName)) }
    if (-not $rel.HasSha) { return (& $fail ("в релизе {0} нет файла контрольной суммы: автоустановка невозможна, скачайте архив вручную" -f $rel.Tag)) }

    $stamp = (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 6)
    $stage = Join-Path $script:dataDir ("tmp\selfupdate-" + $stamp)
    $backup = Join-Path $script:dataDir ("backup\selfupdate-" + $script:version + "-" + $stamp)
    try {
        New-Item -ItemType Directory -Path $stage -Force -ErrorAction Stop | Out-Null
        $zip = Join-Path $stage $rel.ZipName
        $shaFile = Join-Path $stage ($rel.ZipName + ".sha256")

        Say ("Найдена версия {0} (установлена {1}). Скачиваю..." -f $rel.Version, $script:version) "Cyan"
        Invoke-GitHubDownload $rel.ShaUrl $shaFile
        Invoke-GitHubDownload $rel.ZipUrl $zip
        $want = Get-Sha256FromText ([IO.File]::ReadAllText($shaFile))
        if (-not $want) { return (& $fail "в файле контрольной суммы нет значения SHA-256") }
        $got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        if ($got -ne $want) { return (& $fail "контрольная сумма архива не совпала: файл повреждён или подменён, обновление отменено") }
        Say "Контрольная сумма архива совпала." "Green"

        $extract = Join-Path $stage "x"
        New-Item -ItemType Directory -Path $extract -Force -ErrorAction Stop | Out-Null
        Expand-ZipSafe $zip $extract
        $pkg = Get-PackageRoot $extract
        if (-not $pkg) { return (& $fail "в архиве не найден корень пакета (файл VERSION)") }
        $err = Test-PackageTree $pkg $rel.Version
        if ($err) { return (& $fail $err) }
        Say "Структура пакета и контрольные суммы файлов проверены." "Green"

        Say "Запускаю самопроверку новой версии на этом компьютере..." "Cyan"
        if (-not (Invoke-PackageSelftest $pkg)) { return (& $fail "самопроверка новой версии не прошла, установка отменена") }
        Say "Самопроверка новой версии прошла." "Green"

        # перепроверка непосредственно перед остановкой движка и выгрузкой драйвера: замок движка у нас в руках, поэтому состояние уже не изменится
        $again = @(Get-UpdateBlockers)
        if ($again.Count -gt 0) { return (& $fail ("перед остановкой обхода обнаружено: " + ($again -join "; ") + "; обновление отменено, файлы не менялись")) }
        if (-not (Test-EngineLeaseHeld)) { return (& $fail "замок движка потерян: обновление отменено") }

        # остановить обход и освободить драйвер
        Say "Останавливаю обход и выгружаю драйвер..." "Cyan"
        Stop-Winws
        Restore-TcpTimestamps
        Remove-WinDivertService
        Start-Sleep -Milliseconds 800

        Copy-UserDataToPackage $script:root $pkg
        $skipBat = [bool]$env:NORMA_SELF
        $swap = Invoke-TreeSwap $pkg $script:root $backup $skipBat
        if (-not $swap.Ok) { return [pscustomobject]@{ Ok = $false; Error = $swap.Error; Version = ""; Rollback = $swap.Rollback } }

        # проверка результата
        $newV = ""
        try { $newV = ([IO.File]::ReadAllText((Join-Path $script:root "VERSION"))).Trim() } catch {}
        $binBad = @(Get-BinMismatches $script:root)
        if ($newV -ne $rel.Version -or $binBad.Count -gt 0) {
            Say "После замены проверка не прошла, возвращаю прежнюю версию..." "Red"
            $undo = @(Undo-TreeSwap $swap.Done)
            $why = ("после замены проверка не прошла (версия {0}, расхождений bin: {1})" -f $newV, $binBad.Count)
            if ($undo.Count -gt 0) {
                return [pscustomobject]@{ Ok = $false; Error = ("{0}; ВОССТАНОВИТЬ НЕ УДАЛОСЬ: {1}. Прежние файлы лежат в {2}" -f $why, ($undo -join ", "), $backup); Version = ""; Rollback = "failed" }
            }
            return [pscustomobject]@{ Ok = $false; Error = ($why + "; прежняя версия восстановлена"); Version = ""; Rollback = "ok" }
        }
        Set-StateStamp "lastNormaUpdate"
        $st = Get-State
        $st | Add-Member -NotePropertyName updateAvailable -NotePropertyValue "" -Force
        Save-State $st
        Say ("NORMA обновлена до версии {0}. Прежние файлы: {1}" -f $rel.Version, $backup) "Green"
        return [pscustomobject]@{ Ok = $true; Error = ""; Version = $rel.Version; Rollback = "none" }
    } catch {
        return (& $fail ("обновление прервано: " + $_.Exception.Message))
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Показывает результат установки
function Show-UpdateOutcome($R) {
    if ($R.Ok) { return }
    if ($R.Rollback -eq "failed") { Say ("ВНИМАНИЕ: обновление не выполнено, и откат не удался. " + $R.Error) "Red" }
    else { Say ("Обновление не выполнено: " + $R.Error + ". Установленная версия не изменена.") "Yellow" }
}

# ---------- пункты меню
# Проверка и (по желанию) установка. Возвращает $true, если NORMA обновлена и окно нужно перезапустить.
function Show-NormaUpdate {
    Say ("Версия NORMA: {0}" -f $script:version) "Gray"
    $info = Get-NormaUpdateInfo
    if (-not $info.Release) { return $false }
    Set-StateStamp "lastNormaCheck"
    Say ("Последний релиз на GitHub: {0}" -f $info.Release.Version) "Gray"
    if (-not $info.Available) { Say "У вас актуальная версия NORMA." "Green"; return $false }
    $st = Get-State
    $st | Add-Member -NotePropertyName updateAvailable -NotePropertyValue $info.Release.Version -Force
    Save-State $st
    Say "Вышла новая версия NORMA." "Yellow"
    if (-not $info.Release.HasSha) {
        Say "У этого релиза нет контрольной суммы, автоустановка недоступна: скачайте архив вручную." "Yellow"
        $a = Read-Host "Открыть страницу загрузки? (д/н)"
        if ($a -match '^[дДyY]') { try { Start-Process "https://github.com/Quancore21/NORMA/releases/latest" } catch {} }
        return $false
    }
    $a = Read-Host "Установить сейчас? (д/н)"
    if ($a -notmatch '^[дДyY]') { return $false }
    $r = Install-NormaUpdate
    Show-UpdateOutcome $r
    if ($r.Ok -and $r.Version) {
        Say "Закройте это окно и запустите NORMA.bat заново, чтобы работать с новой версией." "Green"
        return $true
    }
    return $false
}

# Проверка при запуске меню: не чаще, чем раз в updateCheckHours. Возвращает $true, если NORMA обновлена и окно нужно закрыть.
function Invoke-StartupUpdateCheck {
    $s = Get-Settings
    if ($s.autoUpdateNorma -eq "off") { return $false }
    $st = Get-State
    if (-not (Test-UpdateDue ([string]$st.lastNormaCheck) $s.updateCheckHours)) { return $false }
    $info = Get-NormaUpdateInfo 8
    Set-StateStamp "lastNormaCheck"
    $st = Get-State
    if ($info.Available) {
        $st | Add-Member -NotePropertyName updateAvailable -NotePropertyValue $info.Release.Version -Force
        Save-State $st
        if ($s.autoUpdateNorma -eq "auto" -and $info.Release.HasSha) {
            Write-Host ("Вышла новая версия NORMA: {0} (установлена {1})." -f $info.Release.Version, $script:version) -ForegroundColor Yellow
            $a = Read-Host "Установить сейчас? (д/н)"
            if ($a -match '^[дДyY]') {
                $r = Install-NormaUpdate
                Show-UpdateOutcome $r
                if ($r.Ok -and $r.Version) {
                    Write-Host "Закройте это окно и запустите NORMA.bat заново, чтобы работать с новой версией." -ForegroundColor Green
                    return $true
                }
            }
        }
    } elseif ($info.Release) {
        $st | Add-Member -NotePropertyName updateAvailable -NotePropertyValue "" -Force
        Save-State $st
    }
    return $false
}

# ---------- плановое обслуживание фонового режима
# Возвращает: none | restart-engine (списки обновились, обход нужно перезапустить) | update (NORMA обновлена, нужен перезапуск процесса)
function Invoke-BackgroundMaintenance([string]$StrategyName) {
    $s = Get-Settings
    $result = "none"

    if ($s.autoUpdateLists) {
        $st = Get-State
        if (Test-UpdateDue ([string]$st.lastListsUpdate) $s.updateCheckHours) {
            Say "Плановое обновление списков..." "Cyan"
            $changed = $false
            $r1 = Update-Lists
            if ($r1 -and $r1.Ok -and (@($r1.Details | Where-Object { $_.Status -eq "changed" }).Count -gt 0)) { $changed = $true }
            if ((Get-IpsetMode) -eq "loaded") {
                $r2 = Update-Ipset
                if ($r2 -and $r2.Ok -and (@($r2.Details | Where-Object { $_.Status -eq "changed" }).Count -gt 0)) { $changed = $true }
            }
            if ($r1 -and $r1.Ok) { Set-StateStamp "lastListsUpdate" }
            if ($changed) { $result = "restart-engine" }
        }
    }

    if ($s.autoUpdateNorma -ne "off") {
        $st = Get-State
        if (Test-UpdateDue ([string]$st.lastNormaCheck) $s.updateCheckHours) {
            $info = Get-NormaUpdateInfo
            if ($info.Release) { Set-StateStamp "lastNormaCheck" }
            if ($info.Available) {
                $st = Get-State
                $st | Add-Member -NotePropertyName updateAvailable -NotePropertyValue $info.Release.Version -Force
                Save-State $st
                if ($s.autoUpdateNorma -eq "auto") {
                    Say ("Найдена новая версия NORMA {0}: устанавливаю." -f $info.Release.Version) "Cyan"
                    $r = Install-NormaUpdate -Background
                    Show-UpdateOutcome $r
                    if ($r.Ok -and $r.Version) { return "update" }
                    $result = "restart-engine"          # установщик мог остановить обход: вернуть его
                    Set-StateStamp "lastNormaCheck" ([math]::Max(0, $s.updateCheckHours - 2))     # повторить через 2 часа, а не через сутки
                } else {
                    Say ("Доступна новая версия NORMA {0}. Автоустановка выключена в настройках." -f $info.Release.Version) "Yellow"
                }
            }
        }
    }
    return $result
}
