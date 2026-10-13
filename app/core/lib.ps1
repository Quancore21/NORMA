# NORMA core: общие функции.
# Стратегии (zapret + NORMA + свои), запуск winws.exe, проверка сети, состояние, память по сетям, журналы.
# Загружается из app\norma.ps1 через dot-source, поэтому функции видны всему меню.

$script:root = $env:NORMA_DIR
if (-not $script:root) { $script:root = (Get-Location).Path }
$script:root = $script:root.TrimEnd('\')
$script:vendor = Join-Path $script:root "vendor\zapret"          # оригинальный zapret-discord-youtube (не менять)
$script:binDir = Join-Path $script:vendor "bin"
$script:listsDir = Join-Path $script:vendor "lists"
$script:dataDir = Join-Path $script:root "data"
$script:logDir = Join-Path $script:dataDir "logs"
$script:stratDir = Join-Path $script:root "strategies"
$script:statePath = Join-Path $script:dataDir "state.json"
$script:pidPath = Join-Path $script:dataDir "norma.pid"
$script:log = New-Object 'System.Collections.Generic.List[string]'
$script:winws = $null
$script:jobOk = $false
$script:version = "0.8"
try {
    $vf = Join-Path $script:root "VERSION"
    if (Test-Path $vf) { $vv = ([IO.File]::ReadAllText($vf)).Trim(); if ($vv) { $script:version = $vv } }
} catch {}

function Say([string]$Text, [string]$Color = "Gray") {
    Write-Host $Text -ForegroundColor $Color
    $script:log.Add($Text)
}

function Initialize-Dirs {
    foreach ($d in @($script:dataDir, $script:logDir, (Join-Path $script:stratDir "user"))) {
        if (-not (Test-Path $d)) { try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch {} }
    }
}

# Сохраняет журнал сеанса в data\logs (хранится 15 последних файлов каждого типа); возвращает путь
function Save-NormaLog([string]$Tag = "session") {
    try {
        Initialize-Dirs
        $name = "norma-{0}-{1}.log" -f $Tag, (Get-Date -Format "yyyyMMdd-HHmmss")
        $p = Join-Path $script:logDir $name
        [IO.File]::WriteAllLines($p, $script:log, (New-Object Text.UTF8Encoding($true)))
        $old = @(Get-ChildItem -LiteralPath $script:logDir -Filter ("norma-{0}-*.log" -f $Tag) -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -Skip 15)
        foreach ($o in $old) { Remove-Item -LiteralPath $o.FullName -Force -ErrorAction SilentlyContinue }
        return $p
    } catch { return "" }
}

# ---------- состояние: последняя рабочая стратегия, профиль проверки, стратегия для каждой сети
function Get-State {
    $st = $null
    try {
        if (Test-Path $script:statePath) {
            $st = [IO.File]::ReadAllText($script:statePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        }
    } catch { $st = $null }
    if (-not $st) { $st = [pscustomobject]@{ strategy = ""; profile = "youtube"; networks = @() } }
    if (-not $st.profile) { $st | Add-Member -NotePropertyName profile -NotePropertyValue "youtube" -Force }
    if (-not $st.strategy) { $st | Add-Member -NotePropertyName strategy -NotePropertyValue "" -Force }
    if (-not $st.networks) { $st | Add-Member -NotePropertyName networks -NotePropertyValue @() -Force }
    return $st
}

function Save-State($State) {
    try {
        Initialize-Dirs
        [IO.File]::WriteAllText($script:statePath, (ConvertTo-Json -InputObject $State -Depth 5), (New-Object Text.UTF8Encoding($false)))
    } catch {}
}

# Подпись текущей сети: имя подключения + шлюз. У дома, на работе и в кафе она разная.
function Get-NetworkSignature {
    try {
        $r = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1
        if (-not $r) { return "offline" }
        $name = ""
        try { $name = (Get-NetConnectionProfile -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop).Name } catch {}
        return ("{0}|{1}" -f $name, $r.NextHop)
    } catch { return "unknown" }
}

function Get-NetworkStrategy([string]$Sig) {
    $st = Get-State
    foreach ($n in @($st.networks)) {
        if ($n -and $n.sig -eq $Sig) { return [string]$n.strategy }
    }
    return ""
}

function Set-NetworkStrategy([string]$Sig, [string]$Name) {
    if (-not $Sig -or -not $Name) { return }
    $st = Get-State
    $list = @()
    foreach ($n in @($st.networks)) { if ($n -and $n.sig -ne $Sig) { $list += $n } }
    $list += [pscustomobject]@{ sig = $Sig; strategy = $Name }
    if ($list.Count -gt 30) { $list = @($list | Select-Object -Last 30) }
    $st | Add-Member -NotePropertyName networks -NotePropertyValue $list -Force
    Save-State $st
}

# ---------- защита: winws.exe завершается вместе с окном NORMA (Job Object с KILL_ON_JOB_CLOSE)
$jobSrc = @'
using System;
using System.Runtime.InteropServices;
namespace NormaCore
{
    public static class JobGuard
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
            public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct BASIC_LIMIT
        {
            public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct EXTENDED_LIMIT
        {
            public BASIC_LIMIT BasicLimitInformation; public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attrs, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        private static IntPtr job = IntPtr.Zero;

        // Returns null on success, otherwise a short error text.
        public static string Attach(IntPtr processHandle)
        {
            if (job == IntPtr.Zero)
            {
                job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) return "CreateJobObject " + Marshal.GetLastWin32Error();
                EXTENDED_LIMIT info = new EXTENDED_LIMIT();
                info.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                int size = Marshal.SizeOf(typeof(EXTENDED_LIMIT));
                IntPtr ptr = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(info, ptr, false);
                    if (!SetInformationJobObject(job, 9, ptr, (uint)size)) return "SetInformationJobObject " + Marshal.GetLastWin32Error();
                }
                finally { Marshal.FreeHGlobal(ptr); }
            }
            if (!AssignProcessToJobObject(job, processHandle)) return "AssignProcessToJobObject " + Marshal.GetLastWin32Error();
            return null;
        }
    }
}
'@

function Initialize-NormaCore {
    Initialize-Dirs
    if (-not ('NormaCore.JobGuard' -as [type])) {
        try { Add-Type -TypeDefinition $jobSrc -Language CSharp } catch { $script:jobOk = $false; return }
    }
    $script:jobOk = $true
}

# ---------- проверки окружения
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# upstream (service.bat :load_user_lists) создаёт пользовательские списки; winws без них не стартует
function Initialize-NormaFiles {
    $lists = $script:listsDir
    if (-not (Test-Path $lists)) { New-Item -ItemType Directory -Path $lists -Force | Out-Null }
    $f1 = Join-Path $lists "ipset-exclude-user.txt"
    if (-not (Test-Path $f1)) { [IO.File]::WriteAllText($f1, "203.0.113.113/32`r`n") }
    $f2 = Join-Path $lists "list-general-user.txt"
    if (-not (Test-Path $f2)) { [IO.File]::WriteAllText($f2, "# Never leave this file empty`r`ndomain.example.abc`r`n") }
    $f3 = Join-Path $lists "list-exclude-user.txt"
    if (-not (Test-Path $f3)) { [IO.File]::WriteAllText($f3, "domain.example.abc`r`n") }
}

# Возвращает $true, если можно запускаться. В тихом режиме (автозапуск) ничего не спрашивает и ничего чужого не останавливает.
function Resolve-Conflicts([switch]$Silent) {
    $running = @(Get-Process -Name "goodbyedpi", "winws" -ErrorAction SilentlyContinue)
    $svc = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
    $svcRun = $false
    if ($svc -and $svc.Status -eq "Running") { $svcRun = $true }
    if ($running.Count -eq 0 -and -not $svcRun) { return $true }
    $names = @($running | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
    if ($svcRun) { $names += "служба zapret" }
    Say ("Запущено: {0}. Это конфликтует с NORMA." -f ($names -join ", ")) "Yellow"
    foreach ($cl in @(Get-RunningCommandLines @("winws", "goodbyedpi"))) { Say ("  " + $cl) "DarkGray" }
    if ($Silent) { return $false }
    $a = Read-Host "Остановить? (д/н)"
    if ($a -notmatch "^[дДyY]") { Say "Тогда включить NORMA нельзя." "Red"; return $false }
    if ($svcRun) { & sc.exe stop zapret 2>&1 | Out-Null; Start-Sleep -Seconds 1 }
    Get-Process -Name "goodbyedpi", "winws" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    return $true
}

# ---------- стратегии
# Три источника:
#   zapret   vendor\zapret\general*.bat (одна команда start ... winws.exe с переносами через ^);
#   norma    strategies\norma\*.args (созданы tools\gen_strategies.py, тонкие стратегии только для YouTube);
#   user     strategies\user\*.args (ваши собственные).
# Формат .args описан в docs\STRATEGIES.md. Новые файлы подхватываются автоматически.

function New-Strategy([string]$Name, [string]$Source, [string]$Scope, [string]$Family, [string]$Desc, [string]$ArgsTpl, [string]$File) {
    return [pscustomobject]@{ Name = $Name; Source = $Source; Scope = $Scope; Family = $Family; Desc = $Desc; ArgsTpl = $ArgsTpl; File = $File }
}

function Read-ArgsFiles([string]$Dir, [string]$Source) {
    $res = @()
    if (-not (Test-Path $Dir)) { return $res }
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Filter "*.args" -File -ErrorAction SilentlyContinue)) {
        $meta = @{}
        $body = @()
        foreach ($l in [IO.File]::ReadAllLines($f.FullName, [Text.Encoding]::UTF8)) {
            $t = $l.Trim()
            if ($t -eq "") { continue }
            if ($t.StartsWith("#")) {
                $m = [regex]::Match($t, '^#\s*(name|scope|family|desc|from)\s*:\s*(.*)$')
                if ($m.Success) { $meta[$m.Groups[1].Value.ToLower()] = $m.Groups[2].Value.Trim() }
                continue
            }
            $body += $t
        }
        if ($body.Count -eq 0) { continue }
        $name = $f.BaseName
        if ($meta.ContainsKey("name") -and $meta["name"]) { $name = $meta["name"] }
        $scope = "full"
        if ($meta.ContainsKey("scope") -and $meta["scope"]) { $scope = $meta["scope"].ToLower() }
        $family = ""
        if ($meta.ContainsKey("family")) { $family = $meta["family"] }
        $desc = ""
        if ($meta.ContainsKey("desc")) { $desc = $meta["desc"] }
        $res += (New-Strategy $name $Source $scope $family $desc ($body -join " ") $f.Name)
    }
    return $res
}

function Read-ZapretBats {
    $res = @()
    $files = @(Get-ChildItem -LiteralPath $script:vendor -Filter "general*.bat" -File -ErrorAction SilentlyContinue)
    foreach ($f in $files) {
        $lines = [IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8) -split "\r?\n"
        $start = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i].TrimStart()
            if (($l -match '^start\s') -and ($l -match 'winws\.exe')) { $start = $i; break }
        }
        if ($start -lt 0) { continue }
        $buf = New-Object System.Collections.ArrayList
        for ($i = $start; $i -lt $lines.Count; $i++) {
            $l = $lines[$i].TrimEnd()
            if ($l.EndsWith("^")) { [void]$buf.Add($l.Substring(0, $l.Length - 1).Trim()) }
            else { [void]$buf.Add($l.Trim()); break }
        }
        $cmd = ($buf -join " ")
        $m = [regex]::Match($cmd, '"%BIN%winws\.exe"\s+(.*)$')
        if (-not $m.Success) { continue }
        # в .bat символ ^ экранирует следующий (например ^! это !); winws должен получить уже без ^
        $argText = [regex]::Replace($m.Groups[1].Value, '\^(.)', '$1')
        $res += (New-Strategy $f.BaseName "zapret" "full" "" "" $argText $f.Name)
    }
    return $res
}

function Get-Strategies {
    $res = @()
    $res += @(Read-ZapretBats)
    $res += @(Read-ArgsFiles (Join-Path $script:stratDir "norma") "norma")
    $res += @(Read-ArgsFiles (Join-Path $script:stratDir "user") "user")
    return $res
}

# Порядок перебора: свои (user), тонкие NORMA для YouTube (TCP, затем с QUIC), потом полные zapret
function Get-StrategyRank($S) {
    $num = 1
    if ($S.Name -match '(\d+)\D*$') { $num = [int]$Matches[1] }
    if ($S.Source -eq "user") { return $num }
    if ($S.Source -eq "norma") {
        if ($S.Family -eq "quic") { return 2000 + $num }
        return 1000 + $num
    }
    $tag = ""
    if ($S.Name -match '^general\s*\((.*)\)$') { $tag = $Matches[1] }
    $grp = 5
    if ($tag -eq "") { $grp = 0 }
    elseif ($tag -match '^ALT\d*$') { $grp = 1 }
    elseif ($tag -match '^FAKE TLS AUTO') { $grp = 2 }
    elseif ($tag -match '^SIMPLE FAKE') { $grp = 3 }
    elseif ($tag -eq 'EXP') { $grp = 4 }
    return 5000 + ($grp * 100) + $num
}

# Профиль youtube: все стратегии; профиль all (YouTube + Discord): только полные (тонкие не трогают Discord)
function Get-SortedStrategies([string]$Prof = "youtube") {
    $all = @(Get-Strategies)
    if ($Prof -eq "all") { $all = @($all | Where-Object { $_.Scope -ne "youtube" }) }
    return @($all | Sort-Object @{ Expression = { Get-StrategyRank $_ } }, Name)
}

# Игровой фильтр в NORMA выключен: порт 12 (как в upstream при disabled)
function Expand-Args([string]$Tpl, [string]$GameTcp = "12", [string]$GameUdp = "12") {
    $bin = $script:binDir + "\"
    $lists = $script:listsDir + "\"
    return $Tpl.Replace("%BIN%", $bin).Replace("%LISTS%", $lists).Replace("%GameFilterTCP%", $GameTcp).Replace("%GameFilterUDP%", $GameUdp)
}

# ---------- запуск и остановка winws
function Stop-Winws {
    Get-Process -Name "winws" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $script:winws = $null
    Start-Sleep -Milliseconds 400
}

function Start-Winws($Strategy) {
    Stop-Winws
    $exe = Join-Path $script:binDir "winws.exe"
    if (-not (Test-Path $exe)) { Say ("Не найден файл: " + $exe) "Red"; return $null }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (Expand-Args $Strategy.ArgsTpl)
    $psi.WorkingDirectory = $script:binDir
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = $null
    try { $p = [System.Diagnostics.Process]::Start($psi) }
    catch { Say ("  не удалось запустить winws.exe: " + $_.Exception.Message) "Red"; return $null }
    if ($script:jobOk) {
        try {
            $err = [NormaCore.JobGuard]::Attach($p.Handle)
            if ($err) { $script:jobOk = $false; Say ("  (winws не привязан к окну NORMA: $err; при закрытии окна выключайте NORMA клавишей)") "DarkGray" }
        } catch { $script:jobOk = $false }
    }
    $script:winws = $p
    return $p
}

# ---------- проверка доступности сайтов (curl.exe есть в Windows 10 1803+)
# Цели: vendor\zapret\utils\targets.txt плюс ваши в data\targets.user.txt (тот же формат: Имя = "https://адрес")
function Get-Targets([string]$Prof = "youtube") {
    $res = @()
    foreach ($p in @((Join-Path $script:vendor "utils\targets.txt"), (Join-Path $script:dataDir "targets.user.txt"))) {
        if (-not (Test-Path $p)) { continue }
        foreach ($l in [IO.File]::ReadAllLines($p, [Text.Encoding]::UTF8)) {
            $m = [regex]::Match($l, '^\s*([A-Za-z0-9_]+)\s*=\s*"(https://[^"]+)"')
            if ($m.Success) { $res += [pscustomobject]@{ Key = $m.Groups[1].Value; Url = $m.Groups[2].Value } }
        }
    }
    if ($res.Count -eq 0) {
        $res = @(
            [pscustomobject]@{ Key = "YouTubeWeb"; Url = "https://www.youtube.com" },
            [pscustomobject]@{ Key = "YouTubeImage"; Url = "https://i.ytimg.com" },
            [pscustomobject]@{ Key = "YouTubeVideoRedirect"; Url = "https://redirector.googlevideo.com" },
            [pscustomobject]@{ Key = "GoogleMain"; Url = "https://www.google.com" },
            [pscustomobject]@{ Key = "CloudflareWeb"; Url = "https://www.cloudflare.com" }
        )
    }
    if ($Prof -eq "youtube") { $res = @($res | Where-Object { $_.Key -match '^(YouTube|Google|Cloudflare)' }) }
    return $res
}

# Параллельно открывает адреса; возвращает hashtable: адрес -> { Ok; Time (сек); Speed (байт/с) }
function Test-UrlsDetailed([string[]]$Urls, [int]$TimeoutSec = 6) {
    $res = @{}
    $procs = @{}
    foreach ($u in $Urls) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "curl.exe"
            $psi.Arguments = ('-s -o NUL -w "%{{http_code}} %{{time_total}} %{{speed_download}}" --ssl-no-revoke --connect-timeout {0} --max-time {1} "{2}"' -f $TimeoutSec, ($TimeoutSec + 4), $u)
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $procs[$u] = [System.Diagnostics.Process]::Start($psi)
        } catch { $res[$u] = [pscustomobject]@{ Ok = $false; Time = 99.0; Speed = 0.0 } }
    }
    foreach ($u in @($procs.Keys)) {
        $p = $procs[$u]
        $out = ""
        try {
            if ($p.WaitForExit(($TimeoutSec + 8) * 1000)) { $out = $p.StandardOutput.ReadToEnd().Trim() }
            else { try { $p.Kill() } catch {} }
        } catch {}
        $parts = @($out -split '\s+')
        $ok = $false
        $tm = 99.0
        $sp = 0.0
        if ($parts.Count -ge 1 -and $parts[0] -match '^[1-5]\d\d$') {
            $ok = $true
            if ($parts.Count -ge 3) {
                $v = 0.0
                if ([double]::TryParse($parts[1], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$v)) { $tm = $v }
                if ([double]::TryParse($parts[2], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$v)) { $sp = $v }
            }
        }
        $res[$u] = [pscustomobject]@{ Ok = $ok; Time = $tm; Speed = $sp }
    }
    return $res
}

# Упрощённый вариант: адрес -> $true/$false
function Test-Urls([string[]]$Urls, [int]$TimeoutSec = 6) {
    $d = Test-UrlsDetailed $Urls $TimeoutSec
    $res = @{}
    foreach ($k in @($d.Keys)) { $res[$k] = [bool]$d[$k].Ok }
    return $res
}

# ---------- вспомогательные функции подбора
# Параметры запуска уже работающих winws/goodbyedpi (если у человека всё открывается, это готовый рецепт)
function Get-RunningCommandLines([string[]]$Names) {
    $res = @()
    foreach ($n in $Names) {
        try {
            foreach ($ci in @(Get-CimInstance -ClassName Win32_Process -Filter ("Name = '{0}.exe'" -f $n) -ErrorAction Stop)) {
                $res += ("{0}: {1}" -f $ci.Name, $ci.CommandLine)
            }
        } catch {}
    }
    return $res
}

function Get-Median([double[]]$Values) {
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return 0.0 }
    $mid = [int][math]::Floor($v.Count / 2)
    if ($v.Count % 2 -eq 1) { return [double]$v[$mid] }
    return ([double]$v[$mid - 1] + [double]$v[$mid]) / 2.0
}

# Упорядочивает результаты бенчмарка (строки: Index, Ok, Harm, Avg) от лучшей к худшей.
# 1) больше открытых сайтов лучше; ломающие остальное и нулевые отбрасываются;
# 2) среди равных по открытым сайтам меньше время ответа лучше;
# 3) результаты в пределах допуска Tol (по умолчанию 15% и 0,03 с) считаются равными и идут в порядке перебора (Index):
#    разница в доли секунды между запусками это шум, а не преимущество.
function Sort-StrategyRows($Rows, [double]$Tol = 0.15) {
    $left = @($Rows | Where-Object { (-not $_.Harm) -and $_.Ok -gt 0 })
    $out = @()
    while ($left.Count -gt 0) {
        $maxOk = ($left | Measure-Object -Property Ok -Maximum).Maximum
        $lvl = @($left | Where-Object { $_.Ok -eq $maxOk })
        $sorted = @($lvl | Sort-Object Avg, Index)
        $best = [double]$sorted[0].Avg
        $grp = @($sorted | Where-Object { [double]$_.Avg -le $best * (1 + $Tol) + 0.03 } | Sort-Object Index)
        $out += $grp
        $taken = @($grp | ForEach-Object { $_.Index })
        $left = @($left | Where-Object { $taken -notcontains $_.Index })
    }
    return $out
}
