# NORMA (Node for Obfuscated Routing and Masked Access) - шаг 0: замер сети.
# Выясняет, КАК именно ваш провайдер ограничивает YouTube и Telegram: DNS, IP, SNI, троттлинг.
# Ничего не меняет в системе, права администратора не нужны.
# Результат сохраняется в norma-report.txt и копируется в буфер обмена.
param(
    [switch]$NoPrompt
)

$ProgressPreference = "SilentlyContinue"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$script:root = $env:NORMA_DIR
if (-not $script:root) { $script:root = $PSScriptRoot }
if (-not $script:root) { $script:root = (Get-Location).Path }
$script:report = New-Object 'System.Collections.Generic.List[string]'
$script:verdicts = New-Object 'System.Collections.Generic.List[string]'
$script:dohCache = @{}
$script:neutral = $null
$script:neutralChecked = $false
$script:ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

function Say([string]$Text, [string]$Color = "Gray") {
    Write-Host $Text -ForegroundColor $Color
    $script:report.Add($Text)
}
function Head([string]$Text) { Say ""; Say "== $Text ==" "Cyan" }
function Add-Verdict([string]$Text) { [void]$script:verdicts.Add($Text) }

# ---------------------------------------------------------------- DNS
function Get-SysIps([string]$Name) {
    try {
        return @([System.Net.Dns]::GetHostAddresses($Name) |
            Where-Object { $_.AddressFamily -eq "InterNetwork" } |
            ForEach-Object { $_.ToString() })
    } catch { return @() }
}

function Get-DohIps([string]$Name) {
    if ($script:dohCache.ContainsKey($Name)) { return $script:dohCache[$Name] }
    $ips = @()
    $urls = @(
        "https://cloudflare-dns.com/dns-query?name=$Name&type=A",
        "https://dns.google/resolve?name=$Name&type=A"
    )
    foreach ($u in $urls) {
        try {
            $r = Invoke-RestMethod -Uri $u -Headers @{ accept = "application/dns-json" } -TimeoutSec 5
            $ips = @($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data })
            if ($ips.Count -gt 0) { break }
        } catch {}
    }
    $script:dohCache[$Name] = $ips
    return $ips
}

# ---------------------------------------------------------------- TCP
function Get-NetErrKind($Ex) {
    $e = $Ex
    while ($e -and -not ($e -is [System.Net.Sockets.SocketException])) { $e = $e.InnerException }
    if ($e) {
        $c = [string]$e.SocketErrorCode
        if ($c -eq "TimedOut") { return "TIMEOUT" }
        if ($c -eq "ConnectionReset" -or $c -eq "ConnectionAborted") { return "RESET" }
        if ($c -eq "ConnectionRefused") { return "NOCONN" }
    }
    return "ERR"
}

function Test-Tcp([string]$Ip, [int]$Port, [int]$Ms = 3000) {
    $res = [pscustomobject]@{ Ok = $false; Ms = 0; Err = "" }
    $c = New-Object System.Net.Sockets.TcpClient
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $c.BeginConnect($Ip, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($Ms)) { $res.Err = "таймаут"; return $res }
        $c.EndConnect($iar)
        $res.Ok = $true
    } catch {
        $res.Err = $_.Exception.Message
        if ($_.Exception.InnerException) { $res.Err = $_.Exception.InnerException.Message }
    } finally {
        $res.Ms = [int]$sw.ElapsedMilliseconds
        $c.Close()
    }
    return $res
}

# ---------------------------------------------------------------- TLS ClientHello "вручную"
# Своё рукопожатие нужно, чтобы управлять тем, КАК именно имя сайта уходит в сеть:
# одним куском, разрезанным на TCP-сегменты, разбитым на две TLS-записи и т.д.
function Add-U16($List, [int]$V) {
    $List.Add([byte](($V -shr 8) -band 255))
    $List.Add([byte]($V -band 255))
}

function Slice([byte[]]$A, [int]$From, [int]$Len) {
    $r = New-Object byte[] $Len
    [Array]::Copy($A, $From, $r, 0, $Len)
    return ,$r
}

function New-TlsRecord([byte[]]$Payload) {
    $r = New-Object 'System.Collections.Generic.List[byte]'
    $r.Add(0x16); $r.Add(0x03); $r.Add(0x01)
    Add-U16 $r $Payload.Length
    $r.AddRange($Payload)
    return ,($r.ToArray())
}

function New-ClientHello([string]$Sni) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $random = New-Object byte[] 32; $rng.GetBytes($random)
    $session = New-Object byte[] 32; $rng.GetBytes($session)
    $share = New-Object byte[] 32; $rng.GetBytes($share)
    $rng.Dispose()
    $name = [System.Text.Encoding]::ASCII.GetBytes($Sni)

    $pre = New-Object 'System.Collections.Generic.List[byte]'
    Add-U16 $pre 0x0303
    $pre.AddRange($random)
    $pre.Add(32); $pre.AddRange($session)
    $suites = @(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035)
    Add-U16 $pre ($suites.Count * 2)
    foreach ($s in $suites) { Add-U16 $pre $s }
    $pre.Add(1); $pre.Add(0)

    $ext = New-Object 'System.Collections.Generic.List[byte]'
    # server_name
    Add-U16 $ext 0x0000
    Add-U16 $ext ($name.Length + 5)
    Add-U16 $ext ($name.Length + 3)
    $ext.Add(0)
    Add-U16 $ext $name.Length
    $sniPosInExt = $ext.Count
    $ext.AddRange($name)
    # supported_groups: x25519, secp256r1
    Add-U16 $ext 0x000A; Add-U16 $ext 6; Add-U16 $ext 4; Add-U16 $ext 0x001D; Add-U16 $ext 0x0017
    # ec_point_formats
    Add-U16 $ext 0x000B; Add-U16 $ext 2; $ext.Add(1); $ext.Add(0)
    # signature_algorithms
    $sig = @(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
    Add-U16 $ext 0x000D; Add-U16 $ext (2 + $sig.Count * 2); Add-U16 $ext ($sig.Count * 2)
    foreach ($s in $sig) { Add-U16 $ext $s }
    # ALPN: h2, http/1.1
    Add-U16 $ext 0x0010; Add-U16 $ext 14; Add-U16 $ext 12
    $ext.Add(2); $ext.Add(0x68); $ext.Add(0x32)
    $ext.Add(8); $ext.AddRange([System.Text.Encoding]::ASCII.GetBytes("http/1.1"))
    # supported_versions: TLS 1.3, 1.2
    Add-U16 $ext 0x002B; Add-U16 $ext 5; $ext.Add(4); Add-U16 $ext 0x0304; Add-U16 $ext 0x0303
    # key_share: x25519 (любые 32 байта годятся как публичное значение)
    Add-U16 $ext 0x0033; Add-U16 $ext 38; Add-U16 $ext 36; Add-U16 $ext 0x001D; Add-U16 $ext 32
    $ext.AddRange($share)
    # psk_key_exchange_modes
    Add-U16 $ext 0x002D; Add-U16 $ext 2; $ext.Add(1); $ext.Add(1)

    $bodyLen = $pre.Count + 2 + $ext.Count
    $hs = New-Object 'System.Collections.Generic.List[byte]'
    $hs.Add(1)
    $hs.Add([byte](($bodyLen -shr 16) -band 255))
    $hs.Add([byte](($bodyLen -shr 8) -band 255))
    $hs.Add([byte]($bodyLen -band 255))
    $hs.AddRange($pre)
    Add-U16 $hs $ext.Count
    $hs.AddRange($ext)
    $hsBytes = $hs.ToArray()

    $sniOffsetInHs = 4 + $pre.Count + 2 + $sniPosInExt
    return [pscustomobject]@{
        Handshake = $hsBytes
        Record    = (New-TlsRecord $hsBytes)
        SniOffset = $sniOffsetInHs + 5      # смещение имени внутри TLS-записи
    }
}

function Convert-MixedCase([string]$S) {
    $o = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $S.Length; $i++) {
        if ($i % 2 -eq 0) { [void]$o.Append([char]::ToUpper($S[$i])) } else { [void]$o.Append([char]::ToLower($S[$i])) }
    }
    return $o.ToString()
}

# Режимы отправки ClientHello:
#   plain        - как обычно, одним куском
#   split1       - TCP-сегмент в 1 байт, потом остальное
#   splitsni     - TCP-разрез прямо посередине имени сайта
#   tlsfrag      - ClientHello разбит на ДВЕ TLS-записи (имя разрезано), уходят вместе
#   tlsfrag-tcp  - то же, но каждая запись отдельным TCP-сегментом
#   case         - имя в РАЗнОМ реГИстРе
function Get-Segments($Hello, [string]$Mode) {
    $rec = $Hello.Record
    $hs = $Hello.Handshake
    $cut = $Hello.SniOffset + 3
    $segs = New-Object System.Collections.ArrayList
    switch ($Mode) {
        "split1" {
            [void]$segs.Add((Slice $rec 0 1))
            [void]$segs.Add((Slice $rec 1 ($rec.Length - 1)))
        }
        "splitsni" {
            [void]$segs.Add((Slice $rec 0 $cut))
            [void]$segs.Add((Slice $rec $cut ($rec.Length - $cut)))
        }
        "tlsfrag" {
            $k = $cut - 5
            $a = New-TlsRecord (Slice $hs 0 $k)
            $b = New-TlsRecord (Slice $hs $k ($hs.Length - $k))
            [void]$segs.Add([byte[]]($a + $b))
        }
        "tlsfrag-tcp" {
            $k = $cut - 5
            [void]$segs.Add((New-TlsRecord (Slice $hs 0 $k)))
            [void]$segs.Add((New-TlsRecord (Slice $hs $k ($hs.Length - $k))))
        }
        default { [void]$segs.Add($rec) }
    }
    return ,$segs
}

function New-Probe([string]$Status, [int]$Ms, [string]$Detail = "") {
    return [pscustomobject]@{ Status = $Status; Ms = $Ms; Detail = $Detail }
}

# Отправляет ClientHello и смотрит, ответил ли сервер (TLS-запись 0x16/0x15).
# OK - сервер получил имя и ответил; RESET/TIMEOUT - соединение убито или заглохло после отправки имени.
function Invoke-HelloProbe([string]$Ip, [string]$Sni, [string]$Mode, [int]$Ms = 3000) {
    $use = $Sni
    if ($Mode -eq "case") { $use = Convert-MixedCase $Sni }
    $hello = New-ClientHello $use
    $segs = Get-Segments $hello $Mode
    $client = New-Object System.Net.Sockets.TcpClient
    $client.NoDelay = $true
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $client.BeginConnect($Ip, 443, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($Ms)) { return (New-Probe "NOCONN" ([int]$sw.ElapsedMilliseconds) "TCP: таймаут") }
        $client.EndConnect($iar)
        $ns = $client.GetStream()
        $ns.ReadTimeout = $Ms
        $ns.WriteTimeout = $Ms
        foreach ($s in $segs) {
            $ns.Write($s, 0, $s.Length)
            $ns.Flush()
            if ($segs.Count -gt 1) { Start-Sleep -Milliseconds 40 }
        }
        $buf = New-Object byte[] 16
        $n = 0
        try { $n = $ns.Read($buf, 0, $buf.Length) }
        catch { return (New-Probe (Get-NetErrKind $_.Exception) ([int]$sw.ElapsedMilliseconds) $_.Exception.Message) }
        if ($n -le 0) { return (New-Probe "CLOSED" ([int]$sw.ElapsedMilliseconds) "сервер закрыл соединение") }
        if ($buf[0] -eq 0x16 -or $buf[0] -eq 0x15) { return (New-Probe "OK" ([int]$sw.ElapsedMilliseconds)) }
        return (New-Probe "STUB" ([int]$sw.ElapsedMilliseconds) ("ответ не похож на TLS, байт 0x{0:X2}" -f $buf[0]))
    } catch {
        return (New-Probe (Get-NetErrKind $_.Exception) ([int]$sw.ElapsedMilliseconds) $_.Exception.Message)
    } finally {
        $client.Close()
    }
}

function Tag([object]$P) {
    if (-not $P) { return "-" }
    switch ($P.Status) {
        "OK"     { return "OK" }
        "RESET"  { return "СБРОС" }
        "TIMEOUT" { return "ТИШИНА" }
        "STUB"   { return "ЗАГЛУШКА" }
        "CLOSED" { return "ЗАКРЫТО" }
        "NOCONN" { return "НЕТ TCP" }
        default  { return "ОШИБКА" }
    }
}

# Нейтральный сервер: принимает любое имя, поэтому показывает, режет ли сеть САМО имя.
function Get-Neutral {
    if ($script:neutralChecked) { return $script:neutral }
    $script:neutralChecked = $true
    foreach ($c in @("1.1.1.1", "8.8.8.8", "9.9.9.9")) {
        $r = Invoke-HelloProbe $c "www.example.org" "plain"
        if ($r.Status -eq "OK") { $script:neutral = $c; break }
    }
    return $script:neutral
}

# ---------------------------------------------------------------- HTTP-скорость
function Measure-Download([string]$Url, [int]$MaxMs = 8000, [long]$MaxBytes = 5MB) {
    $res = [pscustomobject]@{ Ok = $false; Code = 0; Bytes = 0; Ms = 0; Ttfb = 0; Kbps = 0; Err = "" }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.UserAgent = $script:ua
        $req.Timeout = 8000
        $req.ReadWriteTimeout = 5000
        $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $resp = $req.GetResponse()
        $res.Ttfb = [int]$sw.ElapsedMilliseconds
        $res.Code = [int]$resp.StatusCode
        $st = $resp.GetResponseStream()
        $buf = New-Object byte[] 65536
        $total = 0L
        while ($sw.ElapsedMilliseconds -lt $MaxMs -and $total -lt $MaxBytes) {
            $n = $st.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $total += $n
        }
        $res.Bytes = $total
        $res.Ok = $true
        $dl = [math]::Max(1, [int]$sw.ElapsedMilliseconds - $res.Ttfb)
        $res.Kbps = [int]($total * 8 / $dl)
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) { $res.Code = [int]$_.Exception.Response.StatusCode; $res.Err = "HTTP $($res.Code)" }
        else { $res.Err = $_.Exception.Message }
    } catch {
        $res.Err = $_.Exception.Message
    } finally {
        $res.Ms = [int]$sw.ElapsedMilliseconds
        if ($resp) { $resp.Close() }
    }
    return $res
}

function Show-Download([string]$Label, [string]$Url, [int]$MaxMs = 8000, [long]$MaxBytes = 5MB) {
    $d = Measure-Download $Url $MaxMs $MaxBytes
    if ($d.Ok) {
        $speed = ""
        if ($d.Bytes -gt 300KB) { $speed = ", ~{0:N1} Мбит/с" -f ($d.Kbps / 1000) }
        Say ("  {0,-34} OK: {1} КБ за {2} мс (ответ через {3} мс){4}" -f $Label, [int]($d.Bytes / 1KB), $d.Ms, $d.Ttfb, $speed) "Green"
    } else {
        Say ("  {0,-34} НЕ ОТКРЫЛОСЬ: {1} ({2} мс)" -f $Label, $d.Err, $d.Ms) "Red"
    }
    return $d
}

# ---------------------------------------------------------------- проверка одного хоста
function Test-HostFull([string]$Svc, [string]$HostName) {
    Say ""
    Say $HostName "Cyan"
    $sys = @(Get-SysIps $HostName)
    $doh = @(Get-DohIps $HostName)
    $cands = @($sys + $doh | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 4)
    $ip = $null
    foreach ($c in $cands) { if ((Test-Tcp $c 443 3000).Ok) { $ip = $c; break } }

    if (-not $ip) {
        $msg = "TCP:443 не соединяется ни с одним адресом ($($cands -join ', '))"
        if ($cands.Count -eq 0) { $msg = "имя не разрешается (ни системой, ни через DoH)" }
        Say "  [!!] $msg" "Red"
        Add-Verdict ("{0} / {1}: {2}" -f $Svc, $HostName, $msg)
        return
    }

    $neutral = Get-Neutral
    $nPlain = $null
    if ($neutral) { $nPlain = Invoke-HelloProbe $neutral $HostName "plain" }
    $rPlain = Invoke-HelloProbe $ip $HostName "plain"
    $nameBlocked = ($nPlain -and $nPlain.Status -ne "OK")

    Say ("  адрес {0}; обычный запрос: напрямую {1}, через нейтральный сервер {2}" -f $ip, (Tag $rPlain), (Tag $nPlain))

    if (-not $nameBlocked -and $rPlain.Status -eq "OK") {
        Say "  [OK] рукопожатие проходит, фильтра по имени нет" "Green"
        Add-Verdict ("{0} / {1}: рукопожатие проходит (возможен троттлинг скорости, см. замер ниже)" -f $Svc, $HostName)
        return
    }

    $modes = @("split1", "splitsni", "tlsfrag", "tlsfrag-tcp", "case")
    $wins = @()
    foreach ($m in $modes) {
        $rn = $null
        if ($neutral) { $rn = Invoke-HelloProbe $neutral $HostName $m }
        $rr = Invoke-HelloProbe $ip $HostName $m
        Say ("    {0,-12} напрямую: {1,-9} нейтральный: {2}" -f $m, (Tag $rr), (Tag $rn))
        $ok = $false
        if ($nameBlocked) { if ($rn -and $rn.Status -eq "OK") { $ok = $true } }
        else { if ($rr.Status -eq "OK") { $ok = $true } }
        if ($ok) { $wins += $m }
    }

    if ($nameBlocked) {
        if ($wins.Count -gt 0) {
            Say "  [!!] имя режется по SNI. Обходят: $($wins -join ', ')" "Yellow"
            Add-Verdict ("{0} / {1}: блок по SNI; помогают приёмы: {2}" -f $Svc, $HostName, ($wins -join ", "))
        } else {
            Say "  [!!] имя режется по SNI, простые приёмы не помогли" "Red"
            Add-Verdict ("{0} / {1}: блок по SNI, простые приёмы не помогли (нужен другой подход или узел)" -f $Svc, $HostName)
        }
    } elseif (-not $neutral) {
        Say "  [?] нейтральный сервер недоступен, сравнить не с чем: вывод неточный (закройте GoodbyeDPI/VPN и повторите)" "Yellow"
        Add-Verdict ("{0} / {1}: НЕТ КОНТРОЛЯ (нейтральные серверы не отвечают), вывод неточный" -f $Svc, $HostName)
    } else {
        if ($wins.Count -gt 0) {
            Say "  [!!] с адресом $ip рукопожатие обрывается, помогают: $($wins -join ', ')" "Yellow"
            Add-Verdict ("{0} / {1}: проблема на уровне адреса; помогают: {2}" -f $Svc, $HostName, ($wins -join ", "))
        } else {
            Say "  [!!] имя проходит на нейтральном сервере, а адрес $ip не отвечает: похоже на блок по IP" "Red"
            Add-Verdict ("{0} / {1}: блок по IP/адресу (нужен узел)" -f $Svc, $HostName)
        }
    }
}

# ================================================================= ЗАПУСК
Say "NORMA: замер сети (шаг 0)" "Cyan"
Say ("Дата: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm"))
Say "Займёт 1-4 минуты. Ничего не закрывайте."

# ---------- среда
Head "Среда"
try { Say ("Windows: {0}; PowerShell {1}" -f [Environment]::OSVersion.VersionString, $PSVersionTable.PSVersion) } catch {}
try {
    Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } |
        ForEach-Object { Say ("DNS {0}: {1}" -f $_.InterfaceAlias, ($_.ServerAddresses -join ", ")) }
} catch {}
try {
    $ie = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    Say ("Прокси: включён={0}; сервер={1}; PAC={2}" -f $ie.ProxyEnable, $ie.ProxyServer, $ie.AutoConfigURL)
} catch {}
try {
    $virt = @(Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and -not $_.HardwareInterface } | ForEach-Object { $_.Name })
    if ($virt.Count -gt 0) { Say ("Виртуальные адаптеры (VPN/туннели?): {0}" -f ($virt -join ", ")) "Yellow" }
} catch {}
$tools = @("goodbyedpi", "winws", "zapret", "tpws", "nfqws", "xray", "v2ray", "sing-box", "clash", "clash-verge", "mihomo",
           "nekoray", "nekobox", "hiddify", "amnezia", "wireguard", "openvpn", "outline", "psiphon", "tor", "spoofdpi", "byedpi", "ciadpi")
$found = @(Get-Process -Name $tools -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
if ($found.Count -gt 0) {
    Say ("ВНИМАНИЕ: запущены средства обхода/VPN: {0}. Замер будет неточным, закройте их и повторите." -f ($found -join ", ")) "Red"
}
try {
    $hp = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
    $hl = @(Get-Content $hp | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith("#") -and $_ -match "youtu|googlevideo|ggpht|telegram|t\.me" })
    if ($hl.Count -gt 0) { Say "В hosts есть записи про YouTube/Telegram (они влияют на замер):" "Yellow"; $hl | ForEach-Object { Say ("  " + $_.Trim()) } }
} catch {}

# ---------- DNS
Head "DNS: что отвечает ваш DNS и что отвечает DoH"
$dnsNames = @("www.youtube.com", "i.ytimg.com", "redirector.googlevideo.com", "youtubei.googleapis.com", "yt3.ggpht.com",
              "web.telegram.org", "telegram.org", "t.me", "api.telegram.org", "core.telegram.org")
foreach ($n in $dnsNames) {
    $s = @(Get-SysIps $n)
    $d = @(Get-DohIps $n)
    $flag = ""
    if ($s.Count -eq 0) { $flag = "  <- DNS не отвечает" }
    elseif ($s[0] -match "^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)") { $flag = "  <- подмена на локальный адрес" }
    Say ("  {0,-27} система: {1,-16} DoH: {2}{3}" -f $n, ($s | Select-Object -First 1), ($d | Select-Object -First 1), $flag)
}
Say "  (Для крупных CDN адреса у DNS и DoH могут отличаться, это не доказательство подмены.)"

# ---------- YouTube
Head "YouTube: рукопожатие TLS и обходные приёмы"
$ytHosts = @("www.youtube.com", "i.ytimg.com", "redirector.googlevideo.com")
$node = $null
try {
    $t = [string](Invoke-WebRequest "https://redirector.googlevideo.com/report_mapping?di=no" -UseBasicParsing -TimeoutSec 8).Content
    $m = [regex]::Match($t, "r\d+---sn-[a-z0-9\-]+")
    if ($m.Success) { $node = $m.Value + ".googlevideo.com" }
} catch {}
if ($node) { Say "Ближайший видеоузел Google: $node"; $ytHosts += $node } else { Say "Видеоузел Google определить не удалось (это нормально, идём дальше)." }
foreach ($h in $ytHosts) { Test-HostFull "YouTube" $h }

# ---------- Telegram
Head "Telegram: рукопожатие TLS и обходные приёмы"
foreach ($h in @("web.telegram.org", "t.me")) { Test-HostFull "Telegram" $h }

Head "Telegram: дата-центры (прямое TCP-подключение клиента)"
$dcs = @(
    @("DC1", "149.154.175.53"), @("DC2", "149.154.167.51"), @("DC3", "149.154.175.100"),
    @("DC4", "149.154.167.91"), @("DC5", "91.108.56.130")
)
$dcOk = 0
foreach ($dc in $dcs) {
    $a = Test-Tcp $dc[1] 443 3000
    $b = Test-Tcp $dc[1] 80 3000
    $ta = if ($a.Ok) { "OK {0} мс" -f $a.Ms } else { "НЕТ ($($a.Err))" }
    $tb = if ($b.Ok) { "OK {0} мс" -f $b.Ms } else { "НЕТ" }
    $col = if ($a.Ok) { "Green" } else { "Red" }
    if ($a.Ok) { $dcOk++ }
    Say ("  {0} {1,-16} 443: {2,-14} 80: {3}" -f $dc[0], $dc[1], $ta, $tb) $col
}
if ($dcOk -eq 0) { Add-Verdict ("Telegram: прямое TCP к дата-центрам не проходит (блок по IP: нужен узел)") }
elseif ($dcOk -lt $dcs.Count) { Add-Verdict ("Telegram: часть дата-центров недоступна ($dcOk из $($dcs.Count))") }
else { Add-Verdict ("Telegram: TCP к дата-центрам проходит (клиент может блокироваться по сигнатуре MTProto, смотрите, как ведёт себя приложение)") }

# ---------- скорость
Head "Скорость и открытие страниц"
[void](Show-Download "youtube.com (главная)" "https://www.youtube.com/")
[void](Show-Download "миниатюра i.ytimg.com" "https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg")
[void](Show-Download "web.telegram.org" "https://web.telegram.org/")
[void](Show-Download "t.me/telegram" "https://t.me/telegram")

# ---------- итог
Head "Итог"
foreach ($v in $script:verdicts) { Say ("  " + $v) }

$path = Join-Path $script:root "data\logs\norma-report.txt"
try { [System.IO.File]::WriteAllLines($path, $script:report, (New-Object System.Text.UTF8Encoding($true))) } catch {}
$copied = $false
try { Set-Clipboard -Value ($script:report -join "`r`n"); $copied = $true } catch {}
Write-Host ""
Write-Host "Отчёт сохранён: $path" -ForegroundColor Green
if ($copied) { Write-Host "И скопирован в буфер обмена: вставьте его в чат целиком." -ForegroundColor Green }
Write-Host ""
