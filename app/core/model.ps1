# NORMA: модель стратегии.
# Стратегия для winws это строка аргументов. Здесь она превращается в структуру: профили (сегменты), в них параметры.
# Это позволяет: описать стратегию человеческим языком, собрать её обратно без потерь, найти стратегии с одинаковым
# правилом для YouTube (и не проверять их повторно) и, в будущем, менять параметры и передавать их собственному движку.
#
# Структура: Model = { Segments = [ { Options = [ { Name; Value; HasValue; Quoted } ] } ] }
# Сегменты разделяются параметром --new. Токен, не похожий на --параметр, сохраняется с пустым Name.

function Split-ArgTokens([string]$Text) {
    $res = @()
    foreach ($m in [regex]::Matches($Text, '(?:[^\s"]+|"[^"]*")+')) { $res += $m.Value }
    return $res
}

function ConvertTo-StrategyModel([string]$ArgsTpl) {
    $segs = @()
    $cur = @()
    foreach ($tok in @(Split-ArgTokens $ArgsTpl)) {
        if ($tok -eq "--new") {
            $segs += [pscustomobject]@{ Options = @($cur) }
            $cur = @()
            continue
        }
        $m = [regex]::Match($tok, '^--([A-Za-z0-9-]+)(?:=(.*))?$')
        if ($m.Success) {
            $has = $m.Groups[2].Success
            $val = ""
            $quoted = $false
            if ($has) {
                $val = $m.Groups[2].Value
                if ($val.Length -ge 2 -and $val.StartsWith('"') -and $val.EndsWith('"')) { $quoted = $true; $val = $val.Substring(1, $val.Length - 2) }
            }
            $cur += [pscustomobject]@{ Name = $m.Groups[1].Value; Value = $val; HasValue = $has; Quoted = $quoted }
        } else {
            $cur += [pscustomobject]@{ Name = ""; Value = $tok; HasValue = $false; Quoted = $false }
        }
    }
    $segs += [pscustomobject]@{ Options = @($cur) }
    return [pscustomobject]@{ Segments = @($segs) }
}

function ConvertTo-OptionText($O) {
    if (-not $O.Name) { return [string]$O.Value }
    if (-not $O.HasValue) { return ("--" + $O.Name) }
    $v = $O.Value
    if ($O.Quoted) { $v = '"' + $v + '"' }
    return ("--" + $O.Name + "=" + $v)
}

function ConvertFrom-StrategyModel($Model) {
    $toks = @()
    $segs = @($Model.Segments)
    for ($i = 0; $i -lt $segs.Count; $i++) {
        foreach ($o in @($segs[$i].Options)) { $toks += (ConvertTo-OptionText $o) }
        if ($i -lt $segs.Count - 1) { $toks += "--new" }
    }
    return ($toks -join " ")
}

# ---------- чтение параметров сегмента
function Get-OptValue($Seg, [string]$Name) {
    foreach ($o in @($Seg.Options)) { if ($o.Name -eq $Name) { return $o.Value } }
    return $null
}

# Имена файлов списков (hostlist, ipset) без подстановки %LISTS%
function Get-SegLists($Seg) {
    $res = @()
    foreach ($o in @($Seg.Options)) {
        if (@("hostlist", "ipset") -contains $o.Name) { $res += ([string]$o.Value -replace '^%LISTS%', '') }
    }
    return $res
}

function Test-SegGoogle($Seg) {
    return (@(Get-SegLists $Seg | Where-Object { $_ -match '^list-google' }).Count -gt 0)
}

# Роль профиля по спискам и портам
function Get-SegmentRole($Seg) {
    $tcp = [string](Get-OptValue $Seg "filter-tcp")
    $udp = [string](Get-OptValue $Seg "filter-udp")
    $l7 = [string](Get-OptValue $Seg "filter-l7")
    $lists = @(Get-SegLists $Seg)
    if ((Test-SegGoogle $Seg) -and $tcp) { return "YouTube/Google" }
    if ($udp -eq "443") { return "QUIC" }
    if (("$tcp $udp") -match 'GameFilter') { return "игры" }
    if (($udp -match '19294') -or ($l7 -match 'discord|stun')) { return "Discord (голос)" }
    if ($tcp -match '2053') { return "Discord/Cloudflare" }
    if (@($lists | Where-Object { $_ -match '^list-general' }).Count -gt 0) { return "общие сайты и Discord" }
    return "прочее"
}

# Короткое описание приёма: режим, подделка, разрез, перекрытие, повторы
function Get-DesyncText($Seg) {
    $modes = [string](Get-OptValue $Seg "dpi-desync")
    if (-not $modes) { return "без десинхронизации" }
    $t = $modes.Replace(",", "+")
    $f = [string](Get-OptValue $Seg "dpi-desync-fooling")
    if ($f) { $t += "; подделка: " + $f }
    $sp = [string](Get-OptValue $Seg "dpi-desync-split-pos")
    if ($sp) { $t += "; разрез: " + $sp }
    $so = [string](Get-OptValue $Seg "dpi-desync-split-seqovl")
    if ($so) { $t += "; seqovl " + $so }
    $rp = [string](Get-OptValue $Seg "dpi-desync-repeats")
    if ($rp) { $t += "; повторов " + $rp }
    return $t
}

# Описание стратегии одной строкой: что делает для YouTube и что ещё затрагивает
function Get-StrategySummary($S) {
    try {
        $m = ConvertTo-StrategyModel $S.ArgsTpl
        $main = ""
        $others = @()
        foreach ($seg in @($m.Segments)) {
            $role = Get-SegmentRole $seg
            if ($role -eq "YouTube/Google") {
                if (-not $main) { $main = ("YouTube/Google TCP {0}: {1}" -f (Get-OptValue $seg "filter-tcp"), (Get-DesyncText $seg)) }
            } elseif ($others -notcontains $role) {
                $others += $role
            }
        }
        if (-not $main) { $main = "отдельного правила для YouTube нет" }
        if ($others.Count -gt 0) { return ($main + " | также: " + ($others -join ", ")) }
        return $main
    } catch { return "" }
}

# Ключ эквивалентности: каноническая запись правила для YouTube (TCP) и для QUIC по списку list-google.
# Две стратегии с одним ключом одинаково ведут себя на YouTube. Пустая строка: отдельного правила нет.
function Get-StrategyYoutubeKey($S) {
    try {
        $m = ConvertTo-StrategyModel $S.ArgsTpl
        $tcpKey = ""
        $quicKey = "-"
        foreach ($seg in @($m.Segments)) {
            if (-not (Test-SegGoogle $seg)) { continue }
            $parts = @()
            foreach ($o in @($seg.Options)) {
                if (@("hostlist", "filter-tcp", "filter-udp", "wf-tcp", "wf-udp") -contains $o.Name) { continue }
                $parts += (ConvertTo-OptionText $o)
            }
            $text = ($parts -join " ")
            if (Get-OptValue $seg "filter-tcp") { if (-not $tcpKey) { $tcpKey = $text } }
            elseif (Get-OptValue $seg "filter-udp") { $quicKey = $text }
        }
        if (-not $tcpKey) { return "" }
        return ("T[{0}] Q[{1}]" -f $tcpKey, $quicKey)
    } catch { return "" }
}

# ---------- справочник параметров (app\core\options.txt)
function Get-OptionReference {
    $res = @{}
    $p = Join-Path $script:root "app\core\options.txt"
    if (-not (Test-Path $p)) { return $res }
    foreach ($l in [IO.File]::ReadAllLines($p, [Text.Encoding]::UTF8)) {
        if ($l.StartsWith("#") -or $l.Trim() -eq "") { continue }
        $f = $l -split "`t", 3
        if ($f.Count -ge 3) { $res[$f[0]] = [pscustomobject]@{ Kind = $f[1]; Text = $f[2] } }
    }
    return $res
}
