# NORMA: план приёма и сборка пакетов. Показывает, какие пакеты отправит стратегия, если ей дать настоящий TLS ClientHello,
# и из каких байт эти пакеты состоят (заголовки IPv4 и TCP, порядковые номера, контрольные суммы, подделка).
# Это вычисление без сети и драйвера (app\native\NormaEngine.cs); так мы понимаем стратегии и готовим основу собственного движка.
# Моделируются приёмы fake, multisplit, multidisorder и позиции числом, host, endhost, midsld. Остальное перечисляется как «не моделируется».

function Initialize-Planner {
    if ('NormaCore.Planner' -as [type]) { return $true }
    try {
        $src = [IO.File]::ReadAllText((Join-Path $script:root "app\native\NormaEngine.cs"), [Text.Encoding]::UTF8)
        Add-Type -TypeDefinition $src -Language CSharp
        return $true
    } catch {
        Say ("Не удалось загрузить планировщик: " + $_.Exception.Message) "Red"
        return $false
    }
}

function ConvertTo-IntSafe([string]$Text) {
    $v = 0
    if ([int]::TryParse($Text, [ref]$v)) { return $v }
    return 0
}

# ---------- байты и параметры для сборщика пакетов
function ConvertFrom-Hex([string]$Hex) {
    $b = New-Object byte[] ([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring(2 * $i, 2), 16) }
    return ,$b
}

function Join-Bytes([byte[]]$A, [byte[]]$B) {
    $r = New-Object byte[] ($A.Length + $B.Length)
    [Array]::Copy($A, 0, $r, 0, $A.Length)
    [Array]::Copy($B, 0, $r, $A.Length, $B.Length)
    return ,$r
}

# Число из параметра: десятичное (со знаком) или 0x...; при ошибке значение по умолчанию
function ConvertTo-IntAuto([string]$Text, [int]$Default) {
    $t = $Text.Trim()
    if ($t -match '^[+-]?0[xX][0-9a-fA-F]+$') {
        try {
            $n = [Convert]::ToInt64(($t -replace '^[+-]?0[xX]', ''), 16)
            if ($t.StartsWith("-")) { $n = -$n }
            return [int]$n
        } catch { return $Default }
    }
    $v = 0
    if ([int]::TryParse($t, [ref]$v)) { return $v }
    return $Default
}

# Содержимое поддельного пакета: %BIN%файл, 0xШЕСТНАДЦАТЕРИЧНО или встроенное (образец ClientHello для www.google.com)
function Resolve-FakePayload([string]$Spec) {
    if ($Spec -match '^%BIN%(.+)$') {
        $p = Join-Path $script:binDir $Matches[1]
        if (Test-Path $p) { return ,[IO.File]::ReadAllBytes($p) }
    }
    if (($Spec -match '^0x([0-9a-fA-F]+)$') -and (($Matches[1].Length % 2) -eq 0)) { return ,(ConvertFrom-Hex $Matches[1]) }
    return ,[IO.File]::ReadAllBytes((Join-Path $script:binDir "tls_clienthello_www_google_com.bin"))
}

# Шаблон для перекрытия seqovl: %BIN%файл или пусто (тогда нули)
function Resolve-PatternBytes([string]$Spec) {
    if ($Spec -match '^%BIN%(.+)$') {
        $p = Join-Path $script:binDir $Matches[1]
        if (Test-Path $p) { return ,[IO.File]::ReadAllBytes($p) }
    }
    return ,(New-Object byte[] 0)
}

# Пакеты стратегии для образца ClientHello: { Set (PacketSet); Seg; Template }. Образец: IPv4+TCP с включёнными TCP timestamps.
function Get-StrategyPackets($S, [byte[]]$Hello) {
    $m = ConvertTo-StrategyModel $S.ArgsTpl
    $seg = $null
    foreach ($x in @($m.Segments)) { if ((Get-SegmentRole $x) -eq "YouTube/Google") { $seg = $x; break } }
    if (-not $seg) { return $null }
    $pkt = [NormaCore.PacketBuilder]::MakeTemplate($Hello, $true)
    $inc = ConvertTo-IntAuto ([string](Get-OptValue $seg "dpi-desync-badseq-increment")) (-10000)
    $set = [NormaCore.PacketBuilder]::Build($pkt, [string](Get-OptValue $seg "dpi-desync"), [string](Get-OptValue $seg "dpi-desync-split-pos"),
        (ConvertTo-IntSafe ([string](Get-OptValue $seg "dpi-desync-split-seqovl"))), (ConvertTo-IntSafe ([string](Get-OptValue $seg "dpi-desync-repeats"))),
        [string](Get-OptValue $seg "dpi-desync-fooling"), (Resolve-FakePayload ([string](Get-OptValue $seg "dpi-desync-fake-tls"))),
        (Resolve-PatternBytes ([string](Get-OptValue $seg "dpi-desync-split-seqovl-pattern"))), (ConvertTo-IntSafe ([string](Get-OptValue $seg "dpi-desync-ttl"))),
        $inc, (([string](Get-OptValue $seg "ip-id")) -eq "zero"), (-not [string]::IsNullOrEmpty([string](Get-OptValue $seg "dpi-desync-fake-tls-mod"))))
    return [pscustomobject]@{ Set = $set; Seg = $seg; Template = $pkt }
}

function Format-TcpFlags([int]$F) {
    $names = @()
    if ($F -band 2) { $names += "SYN" }
    if ($F -band 1) { $names += "FIN" }
    if ($F -band 4) { $names += "RST" }
    if ($F -band 16) { $names += "ACK" }
    if ($F -band 8) { $names += "PSH" }
    if ($names.Count -eq 0) { return "-" }
    return ($names -join "+")
}

# Длина поддельного пакета: из файла, на который ссылается dpi-desync-fake-tls; 0, если используется встроенный
function Get-FakeLength($Seg) {
    $v = [string](Get-OptValue $Seg "dpi-desync-fake-tls")
    if ($v -match '^%BIN%(.+)$') {
        $p = Join-Path $script:binDir $Matches[1]
        if (Test-Path $p) { return [int](Get-Item -LiteralPath $p).Length }
    }
    return 0
}

# План для стратегии на образце ClientHello. Возвращает { Plan; Seg; FakeFile; Increment } или $null, если у стратегии нет правила для YouTube.
function Get-StrategyPlan($S, [byte[]]$Hello) {
    $m = ConvertTo-StrategyModel $S.ArgsTpl
    $seg = $null
    foreach ($x in @($m.Segments)) { if ((Get-SegmentRole $x) -eq "YouTube/Google") { $seg = $x; break } }
    if (-not $seg) { return $null }
    $modes = [string](Get-OptValue $seg "dpi-desync")
    $spec = [string](Get-OptValue $seg "dpi-desync-split-pos")
    $seqovl = ConvertTo-IntSafe ([string](Get-OptValue $seg "dpi-desync-split-seqovl"))
    $rep = ConvertTo-IntSafe ([string](Get-OptValue $seg "dpi-desync-repeats"))
    $foo = [string](Get-OptValue $seg "dpi-desync-fooling")
    $plan = [NormaCore.Planner]::Build($Hello, $modes, $spec, $seqovl, $rep, $foo, (Get-FakeLength $seg))
    return [pscustomobject]@{ Plan = $plan; Seg = $seg; FakeFile = [string](Get-OptValue $seg "dpi-desync-fake-tls"); Increment = [string](Get-OptValue $seg "dpi-desync-badseq-increment") }
}

function Format-FoolingText([string]$Fooling, [string]$Increment) {
    if (-not $Fooling) { return "без подделки заголовков" }
    $t = $Fooling
    if ($Fooling -match 'badseq' -and $Increment) { $t = ($Fooling + " (сдвиг номера " + $Increment + ")") }
    return $t
}

# Печатает план по-человечески
function Show-StrategyPlan($S) {
    if (-not (Initialize-Planner)) { return }
    $sample = Join-Path $script:binDir "tls_clienthello_www_google_com.bin"
    if (-not (Test-Path $sample)) { Say "Нет образца ClientHello (bin\tls_clienthello_www_google_com.bin)." "Red"; return }
    $hello = [IO.File]::ReadAllBytes($sample)
    $info = [NormaCore.Planner]::ParseHello($hello)
    Say ("Стратегия: {0}" -f $S.Name) "Cyan"
    $r = Get-StrategyPlan $S $hello
    if (-not $r) { Say "У этой стратегии нет отдельного правила для YouTube (TCP): план для него не строится." "Yellow"; return }
    Say ("Приём: {0}" -f (Get-DesyncText $r.Seg)) "Gray"
    Say ("Образец: TLS ClientHello на {0} байт, имя сайта {1} (смещение {2}, длина {3})" -f $hello.Length, $info.Host, $info.SniOffset, $info.SniLength) "DarkGray"
    Say ""
    Say "Пакеты в порядке отправки:" "Cyan"
    $n = 0
    foreach ($k in @($r.Plan.Packets)) {
        $n++
        if ($k.Kind -eq "fake") {
            $src = "встроенный"
            if ($r.FakeFile -match '^%BIN%(.+)$') { $src = $Matches[1] } elseif ($k.Length -gt 0) { $src = ("{0} байт" -f $k.Length) }
            Say ("  {0}. поддельный пакет ({1}), повторов: {2}; подделка заголовков: {3}" -f $n, $src, $k.Extra, (Format-FoolingText $r.Plan.Fooling $r.Increment)) "Yellow"
        } else {
            $end = $k.Offset + $k.Length
            $line = ("  {0}. данные [{1}, {2}): {3} байт" -f $n, $k.Offset, $end, $k.Length)
            if ($k.Extra -gt 0) { $line += ("; перекрытие seqovl {0} байт шаблона перед началом сегмента" -f $k.Extra) }
            Say $line "Green"
        }
    }
    if ($r.Plan.Unsupported.Count -gt 0) {
        Say ""
        Say ("Пока не моделируется: {0}. Эти части работают в winws как обычно, но здесь их не видно." -f (@($r.Plan.Unsupported) -join ", ")) "DarkGray"
    }
    $dataTotal = 0
    foreach ($k in @($r.Plan.Packets)) { if ($k.Kind -eq "data") { $dataTotal += $k.Length } }
    Say ""
    if ($dataTotal -eq $hello.Length) { Say ("Проверка: сегменты данных вместе дают исходные {0} байт, ничего не потеряно и не продублировано." -f $hello.Length) "DarkGray" }

    # собранные пакеты: из каких байт состоит каждый
    $pk = Get-StrategyPackets $S $hello
    if ($pk) {
        Say ""
        Say "Собранные пакеты (образец: IPv4+TCP с включёнными TCP timestamps; номер отсчитывается от исходного):" "Cyan"
        $n2 = 0
        foreach ($b in @($pk.Set.Packets)) {
            $n2++
            $kind = "данные   "
            if ($b.Kind -eq "fake") { $kind = "поддельный" }
            $sum = "суммы верны"
            if (-not $b.ChecksumOk) { $sum = "сумма TCP намеренно неверна" }
            $line = ("  {0,2}. {1} номер {2,9:+0;-0;0}  содержимое {3,4} байт  флаги {4,-7} TTL {5}  ID {6}  {7}" -f $n2, $kind, $b.SeqRel, $b.PayloadLen, (Format-TcpFlags $b.Flags), $b.Ttl, $b.Id, $sum)
            $col = "Green"
            if ($b.Kind -eq "fake") { $col = "Yellow" }
            Say $line $col
        }
        $extraNotes = @($pk.Set.Notes | Where-Object { @($r.Plan.Unsupported) -notcontains $_ })
        if ($extraNotes.Count -gt 0) { Say ("Не применено или не моделируется при сборке: {0}." -f ($extraNotes -join ", ")) "DarkGray" }
    }
}
