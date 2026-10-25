# NORMA: план приёма. Показывает, какие пакеты отправит стратегия, если ей дать настоящий TLS ClientHello.
# Это вычисление без сети и драйвера (планировщик app\native\NormaPlan.cs); так мы понимаем стратегии и готовим основу собственного движка.
# Моделируются приёмы fake, multisplit, multidisorder и позиции числом, host, endhost, midsld. Остальное перечисляется как «не моделируется».

function Initialize-Planner {
    if ('NormaCore.Planner' -as [type]) { return $true }
    try {
        $src = [IO.File]::ReadAllText((Join-Path $script:root "app\native\NormaPlan.cs"), [Text.Encoding]::UTF8)
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
}
