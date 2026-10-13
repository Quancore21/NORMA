# NORMA: автоподбор стратегии.
# Принципы:
#   1) обход нужен только для того, что реально не открывается: сначала замер без обхода;
#   2) стратегия, которая ломает то, что и так открывалось, не подходит;
#   3) обычный режим: побеждает первая стратегия, которая открывает всё нужное и ничего не ломает;
#   4) режим бенчмарка (-Benchmark): пробуются все. Годная стратегия проверяется трижды (стабильность и медиана времени).
#      Результаты в пределах допуска считаются равными: разница в доли секунды это шум.
# Результат: объект { Status = ok | partial | none-needed | failed; Strategy; Score; Total; RequiredUrls }.
# При Status = ok / partial выбранный winws остаётся запущенным.

function New-PickResult([string]$Status, $Strategy, [int]$Score, [int]$Total, $ReqUrls) {
    return [pscustomobject]@{ Status = $Status; Strategy = $Strategy; Score = $Score; Total = $Total; RequiredUrls = @($ReqUrls) }
}

function Invoke-AutoPick {
    param(
        [string]$Prof = "youtube",
        [string]$Prefer = "",
        [int]$Max = 0,
        [switch]$Force,
        [switch]$Benchmark
    )

    $targets = @(Get-Targets $Prof)
    if ($targets.Count -eq 0) {
        Say "Нет списка проверок (vendor\zapret\utils\targets.txt)." "Red"
        return (New-PickResult "failed" $null 0 0 @())
    }
    if (-not (Get-Command "curl.exe" -ErrorAction SilentlyContinue)) {
        Say "Не найден curl.exe (нужна Windows 10 версии 1803 или новее)." "Red"
        return (New-PickResult "failed" $null 0 0 @())
    }
    $urls = @($targets | ForEach-Object { $_.Url })

    # ---------- шаг 1: что реально не открывается без обхода
    Say "Шаг 1. Проверяю сеть без обхода..." "Cyan"
    Stop-Winws
    $base = Test-Urls $urls
    $required = @()
    $control = @()
    foreach ($t in $targets) {
        if ($base[$t.Url]) { $control += $t; Say ("  {0,-24} открывается" -f $t.Key) "Green" }
        else { $required += $t; Say ("  {0,-24} НЕ ОТКРЫВАЕТСЯ" -f $t.Key) "Yellow" }
    }
    if ($required.Count -eq 0) {
        if (-not $Force -and -not $Benchmark) {
            Say "Всё проверенное открывается и без обхода. NORMA сейчас не нужна." "Green"
            return (New-PickResult "none-needed" $null 0 0 @())
        }
        $required = $targets
        $control = @()
    }
    if ($required.Count -eq $targets.Count) {
        Say "  Не открывается ничего из проверенного. Если подбор не поможет: проверьте интернет и включите Secure DNS (пункт «Доктор» в меню подскажет)." "Yellow"
    }
    $reqUrls = @($required | ForEach-Object { $_.Url })

    # ---------- шаг 2: перебор стратегий
    $all = @(Get-SortedStrategies $Prof)
    if ($all.Count -eq 0) {
        Say "Не найдено ни одной стратегии (vendor\zapret\general*.bat, strategies\*.args)." "Red"
        return (New-PickResult "failed" $null 0 $required.Count $reqUrls)
    }
    if ($Prefer) {
        $all = @($all | Where-Object { $_.Name -eq $Prefer }) + @($all | Where-Object { $_.Name -ne $Prefer })
    }
    if ($Max -gt 0) { $all = @($all | Select-Object -First $Max) }

    Say ""
    $mode = "поиск первой подходящей"
    if ($Benchmark) { $mode = "бенчмарк: проверяю все" }
    Say ("Шаг 2. Перебираю стратегии: {0} ({1}). Нужно открыть: {2} из {3} проверок." -f $all.Count, $mode, $required.Count, $targets.Count) "Cyan"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = @()
    $best = $null
    $bestScore = 0
    $i = 0
    foreach ($s in $all) {
        $i++
        $p = Start-Winws $s
        if (-not $p) { continue }
        Start-Sleep -Milliseconds 2500
        if ($p.HasExited) {
            Say ("  [{0}/{1}] {2}: winws завершился (код {3}), пропускаю" -f $i, $all.Count, $s.Name, $p.ExitCode) "DarkGray"
            continue
        }
        $r = Test-UrlsDetailed $urls
        $okReq = @($required | Where-Object { $r[$_.Url].Ok }).Count
        $badCtl = @($control | Where-Object { -not $r[$_.Url].Ok })
        if ($badCtl.Count -gt 0) {
            # повторная проверка, чтобы не принять случайный сбой за поломку
            $r2 = Test-Urls @($badCtl | ForEach-Object { $_.Url })
            $badCtl = @($badCtl | Where-Object { -not $r2[$_.Url] })
        }
        $harm = ($badCtl.Count -gt 0)
        $sumT = 0.0
        foreach ($t in $required) { if ($r[$t.Url].Ok) { $sumT += $r[$t.Url].Time } }
        $avgT = 99.0
        if ($okReq -gt 0) { $avgT = $sumT / $okReq }

        # бенчмарк: годная стратегия проверяется ещё дважды (стабильность, медиана)
        if ($Benchmark -and -not $harm -and $okReq -eq $required.Count) {
            $times = @($avgT)
            $stable = $okReq
            for ($k = 2; $k -le 3; $k++) {
                $rr = Test-UrlsDetailed $reqUrls
                $okK = @($required | Where-Object { $rr[$_.Url].Ok }).Count
                if ($okK -lt $stable) { $stable = $okK }
                if ($okK -gt 0) {
                    $sk = 0.0
                    foreach ($t in $required) { if ($rr[$t.Url].Ok) { $sk += $rr[$t.Url].Time } }
                    $times += ($sk / $okK)
                }
            }
            $avgT = Get-Median $times
            $okReq = $stable
        }

        $ctlTxt = "контроль ок"
        if ($control.Count -eq 0) { $ctlTxt = "без контроля" }
        if ($harm) {
            if ($okReq -eq 0) { $ctlTxt = "не подошла" }
            else { $ctlTxt = "ЛОМАЕТ: " + (($badCtl | ForEach-Object { $_.Key }) -join ", ") }
        }
        $timeTxt = "{0:N2} с" -f $avgT
        if ($okReq -eq 0) { $timeTxt = "-" }
        $etaTxt = ""
        if ($all.Count -gt 8 -and $i -lt $all.Count) {
            $etaTxt = (" | ещё ~{0} мин" -f [math]::Ceiling(($sw.Elapsed.TotalSeconds / $i) * ($all.Count - $i) / 60))
        }
        $col = "DarkGray"
        if ($harm) { $col = "Red" } elseif ($okReq -eq $required.Count) { $col = "Green" }
        Say ("  [{0}/{1}] {2,-34} {3}/{4}; {5}; {6}{7}" -f $i, $all.Count, $s.Name, $okReq, $required.Count, $timeTxt, $ctlTxt, $etaTxt) $col

        $rows += [pscustomobject]@{ Index = $i; Strategy = $s; Ok = $okReq; Harm = $harm; Avg = $avgT }
        if (-not $harm -and $okReq -gt $bestScore) { $best = $s; $bestScore = $okReq }
        if (-not $Benchmark -and -not $harm -and $okReq -eq $required.Count) {
            return (New-PickResult "ok" $s $okReq $required.Count $reqUrls)
        }
    }

    Stop-Winws

    if ($Benchmark) {
        $ranked = @(Sort-StrategyRows $rows)
        if ($ranked.Count -eq 0) {
            Say "Бенчмарк: ни одна стратегия не подошла. Обход НЕ включён." "Red"
            return (New-PickResult "failed" $null 0 $required.Count $reqUrls)
        }
        Say ""
        Say "Лучшие стратегии. Результаты в пределах 15% считаются равными и идут в порядке перебора:" "Cyan"
        $rank = 0
        foreach ($c in ($ranked | Select-Object -First 10)) {
            $rank++
            Say ("  {0,2}. {1,-34} {2}/{3}; {4:N2} с" -f $rank, $c.Strategy.Name, $c.Ok, $required.Count, $c.Avg) "Gray"
        }
        # ранжирование сохраняется в data\ranking.json
        try {
            Initialize-Dirs
            $out = @($ranked | ForEach-Object {
                    [pscustomobject]@{ name = $_.Strategy.Name; ok = $_.Ok; total = $required.Count; avg = [math]::Round($_.Avg, 3); source = $_.Strategy.Source }
                })
            $doc = [pscustomobject]@{ date = (Get-Date -Format "yyyy-MM-dd HH:mm"); network = (Get-NetworkSignature); profile = $Prof; ranking = $out }
            [IO.File]::WriteAllText((Join-Path $script:dataDir "ranking.json"), (ConvertTo-Json -InputObject $doc -Depth 5), (New-Object Text.UTF8Encoding($false)))
        } catch {}
        $top = $ranked[0]
        [void](Start-Winws $top.Strategy)
        Start-Sleep -Milliseconds 1500
        $status = "partial"
        if ($top.Ok -eq $required.Count) { $status = "ok" }
        Say ("Включена: {0}" -f $top.Strategy.Name) "Green"
        return (New-PickResult $status $top.Strategy $top.Ok $required.Count $reqUrls)
    }

    if ($best -and $bestScore -gt 0) {
        [void](Start-Winws $best)
        Start-Sleep -Milliseconds 1500
        Say ("Идеальной стратегии не нашлось. Включена лучшая из найденных: {0} ({1} из {2})." -f $best.Name, $bestScore, $required.Count) "Yellow"
        return (New-PickResult "partial" $best $bestScore $required.Count $reqUrls)
    }
    Say "Не нашлось стратегии, которая работает и не ломает остальное. Обход НЕ включён." "Red"
    return (New-PickResult "failed" $null 0 $required.Count $reqUrls)
}
