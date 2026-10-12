# NORMA: замер скорости видеопотока (googlevideo.com), то есть того, что человек реально чувствует на YouTube.
# Проверка «сайт открылся» этого не показывает: замедление режет именно скорость видео.
#
# Как работает: yt-dlp (необязательный) один раз получает прямую ссылку на видеопоток тестового ролика,
# а curl.exe качет кусок этого потока несколько секунд и считает среднюю скорость в Мбит/с.
# Тестовый ролик по умолчанию задан в $script:defaultVideo; свой можно записать первой строкой в data\video-probe.txt.
#
# Важно: без внешней JS-среды yt-dlp иногда отдаёт ссылки, которые Google сам ограничивает по скорости.
# Тогда цифра занижена одинаково для всех стратегий. Поэтому сравнивайте стратегии между собой, а не с тарифом.

$script:defaultVideo = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
$script:ytDlp = Join-Path $script:dataDir "yt-dlp.exe"
$script:videoUrl = ""
$script:videoFailed = $false

function Get-YtDlpPath {
    if (Test-Path $script:ytDlp) { return $script:ytDlp }
    $c = Get-Command "yt-dlp.exe" -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return ""
}

function Get-VideoPageUrl {
    $f = Join-Path $script:dataDir "video-probe.txt"
    try {
        if (Test-Path $f) {
            foreach ($l in [IO.File]::ReadAllLines($f, [Text.Encoding]::UTF8)) {
                $t = $l.Trim()
                if ($t -match '^https://') { return $t }
            }
        }
    } catch {}
    return $script:defaultVideo
}

# Скачивает yt-dlp.exe в data\ (около 20 МБ)
function Install-YtDlp {
    Initialize-Dirs
    $tmp = $script:ytDlp + ".part"
    $ProgressPreference = "SilentlyContinue"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Say "Скачиваю yt-dlp.exe с github.com/yt-dlp/yt-dlp (около 20 МБ)..." "Cyan"
        Invoke-WebRequest -Uri "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe" -OutFile $tmp -UseBasicParsing
        if ((Get-Item -LiteralPath $tmp).Length -lt 5000000) { throw "файл слишком мал, загрузка прервалась" }
        Move-Item -LiteralPath $tmp -Destination $script:ytDlp -Force
        $script:videoFailed = $false
        $script:videoUrl = ""
        Say "yt-dlp.exe сохранён в data. Бенчмарк и клавиша S в рабочем окне теперь будут измерять скорость видео." "Green"
    } catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        Say ("Не удалось скачать yt-dlp: " + $_.Exception.Message) "Red"
        Say "Скачайте yt-dlp.exe вручную (github.com/yt-dlp/yt-dlp/releases) и положите в папку data." "Yellow"
    }
}

# Получает прямую ссылку на видеопоток (один раз за сеанс). Нужно вызывать, когда обход уже включён.
function Resolve-VideoStream {
    if ($script:videoUrl) { return $true }
    if ($script:videoFailed) { return $false }
    $y = Get-YtDlpPath
    if (-not $y) { return $false }
    try {
        $lines = @(& $y -g -f "bv*[height<=720][ext=mp4]/18/worst[ext=mp4]/worst" --no-playlist --no-warnings (Get-VideoPageUrl) 2>&1 | ForEach-Object { [string]$_ })
        $u = $lines | Where-Object { $_ -match '^https://' } | Select-Object -First 1
        if ($u) { $script:videoUrl = $u; return $true }
        $script:videoFailed = $true
        $why = ($lines | Select-Object -First 1)
        Say ("  yt-dlp не вернул ссылку на видео: {0}" -f $why) "DarkGray"
    } catch {
        $script:videoFailed = $true
        Say ("  yt-dlp не запустился: " + $_.Exception.Message) "DarkGray"
    }
    return $false
}

# Скорость скачивания видеопотока, Мбит/с; $null, если замер невозможен
function Test-VideoSpeed([int]$Seconds = 8) {
    if (-not $script:videoUrl) { return $null }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "curl.exe"
        $psi.Arguments = ('-s -o NUL -w "%{{http_code}} %{{speed_download}}" --ssl-no-revoke -r 0-40000000 --connect-timeout 5 --max-time {0} "{1}"' -f $Seconds, $script:videoUrl)
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = ""
        if ($p.WaitForExit(($Seconds + 8) * 1000)) { $out = $p.StandardOutput.ReadToEnd().Trim() } else { try { $p.Kill() } catch {} }
        $parts = @($out -split '\s+')
        if ($parts.Count -ge 2 -and $parts[0] -match '^20[06]$') {
            $v = 0.0
            if ([double]::TryParse($parts[1], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$v)) {
                return [math]::Round($v * 8 / 1000000, 2)
            }
        }
        return 0.0
    } catch { return $null }
}

# Разовый замер для рабочего окна (клавиша S) и меню
function Show-VideoSpeed {
    if (-not (Get-YtDlpPath)) {
        Say "Для замера скорости видео нужен yt-dlp: меню «Дополнительно», пункт «Скачать yt-dlp»." "Yellow"
        return
    }
    Say "Замер скорости видео (около 10-30 секунд)..." "Cyan"
    if (-not (Resolve-VideoStream)) { Say "Не удалось получить ссылку на видео. Проверьте, что NORMA включена и YouTube открывается." "Yellow"; return }
    $m = Test-VideoSpeed 10
    if ($null -eq $m) { Say "Замер не удался." "Yellow"; return }
    $col = "Green"
    if ($m -lt 5) { $col = "Yellow" }
    Say ("Скорость видеопотока: {0:N1} Мбит/с" -f $m) $col
    if ($m -lt 5) { Say "Это низкая скорость. Сравните с включённым и выключенным обходом, а также с другой стратегией (бенчмарк)." "DarkGray" }
}
