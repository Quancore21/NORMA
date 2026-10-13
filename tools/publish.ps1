# NORMA: публикация новой версии на GitHub одной командой.
#
# Как пользоваться:
#   1. Распакуйте новый архив NORMA в любую папку (не в папку репозитория).
#   2. Откройте PowerShell и запустите скрипт ИЗ НОВОЙ ПАПКИ, указав путь к своему клону репозитория:
#        powershell -ExecutionPolicy Bypass -File tools\publish.ps1 -Repo "C:\путь\к\клону\NORMA"
#
# Что делает:
#   - зеркально копирует файлы новой версии в клон (удалённые в новой версии файлы тоже удаляются, папка .git не трогается);
#   - запускает самопроверку ядра;
#   - показывает изменения и просит подтверждение;
#   - делает коммит, отправляет его на GitHub и ставит тег vВЕРСИЯ (по тегу GitHub сам собирает релиз).
#
# Папка клона нужна только для публикации: запускайте NORMA из распакованного релиза, а не из клона.
#
# Параметры:
#   -SyncOnly  только скопировать файлы и проверить, без git (дальше Commit и Push в GitHub Desktop)
#   -NoTag     не ставить тег (релиз не соберётся)
#   -Yes       не спрашивать подтверждение
param(
    [Parameter(Mandatory = $true)][string]$Repo,
    [switch]$SyncOnly,
    [switch]$NoTag,
    [switch]$Yes
)

function Fail([string]$Message) {
    Write-Host $Message -ForegroundColor Red
    exit 1
}

# Ищет git: в PATH, в стандартной установке и в GitHub Desktop
function Find-Git {
    $c = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("$env:ProgramFiles\Git\cmd\git.exe", "${env:ProgramFiles(x86)}\Git\cmd\git.exe", "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe")) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    $gd = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA "GitHubDesktop") -Filter "git.exe" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\cmd\\git\.exe$' } | Select-Object -First 1
    if ($gd) { return $gd.FullName }
    return ""
}

$src = (Split-Path -Parent $PSScriptRoot).TrimEnd('\')
if (-not (Test-Path -LiteralPath $Repo)) { Fail "Папка репозитория не найдена: $Repo" }
$repoPath = (Resolve-Path -LiteralPath $Repo).Path.TrimEnd('\')

# защита от неверного пути: зеркальное копирование удаляет в целевой папке всё лишнее
if (-not (Test-Path (Join-Path $repoPath ".git"))) { Fail "В папке $repoPath нет .git: это не клон репозитория." }
if (-not (Test-Path (Join-Path $repoPath "NORMA.bat"))) { Fail "В папке $repoPath нет NORMA.bat: это не клон NORMA. Проверьте путь." }

$verFile = Join-Path $src "VERSION"
if (-not (Test-Path $verFile)) { Fail "В новой папке нет файла VERSION. Запускайте скрипт из распакованного архива NORMA." }
$ver = ([IO.File]::ReadAllText($verFile)).Trim()
$clog = Join-Path $src "CHANGELOG.md"
$top = ""
if (Test-Path $clog) {
    $m = Select-String -Path $clog -Pattern '^## (\S+)' | Select-Object -First 1
    if ($m) { $top = $m.Matches[0].Groups[1].Value }
}
if ($top -ne $ver) { Fail "VERSION ($ver) и верхняя запись CHANGELOG.md ($top) не совпадают." }

Write-Host ("Публикация NORMA {0}" -f $ver) -ForegroundColor Cyan
Write-Host ("  из:  {0}" -f $src)
Write-Host ("  в:   {0}" -f $repoPath)

# 1) копирование
if ($src -ne $repoPath) {
    robocopy $src $repoPath /MIR /XD .git /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Fail ("Не удалось скопировать файлы (robocopy, код {0})." -f $LASTEXITCODE) }
    Write-Host "Файлы скопированы." -ForegroundColor Green
} else {
    Write-Host "Скрипт запущен из самого клона: копирование пропущено."
}

# 2) самопроверка
Write-Host "Самопроверка..." -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoPath "tools\selftest.ps1")
if ($LASTEXITCODE -ne 0) { Fail "Самопроверка не прошла. Публикация остановлена." }

# 3) git
$git = Find-Git
if ($SyncOnly -or -not $git) {
    if (-not $git -and -not $SyncOnly) { Write-Host "git не найден." -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Файлы в клоне обновлены. Дальше вручную:" -ForegroundColor Cyan
    Write-Host "  1. GitHub Desktop: проверьте изменения, Commit to main, затем Push origin."
    Write-Host ("  2. GitHub, Releases, Draft a new release: тег v{0} (Create new tag on publish), Publish release." -f $ver)
    exit 0
}

Set-Location -LiteralPath $repoPath
& $git add -A
$changes = @(& $git status --short)
if ($changes.Count -eq 0) {
    Write-Host "Изменений нет, публиковать нечего." -ForegroundColor Green
    exit 0
}
Write-Host ""
Write-Host ("Изменено файлов: {0}" -f $changes.Count) -ForegroundColor Cyan
$changes | Select-Object -First 30 | ForEach-Object { Write-Host ("  " + $_) }
if ($changes.Count -gt 30) { Write-Host ("  ... и ещё {0}" -f ($changes.Count - 30)) }

if (-not $Yes) {
    Write-Host ""
    $a = Read-Host ("Отправить NORMA {0} на GitHub? (д/н)" -f $ver)
    if ($a -notmatch '^[дДyY]') { Write-Host "Отменено. Файлы в клоне обновлены, но ничего не отправлено."; exit 0 }
}

& $git commit -m ("NORMA {0}" -f $ver)
if ($LASTEXITCODE -ne 0) { Fail "git commit не удался (возможно, не настроены имя и почта: git config user.name, git config user.email)." }
& $git push
if ($LASTEXITCODE -ne 0) { Fail "git push не удался. Проверьте вход в GitHub и интернет." }

if (-not $NoTag) {
    $tag = "v" + $ver
    $exists = @(& $git tag -l $tag)
    if ($exists.Count -gt 0) {
        Write-Host ("Тег {0} уже существует: релиз не создаётся. Повысьте номер в VERSION и CHANGELOG.md." -f $tag) -ForegroundColor Yellow
    } else {
        & $git tag $tag
        & $git push origin $tag
        if ($LASTEXITCODE -ne 0) { Fail "Не удалось отправить тег." }
        Write-Host ("Тег {0} отправлен: GitHub соберёт релиз (вкладка Actions, затем Releases)." -f $tag) -ForegroundColor Green
    }
}
Write-Host "Готово." -ForegroundColor Green
