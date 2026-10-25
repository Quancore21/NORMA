# NORMA: запуск фонового режима. Этот файл запускает задача планировщика (автозапуск) и пункт меню «Фоновый режим».
# Параметр -WaitPid: подождать завершения указанного процесса (при перезапуске после обновления NORMA).
param([int]$WaitPid = 0)

$root = Split-Path -Parent $PSScriptRoot
$env:NORMA_DIR = $root
$env:NORMA_MODE = "background"

if ($WaitPid -gt 0) {
    try {
        $p = Get-Process -Id $WaitPid -ErrorAction Stop
        [void]$p.WaitForExit(60000)
    } catch { }
}

# Основной скрипт читается явно как UTF-8, как и в NORMA.bat
$text = [IO.File]::ReadAllText((Join-Path $root "app\norma.ps1"), [Text.Encoding]::UTF8)
& ([ScriptBlock]::Create($text))
