# NORMA: выгружает драйвер WinDivert из системы (если он остался загружен после лаборатории).
Write-Host "Останавливаю службу драйвера WinDivert..."
& sc.exe stop WinDivert 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "Удаляю регистрацию службы (драйвер сам загрузится снова при следующем запуске лаборатории)..."
& sc.exe delete WinDivert 2>&1 | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "Если написано, что службы нет, значит драйвер уже выгружен." -ForegroundColor Green
