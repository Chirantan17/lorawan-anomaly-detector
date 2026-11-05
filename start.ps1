Write-Host "🚀 Launching LoRaWAN Real-Time Security Engine..." -ForegroundColor Cyan
Set-Location "$PSScriptRoot\01_pipeline_core"
python server.py
