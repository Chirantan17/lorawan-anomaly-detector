Write-Host "🛡️ Running Multi-Attack Benchmark Suite..." -ForegroundColor Green
Set-Location "$PSScriptRoot\01_pipeline_core"
python benchmark_eval.py
