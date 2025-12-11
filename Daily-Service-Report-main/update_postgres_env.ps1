# Quick script to update .env with PostgreSQL settings (port 5433)
param(
    [string]$Password = "postgres"
)

$envFile = ".env"
Write-Host "Updating .env file for PostgreSQL..."
Write-Host "Using port 5433 (detected from PostgreSQL configuration)"
Write-Host ""

# Read .env content
if (Test-Path $envFile) {
    $content = Get-Content $envFile -Raw
    
    # Update DATABASE_URL - uncomment and set correct port
    $newUrl = "DATABASE_URL=postgresql+psycopg2://postgres:$Password@127.0.0.1:5433/dsr"
    
    if ($content -match '#\s*DATABASE_URL=') {
        $content = $content -replace '#\s*DATABASE_URL=.*', $newUrl
        Write-Host "Uncommented and updated DATABASE_URL"
    } elseif ($content -match 'DATABASE_URL=') {
        $content = $content -replace 'DATABASE_URL=.*', $newUrl
        Write-Host "Updated existing DATABASE_URL"
    } else {
        # Add after DATABASE comment section
        $content = $content -replace "(# DATABASE\s*\r?\n)", "`$1$newUrl`r`n"
        Write-Host "Added DATABASE_URL"
    }
    
    # Save updated content
    Set-Content -Path $envFile -Value $content -NoNewline
    Write-Host ""
    Write-Host "✓ .env file updated!"
    Write-Host "  Database URL: postgresql+psycopg2://postgres:***@127.0.0.1:5433/dsr"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Create database: python setup_postgres_db.py $Password"
    Write-Host "  2. Restart backend server"
} else {
    Write-Host "Error: .env file not found!"
    Write-Host "Copy env.example to .env first:"
    Write-Host "  Copy-Item env.example .env"
}

