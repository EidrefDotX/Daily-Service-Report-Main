# PostgreSQL Setup Script for DSR Backend
Write-Host "========================================"
Write-Host "PostgreSQL Integration Setup"
Write-Host "========================================"
Write-Host ""

# Check if .env file exists
$envPath = ".env"
if (-not (Test-Path $envPath)) {
    Write-Host "Creating .env file from env.example..."
    Copy-Item "env.example" $envPath
}

# Read current .env content
$envContent = Get-Content $envPath -Raw

# Ask for PostgreSQL credentials
Write-Host "Please provide your PostgreSQL connection details:"
Write-Host ""

$pgUsername = Read-Host "PostgreSQL Username (default: postgres)"
if ([string]::IsNullOrWhiteSpace($pgUsername)) {
    $pgUsername = "postgres"
}

$pgPassword = Read-Host "PostgreSQL Password" -AsSecureString
$pgPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pgPassword))

$pgHost = Read-Host "PostgreSQL Host (default: 127.0.0.1)"
if ([string]::IsNullOrWhiteSpace($pgHost)) {
    $pgHost = "127.0.0.1"
}

$pgPort = Read-Host "PostgreSQL Port (default: 5432)"
if ([string]::IsNullOrWhiteSpace($pgPort)) {
    $pgPort = "5432"
}

$pgDatabase = Read-Host "Database Name (default: dsr)"
if ([string]::IsNullOrWhiteSpace($pgDatabase)) {
    $pgDatabase = "dsr"
}

# Build DATABASE_URL
$databaseUrl = "postgresql+psycopg2://${pgUsername}:${pgPasswordPlain}@${pgHost}:${pgPort}/${pgDatabase}"

# Update .env file
Write-Host ""
Write-Host "Updating .env file..."

# Uncomment or update DATABASE_URL line
if ($envContent -match "#\s*DATABASE_URL=") {
    # Uncomment existing line
    $envContent = $envContent -replace "#\s*DATABASE_URL=.*", "DATABASE_URL=$databaseUrl"
} elseif ($envContent -match "DATABASE_URL=") {
    # Update existing line
    $envContent = $envContent -replace "DATABASE_URL=.*", "DATABASE_URL=$databaseUrl"
} else {
    # Add new line after DATABASE section comment
    $envContent = $envContent -replace "(# DATABASE\s*\r?\n)", "`$1DATABASE_URL=$databaseUrl`r`n"
}

# Save updated .env
Set-Content -Path $envPath -Value $envContent -NoNewline

Write-Host "✓ .env file updated with PostgreSQL connection string"
Write-Host ""

# Test PostgreSQL connection
Write-Host "Testing PostgreSQL connection..."
try {
    python -c @"
import psycopg2
try:
    conn = psycopg2.connect(
        host='$pgHost',
        port=$pgPort,
        user='$pgUsername',
        password='$pgPasswordPlain',
        database='postgres'  # Connect to default database first
    )
    conn.close()
    print('✓ PostgreSQL connection successful!')
    
    # Try to create database if it doesn't exist
    conn = psycopg2.connect(
        host='$pgHost',
        port=$pgPort,
        user='$pgUsername',
        password='$pgPasswordPlain',
        database='postgres'
    )
    conn.autocommit = True
    cursor = conn.cursor()
    cursor.execute(\"SELECT 1 FROM pg_database WHERE datname='$pgDatabase'\")
    if not cursor.fetchone():
        print(f'Creating database: $pgDatabase')
        cursor.execute(f\"CREATE DATABASE $pgDatabase\")
        print(f'✓ Database \"$pgDatabase\" created successfully!')
    else:
        print(f'✓ Database \"$pgDatabase\" already exists')
    cursor.close()
    conn.close()
except psycopg2.OperationalError as e:
    print(f'✗ PostgreSQL connection failed: {e}')
    print('Please make sure PostgreSQL is running and credentials are correct.')
except Exception as e:
    print(f'✗ Error: {e}')
"@
} catch {
    Write-Host "✗ Error testing connection: $_"
}

Write-Host ""
Write-Host "========================================"
Write-Host "Setup Complete!"
Write-Host "========================================"
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Restart the backend server"
Write-Host "2. The app will automatically create tables in PostgreSQL"
Write-Host ""

