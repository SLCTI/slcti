# Usage: .\bin\deploy.ps1 [-Database]
# Commits and pushes the code, then deploys it on the server with .env.production as its .env.
# The server comes from SLCTI_DEPLOY_* in the local .env; the settings and the database never go through Git: they are copied with scp.

param(
    # Also replace the production database with the local one (otherwise it is only sent when the server has none)
    [switch]$Database
)

$ErrorActionPreference = "Stop"

# -------- Variables --------
$MESSAGE      = "Automated deployment"
$MAX_ATTEMPTS = 10
$SECONDS      = 1

$REMOTE = "origin"
$BRANCH = "main"

$ENV_FILE = ".env.production" # Sent as .env
$DB_FILE  = "private/slcti.db"

# Native commands do not stop the script when they fail, even with $ErrorActionPreference = "Stop"
function Assert-Success($Message) {
    if ($LASTEXITCODE -ne 0) {
        throw $Message
    }
}

Set-Location (Split-Path $PSScriptRoot -Parent)

# -------- Server (SLCTI_DEPLOY_* in the local .env, see .env.example) --------
if (-not (Test-Path .env)) {
    throw ".env is missing (see .env.example)"
}

$Local = @{}

foreach ($Line in Get-Content .env) {
    if ($Line -match '^\s*(SLCTI_DEPLOY_\w+)\s*=\s*(.*?)\s*$') {
        $Local[$Matches[1]] = $Matches[2]
    }
}

foreach ($Name in 'SLCTI_DEPLOY_USER', 'SLCTI_DEPLOY_HOST', 'SLCTI_DEPLOY_DIR', 'SLCTI_DEPLOY_SERVICE') {
    if (-not $Local[$Name]) {
        throw "$Name is missing from .env (see .env.example)"
    }
}

$APP_DIR = $Local.SLCTI_DEPLOY_DIR
$SERVICE = $Local.SLCTI_DEPLOY_SERVICE
$SERVER  = "$($Local.SLCTI_DEPLOY_USER)@$($Local.SLCTI_DEPLOY_HOST)"

# -------- Checks --------
if (-not (Test-Path $ENV_FILE)) {
    throw "$ENV_FILE is missing (see .env.example)"
}

$Settings = Get-Content $ENV_FILE

foreach ($Required in '^NODE_ENV=production\s*$', '^SLCTI_CERTIFICATES=\S', '^SLCTI_DATABASE_KEY=\S') {
    if (-not ($Settings -match $Required)) {
        throw "$ENV_FILE must match $Required (see .env.example)"
    }
}

# The production database comes back to the local one at the end: both must use the same key
$Key = { param($File) (Get-Content $File | Where-Object { $_ -match '^SLCTI_DATABASE_KEY=' } | Select-Object -First 1) -replace '\s+$', '' }

if ((& $Key .env) -ne (& $Key $ENV_FILE)) {
    throw "SLCTI_DATABASE_KEY must be the same in .env and $ENV_FILE"
}

# -------- Local Git --------
Write-Host "Committing changes..."

git add .
Assert-Success "git add failed"

# Settings, data and certificates are ignored by Git; never commit one that slipped through anyway
$Private = git diff --cached --name-only --diff-filter=d | Where-Object {
    $_ -ne '.env.example' -and $_ -match '(^|/)\.env(\.|$)|^private/|(^|/)config\.json$|\.(db|db-wal|db-shm|sqlite3?|xlsx?|xlsm|pem|key)$'
}

if ($Private) {
    git reset -q -- $Private
    throw "Refusing to commit private files: $($Private -join ', ')"
}

if (git status --porcelain) {
    git commit -m $MESSAGE
    Assert-Success "git commit failed"
}

else {
    Write-Host "No changes to commit"
}

git push $REMOTE $BRANCH
Assert-Success "git push failed"

$LocalCommit = git rev-parse HEAD

# -------- Wait for Remote --------
Write-Host "Waiting for remote update..."

$Attempt = 0
do {
    Start-Sleep -Seconds $SECONDS
    $RemoteCommit = (git ls-remote $REMOTE "refs/heads/$BRANCH").Split("`t")[0]
    $Attempt++
} while ($RemoteCommit -ne $LocalCommit -and $Attempt -lt $MAX_ATTEMPTS)

if ($RemoteCommit -ne $LocalCommit) {
    throw "Remote did not update"
}

Write-Host "Remote updated"

# -------- Settings and Database (never through Git) --------
$Exists = ssh $SERVER "test -f $APP_DIR/$DB_FILE && echo yes || echo no"
Assert-Success "Cannot reach $SERVER"

$SendDatabase = $Database -or $Exists -ne "yes"

if ($Database -and $Exists -eq "yes") {
    $Answer = Read-Host "This replaces the production data with the local database (production is backed up first). Type yes to continue"

    if ($Answer -ne "yes") {
        throw "Deployment cancelled"
    }
}

ssh $SERVER "mkdir -p $APP_DIR/private && chmod 700 $APP_DIR/private"
Assert-Success "Cannot create the private folder on the server"

Write-Host "Sending $ENV_FILE..."
scp -q $ENV_FILE "${SERVER}:$APP_DIR/private/env.upload"
Assert-Success "Cannot send $ENV_FILE"

if ($SendDatabase) {
    # A consistent copy, even while the local server is running
    $Snapshot = (node src/backup_db.js) -replace '^Backup written to ', ''
    Assert-Success "Cannot back up the local database"

    Write-Host "Sending the database..."
    scp -q $Snapshot "${SERVER}:$APP_DIR/private/slcti.db.upload"
    Assert-Success "Cannot send the database"
}

# -------- Remote Deploy --------
Write-Host "Deploying on server..."

# No double quotes in this script: Windows PowerShell does not pass them to ssh correctly
$Script = @'
set -e
cd __APP_DIR__

# Never leave an upload behind, where a later deployment could apply it
trap 'rm -f private/env.upload private/slcti.db.upload' EXIT

sed -i 's/\r$//' private/env.upload
grep -q '^NODE_ENV=production' private/env.upload || { echo The settings are not a production configuration; exit 1; }

echo Updating code...
git fetch origin
git reset --hard origin/main

# Stop before the restart when the server Node.js is too old for a package (better-sqlite3-multiple-ciphers needs 22+)
echo Installing dependencies...
npm install --engine-strict

echo Cleaning build artifacts...
rm -rf .next .cache dist tmp

mkdir -p private/backups
chmod 700 private private/backups

stamp=$(date +%F-%H%M%S)

# The settings come first: the code that was just installed reads them, also to back up the database below
echo Updating settings...
if [ -f .env ]; then cp .env private/backups/slcti-$stamp.env && chmod 600 private/backups/slcti-$stamp.env; fi
mv private/env.upload .env
chmod 600 .env
rm -f config.json

if [ __SEND_DATABASE__ = 1 ]; then
    if [ -f private/slcti.db ]; then
        echo Backing up the production database...
        node src/backup_db.js private/backups/slcti-$stamp.db
        chmod 600 private/backups/slcti-$stamp.db
    fi

    echo Replacing the production database...
    # The service keeps its open files until the restart; the WAL files of the old database must not be applied to the new one
    rm -f private/slcti.db-wal private/slcti.db-shm
    mv private/slcti.db.upload private/slcti.db
    chmod 600 private/slcti.db
fi

echo Restarting service...
sudo systemctl daemon-reload
sudo systemctl restart __SERVICE__

# A crashing service looks active between its automatic restarts: wait until the site answers instead
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    sleep 2
    if curl -sk -o /dev/null --max-time 3 https://localhost:3000/; then
        systemctl status __SERVICE__ --no-pager
        exit 0
    fi
done

systemctl status __SERVICE__ --no-pager || true
journalctl -u __SERVICE__ -n 20 --no-pager || true
echo The site does not answer on https://localhost:3000/
exit 1
'@

$Script = $Script.Replace("__APP_DIR__", $APP_DIR).Replace("__SERVICE__", $SERVICE).Replace("__SEND_DATABASE__", [int][bool]$SendDatabase).Replace("`r", "")

ssh $SERVER $Script
Assert-Success "Deployment failed on the server"

Write-Host "Deployment complete"

# -------- Production Database to Local --------
# Production holds the reference data: a copy of it is kept in private/backups, and it replaces the local data
# (backed up first), so the local work is always on current data. Not needed when the local database was just sent.
if (-not $SendDatabase) {
    Write-Host "Copying the production database to the local one..."

    $Copy = "private/backups/slcti-production-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').db"

    ssh $SERVER "cd $APP_DIR && node src/backup_db.js private/download.db"
    Assert-Success "Cannot back up the production database"

    scp -q "${SERVER}:$APP_DIR/private/download.db" $Copy
    Assert-Success "Cannot copy the production database"

    ssh $SERVER "rm -f $APP_DIR/private/download.db"

    node src/restore_db.js $Copy
    Assert-Success "Cannot replace the local data (the production copy is in $Copy)"
}
