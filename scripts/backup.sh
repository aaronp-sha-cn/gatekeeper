#!/bin/bash
# ============================================================
# GateKeeper - Database Backup Script
# Backs up SQLite database with timestamp, keeps last 7 days
# Usage: ./backup.sh
# Cron example: 0 2 * * * /opt/gatekeeper/scripts/backup.sh
# ============================================================

set -euo pipefail

# Configuration
DB_DRIVER="${GK_DB_DRIVER:-sqlite}"
DB_PATH="${GK_DB_PATH:-/opt/gatekeeper/data/gatekeeper.db}"
DB_URL="${GK_DB_URL:-}"
BACKUP_DIR="${GK_BACKUP_DIR:-/opt/gatekeeper/backups}"
KEEP_DAYS=7
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_PREFIX="[backup]"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Create backup based on database driver
echo "${LOG_PREFIX} Starting database backup..."

if [ "$DB_DRIVER" = "postgresql" ]; then
    # PostgreSQL backup using pg_dump
    if [ -z "$DB_URL" ]; then
        echo "${LOG_PREFIX} ERROR: GK_DB_URL not set for PostgreSQL backup" >&2
        exit 1
    fi
    BACKUP_FILE="${BACKUP_DIR}/gatekeeper_${TIMESTAMP}.sql.gz"
    pg_dump "$DB_URL" | gzip > "$BACKUP_FILE"
    if [ $? -ne 0 ]; then
        echo "${LOG_PREFIX} ERROR: pg_dump failed" >&2
        exit 1
    fi
else
    # SQLite backup
    BACKUP_FILE="${BACKUP_DIR}/gatekeeper_${TIMESTAMP}.db.gz"

    # Check if database file exists
    if [ ! -f "$DB_PATH" ]; then
        echo "${LOG_PREFIX} ERROR: Database file not found: ${DB_PATH}" >&2
        exit 1
    fi

    # Create backup using sqlite3 .backup command (safe online backup)
    TEMP_BACKUP="${BACKUP_DIR}/gatekeeper_${TIMESTAMP}.db.tmp"

    if command -v sqlite3 &>/dev/null; then
        # Use sqlite3 .backup for safe online backup
        sqlite3 "$DB_PATH" ".backup '${TEMP_BACKUP}'"
        if [ $? -ne 0 ]; then
            echo "${LOG_PREFIX} ERROR: sqlite3 backup failed, falling back to cp" >&2
            cp "$DB_PATH" "$TEMP_BACKUP"
        fi
    else
        # Fallback to direct copy
        cp "$DB_PATH" "$TEMP_BACKUP"
    fi

    # Compress the backup
    gzip -f "$TEMP_BACKUP"
fi

if [ -f "$BACKUP_FILE" ]; then
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "${LOG_PREFIX} Backup created: ${BACKUP_FILE} (${BACKUP_SIZE})"
else
    echo "${LOG_PREFIX} ERROR: Backup file was not created" >&2
    exit 1
fi

# Clean up old backups (keep last KEEP_DAYS daily backups)
DELETED_COUNT=0
while IFS= read -r -d '' old_file; do
    rm -f "$old_file"
    echo "${LOG_PREFIX} Removed old backup: ${old_file}"
    DELETED_COUNT=$((DELETED_COUNT + 1))
done < <(find "$BACKUP_DIR" \( -name "gatekeeper_*.db.gz" -o -name "gatekeeper_*.sql.gz" \) -type f -mtime +${KEEP_DAYS} -print0)

echo "${LOG_PREFIX} Backup completed successfully"
echo "${LOG_PREFIX} Current backups:"
ls -lh "${BACKUP_DIR}"/gatekeeper_*.gz 2>/dev/null || echo "${LOG_PREFIX}  (no backups found)"
