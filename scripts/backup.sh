#!/bin/bash

# ================================
# CVE Lab Platform - Backup Script
# ================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Create backup directory if it doesn't exist
mkdir -p backups

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backups/cvelab_backup_${TIMESTAMP}.sql.gz"

echo -e "${GREEN}Creating database backup...${NC}"
echo "Backup file: ${BACKUP_FILE}"

# Create compressed backup
docker-compose exec -T db pg_dump -U cveuser cve_lab_db | gzip > "${BACKUP_FILE}"

# Get file size
SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)

echo -e "${GREEN}✓ Backup complete!${NC}"
echo "Size: ${SIZE}"
echo "Location: ${BACKUP_FILE}"

# Optional: Keep only last 7 backups
BACKUP_COUNT=$(ls -1 backups/cvelab_backup_*.sql.gz 2>/dev/null | wc -l)
if [ "${BACKUP_COUNT}" -gt 7 ]; then
    echo -e "${YELLOW}Removing old backups (keeping last 7)...${NC}"
    ls -1t backups/cvelab_backup_*.sql.gz | tail -n +8 | xargs rm -f
fi

echo ""
echo -e "${YELLOW}To restore this backup:${NC}"
echo "gunzip < ${BACKUP_FILE} | docker-compose exec -T db psql -U cveuser cve_lab_db"
