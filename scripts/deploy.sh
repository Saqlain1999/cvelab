#!/bin/bash

# ================================
# CVE Lab Platform - Deployment Script
# ================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}CVE Lab Platform - Deployment${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}Warning: .env file not found!${NC}"
    echo "Creating .env from .env.docker..."
    cp .env.docker .env
    echo -e "${RED}IMPORTANT: Edit .env and update passwords and secrets before deploying to production!${NC}"
    echo ""
    read -p "Press enter to continue or Ctrl+C to abort..."
fi

# Check Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}Step 1: Building Docker images...${NC}"
docker-compose build --no-cache

echo ""
echo -e "${GREEN}Step 2: Starting services...${NC}"
docker-compose up -d

echo ""
echo -e "${GREEN}Step 3: Waiting for services to be healthy...${NC}"
sleep 10

# Check database health
echo "Checking PostgreSQL..."
until docker-compose exec -T db pg_isready -U cveuser &> /dev/null; do
    echo "Waiting for PostgreSQL..."
    sleep 2
done
echo -e "${GREEN}✓ PostgreSQL is ready${NC}"

# Check Redis health
echo "Checking Redis..."
until docker-compose exec -T redis redis-cli -a redispass ping &> /dev/null 2>&1; do
    echo "Waiting for Redis..."
    sleep 2
done
echo -e "${GREEN}✓ Redis is ready${NC}"

# Check app health
echo "Checking application..."
until docker-compose exec -T app wget --spider -q http://localhost:5000/api/cves &> /dev/null; do
    echo "Waiting for application..."
    sleep 2
done
echo -e "${GREEN}✓ Application is ready${NC}"

echo ""
echo -e "${GREEN}Step 4: Deploying database schema...${NC}"
docker-compose exec -T app npm run db:push

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "Application: ${GREEN}http://localhost:5000${NC}"
echo -e "Database: ${GREEN}localhost:5432${NC}"
echo -e "Redis: ${GREEN}localhost:6379${NC}"
echo ""
echo -e "View logs: ${YELLOW}docker-compose logs -f${NC}"
echo -e "Stop services: ${YELLOW}docker-compose down${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Open http://localhost:5000 in your browser"
echo "2. Configure API keys in Settings"
echo "3. Run your first CVE scan!"
echo ""
