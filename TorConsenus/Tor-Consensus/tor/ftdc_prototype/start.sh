#!/bin/bash
# ============================================
# TOR-Unveil FTDC - Production Startup Script
# ============================================
# Usage: ./start.sh [development|production]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default environment
ENV="${1:-development}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  TOR-Unveil FTDC - Startup Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Load environment variables from .env if exists
if [ -f ".env" ]; then
    echo -e "${GREEN}Loading environment from .env file...${NC}"
    export $(grep -v '^#' .env | xargs)
fi

# Set defaults
export PORT="${PORT:-5007}"
export HOST="${HOST:-0.0.0.0}"
export WORKERS="${WORKERS:-4}"
export THREADS="${THREADS:-2}"

# Create required directories
echo -e "${YELLOW}Creating required directories...${NC}"
mkdir -p ftdc/uploads ftdc/results ftdc/models logs

# Function to check if Python virtual environment exists
check_venv() {
    if [ -d "../../.venv" ]; then
        echo -e "${GREEN}Found virtual environment${NC}"
        source "../../.venv/bin/activate"
        return 0
    elif [ -d ".venv" ]; then
        echo -e "${GREEN}Found local virtual environment${NC}"
        source ".venv/bin/activate"
        return 0
    else
        echo -e "${YELLOW}No virtual environment found, using system Python${NC}"
        return 1
    fi
}

# Function to install dependencies
install_deps() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r requirements.txt
}

# Function to start development server
start_dev() {
    echo -e \"${GREEN}Starting Streamlit dashboard on http://${HOST}:${PORT}${NC}\"
    echo \"\"
    streamlit run dashboard/main.py --server.address \"$HOST\" --server.port \"$PORT\"
}

# Function to start production server
start_prod() {
    echo -e \"${GREEN}Starting production Streamlit dashboard on http://${HOST}:${PORT}${NC}\"
    echo \"\"
    
    streamlit run dashboard/main.py \
        --server.address \"$HOST\" \
        --server.port \"$PORT\" \
        --server.headless true \
        --browser.gatherUsageStats false
}

# Function to start with Docker
start_docker() {
    echo -e "${GREEN}Starting with Docker Compose...${NC}"
    
    if [ ! -f "docker-compose.yml" ]; then
        echo -e "${RED}docker-compose.yml not found!${NC}"
        exit 1
    fi
    
    docker-compose up -d --build
    echo ""
    echo -e "${GREEN}Container started! Check status with: docker-compose ps${NC}"
    echo -e "${GREEN}View logs with: docker-compose logs -f${NC}"
}

# Main
case "$ENV" in
    development|dev)
        check_venv
        install_deps
        start_dev
        ;;
    production|prod)
        check_venv
        install_deps
        start_prod
        ;;
    docker)
        start_docker
        ;;
    install)
        check_venv
        install_deps
        echo -e "${GREEN}Dependencies installed successfully!${NC}"
        ;;
    *)
        echo "Usage: $0 [development|production|docker|install]"
        echo ""
        echo "  development  - Start Streamlit dashboard in development mode"
        echo "  production   - Start Streamlit dashboard in production mode"
        echo "  docker       - Start with Docker Compose"
        echo "  install      - Install dependencies only"
        exit 1
        ;;
esac
