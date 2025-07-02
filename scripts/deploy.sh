#!/bin/bash

# SecuNik LogX - Production Deployment Script
# This script prepares and deploys the application for local production use

set -e  # Exit on error

echo "================================================"
echo "SecuNik LogX - Production Deployment"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        echo -e "${RED}Node.js is not installed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Node.js $(node --version)${NC}"
    
    # Check .NET
    if ! command -v dotnet &> /dev/null; then
        echo -e "${RED}.NET SDK is not installed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ .NET $(dotnet --version)${NC}"
    
    # Check SQLite
    if ! command -v sqlite3 &> /dev/null; then
        echo -e "${RED}SQLite is not installed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ SQLite $(sqlite3 --version)${NC}"
}

# Build frontend
build_frontend() {
    echo -e "\n${YELLOW}Building frontend...${NC}"
    cd frontend
    
    # Install dependencies
    echo "Installing dependencies..."
    npm ci --silent
    
    # Run tests
    echo "Running frontend tests..."
    npm test -- --run --silent
    
    # Build production bundle
    echo "Building production bundle..."
    npm run build
    
    echo -e "${GREEN}✓ Frontend build complete${NC}"
    cd ..
}

# Build backend
build_backend() {
    echo -e "\n${YELLOW}Building backend...${NC}"
    cd backend
    
    # Restore packages
    echo "Restoring NuGet packages..."
    dotnet restore
    
    # Run tests
    echo "Running backend tests..."
    dotnet test --no-restore --verbosity quiet
    
    # Build release
    echo "Building release configuration..."
    dotnet build -c Release --no-restore
    
    # Publish
    echo "Publishing backend..."
    dotnet publish -c Release -o ./publish --no-build
    
    echo -e "${GREEN}✓ Backend build complete${NC}"
    cd ..
}

# Setup environment
setup_environment() {
    echo -e "\n${YELLOW}Setting up environment...${NC}"
    
    # Create required directories
    mkdir -p ./data
    mkdir -p ./logs
    mkdir -p ./uploads
    mkdir -p ./evidence
    mkdir -p ./quarantine
    mkdir -p ./temp
    mkdir -p ./reports
    mkdir -p ./plugins
    mkdir -p ./backups
    
    # Set permissions
    chmod 755 ./data ./logs ./uploads ./evidence ./quarantine ./temp ./reports ./plugins ./backups
    
    # Create production config
    if [ ! -f .env.production ]; then
        cp .env.example .env.production
        echo -e "${YELLOW}Created .env.production - Please update with production values${NC}"
    fi
    
    # Initialize database
    echo "Initializing database..."
    cd backend
    dotnet ef database update -c ApplicationDbContext
    cd ..
    
    echo -e "${GREEN}✓ Environment setup complete${NC}"
}

# Create systemd service (Linux)
create_service() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo -e "\n${YELLOW}Creating systemd service...${NC}"
        
        cat > secunik-logx.service << EOF
[Unit]
Description=SecuNik LogX Forensics Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)/backend/publish
ExecStart=/usr/bin/dotnet $(pwd)/backend/publish/SecuNikLogX.API.dll
Restart=always
RestartSec=10
KillSignal=SIGINT
SyslogIdentifier=secunik-logx
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=DOTNET_PRINT_TELEMETRY_MESSAGE=false

[Install]
WantedBy=multi-user.target
EOF

        echo -e "${YELLOW}Service file created. To install:${NC}"
        echo "sudo cp secunik-logx.service /etc/systemd/system/"
        echo "sudo systemctl daemon-reload"
        echo "sudo systemctl enable secunik-logx"
        echo "sudo systemctl start secunik-logx"
    fi
}

# Create Docker files
create_docker_files() {
    echo -e "\n${YELLOW}Creating Docker configuration...${NC}"
    
    # Backend Dockerfile
    cat > backend/Dockerfile << 'EOF'
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 5000

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["API/SecuNikLogX.API.csproj", "API/"]
COPY ["Core/SecuNikLogX.Core.csproj", "Core/"]
RUN dotnet restore "API/SecuNikLogX.API.csproj"
COPY . .
WORKDIR "/src/API"
RUN dotnet build "SecuNikLogX.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "SecuNikLogX.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SecuNikLogX.API.dll"]
EOF

    # Frontend Dockerfile
    cat > frontend/Dockerfile << 'EOF'
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
EOF

    # Docker Compose
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "5000:5000"
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - DATABASE_PATH=/app/data/secunik.db
    volumes:
      - ./data:/app/data
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - frontend
      - backend
    restart: unless-stopped
EOF

    echo -e "${GREEN}✓ Docker files created${NC}"
}

# Performance optimization
optimize_deployment() {
    echo -e "\n${YELLOW}Optimizing deployment...${NC}"
    
    # Frontend optimization
    cd frontend/dist
    
    # Compress assets
    find . -type f \( -name "*.js" -o -name "*.css" -o -name "*.html" \) -exec gzip -k {} \;
    
    cd ../..
    
    # Backend optimization
    cd backend/publish
    
    # Create app settings for production
    cat > appsettings.Production.json << 'EOF'
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "Kestrel": {
    "Limits": {
      "MaxRequestBodySize": 104857600,
      "KeepAliveTimeout": "00:02:00"
    }
  },
  "ResponseCompression": {
    "EnableForHttps": true
  }
}
EOF
    
    cd ../..
    
    echo -e "${GREEN}✓ Optimization complete${NC}"
}

# Health check
health_check() {
    echo -e "\n${YELLOW}Running health checks...${NC}"
    
    # Check backend
    if curl -f http://localhost:5000/health &> /dev/null; then
        echo -e "${GREEN}✓ Backend is healthy${NC}"
    else
        echo -e "${RED}✗ Backend health check failed${NC}"
    fi
    
    # Check frontend
    if curl -f http://localhost:80 &> /dev/null; then
        echo -e "${GREEN}✓ Frontend is accessible${NC}"
    else
        echo -e "${RED}✗ Frontend not accessible${NC}"
    fi
}

# Main deployment process
main() {
    echo "Starting deployment process..."
    
    check_prerequisites
    build_frontend
    build_backend
    setup_environment
    create_service
    create_docker_files
    optimize_deployment
    
    echo -e "\n${GREEN}================================================${NC}"
    echo -e "${GREEN}Deployment complete!${NC}"
    echo -e "${GREEN}================================================${NC}"
    
    echo -e "\nNext steps:"
    echo "1. Update .env.production with your configuration"
    echo "2. Start the application:"
    echo "   - Development: npm run dev (frontend) & dotnet run (backend)"
    echo "   - Production: Use systemd service or Docker Compose"
    echo "3. Access the application at http://localhost"
    
    echo -e "\nFor Docker deployment:"
    echo "docker-compose up -d"
    
    echo -e "\nFor systemd deployment (Linux):"
    echo "sudo systemctl start secunik-logx"
}

# Run main function
main