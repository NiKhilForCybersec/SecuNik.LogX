# SecuNik LogX - Digital Forensics Platform

## Project Overview

SecuNik LogX is a professional-grade local-first digital forensics platform designed for comprehensive log analysis, threat detection, and custom parser development. The platform operates entirely on the user's machine without cloud dependencies, ensuring complete data privacy and security for forensics investigations.

### Mission Statement

Build a professional-grade local-first digital forensics tool that provides advanced file analysis capabilities, AI-powered threat intelligence, custom parser development environment, and comprehensive rule management for YARA and Sigma rules with complete local execution and air-gapped operation capability.

### Key Features

- **Advanced File Analysis**: Real-time progress tracking and comprehensive analysis on local machine
- **AI-Powered Insights**: Automated threat intelligence using user's API keys (OpenAI, VirusTotal)
- **Custom Parser Development**: C# scripting environment with local compilation using Roslyn
- **Rule Management**: Complete YARA and Sigma rule management with local execution
- **Local-First Architecture**: Zero cloud dependencies with direct file system access
- **Real-Time Updates**: Live analysis progress and system monitoring
- **Air-Gapped Operation**: Full functionality in secure forensics environments
- **Evidence Processing**: Direct file system access with chain of custody support

## Technology Stack

### Frontend Stack (Local Execution)
- **React**: 18.2.0 with TypeScript 5.2.2 (strict mode)
- **Build Tool**: Vite 4.5.0 for development server and build process
- **Styling**: Tailwind CSS 3.3.5 (utility-first approach)
- **State Management**: Zustand 4.4.7 for local browser state
- **Animations**: Framer Motion 10.16.16 for transitions
- **Icons**: Lucide React 0.294.0 for consistent iconography
- **Code Editor**: Monaco Editor 4.6.0 for C# parser development
- **Visualization**: Recharts 2.8.0 for analytics and data display
- **Routing**: React Router DOM 6.20.1 for local navigation

### Backend Stack (Local Machine)
- **.NET**: 8.0 Web API with modern C# patterns
- **Database**: Entity Framework Core 8.0.0 with SQLite provider
- **Real-Time**: SignalR 8.0.7 for WebSocket communication
- **Code Analysis**: Microsoft.CodeAnalysis.CSharp 4.8.0 (Roslyn)
- **Rule Engine**: YaraSharp 1.3.0 for YARA rule execution
- **Validation**: FluentValidation 11.8.0 for request validation
- **Logging**: Serilog 3.1.0 for structured local logging
- **Storage**: SQLite for local file-based database

### External Integrations (Optional)
- **OpenAI API**: AI-powered analysis and insights (user's API key)
- **VirusTotal API**: Threat intelligence and IOC enrichment (user's API key)

## System Requirements

### Minimum Requirements
- **Node.js**: 18.x or higher (LTS recommended)
- **.NET**: 8.0 SDK
- **Operating System**: Windows 10/11, macOS 10.15+, or Linux (Ubuntu 20.04+)
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 2GB free space for application, additional space for evidence files
- **Ports**: 5173 (frontend), 5000/5001 (backend) available on localhost

### Development Requirements
- **Git**: Latest version for version control
- **Code Editor**: VS Code, Visual Studio 2022, or JetBrains Rider
- **Browser**: Chrome, Firefox, Edge, or Safari (latest versions)

## Local Development Setup

### 1. Repository Setup
```bash
# Clone the repository
git clone <repository-url>
cd SecuNikLogX

# Run automated setup script
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 2. Manual Setup (Alternative)

#### Environment Configuration
```bash
# Copy environment templates
cp .env.example .env
cd frontend && cp ../.env.example .env.local
cd ../backend && cp ../.env.example .env
```

#### Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

#### Backend Setup
```bash
# Navigate to backend directory
cd backend

# Restore NuGet packages
dotnet restore

# Build the solution
dotnet build

# Run the API
dotnet run --project API
```

### 3. Database Initialization
The SQLite database will be automatically created in the `./data/` directory on first run. No additional database setup is required.

### 4. Verification
- Frontend: http://localhost:5173
- Backend API: http://localhost:5000
- Swagger Documentation: http://localhost:5000/swagger

## Project Structure

```
SecuNikLogX/
├── .gitignore                    # Git ignore patterns
├── .env.example                  # Environment variable templates
├── README.md                     # This documentation
├── scripts/
│   ├── setup.sh                  # Automated setup script
│   └── deploy.sh                 # Local deployment script
├── frontend/                     # React TypeScript application
│   ├── package.json              # Frontend dependencies
│   ├── tsconfig.json             # TypeScript configuration
│   ├── vite.config.ts            # Vite build configuration
│   ├── tailwind.config.js        # Tailwind CSS configuration
│   ├── public/                   # Static assets
│   └── src/                      # Source code
├── backend/                      # .NET 8 Web API
│   ├── SecuNikLogX.sln          # Visual Studio solution
│   ├── API/                      # Web API project
│   ├── Core/                     # Business logic and models
│   └── Tests/                    # Unit and integration tests
├── shared/                       # Shared configurations and types
├── data/                         # Local SQLite database files
├── uploads/                      # File upload storage
└── logs/                         # Application log files
```

## Build and Run Instructions

### Development Mode
```bash
# Start both frontend and backend in development mode
npm run dev:all

# Or start individually:
# Frontend only
cd frontend && npm run dev

# Backend only
cd backend && dotnet run --project API
```

### Production Build
```bash
# Build frontend for production
cd frontend && npm run build

# Build backend for release
cd backend && dotnet build --configuration Release

# Preview production build
cd frontend && npm run preview
```

### Testing
```bash
# Run frontend tests
cd frontend && npm run test

# Run backend tests
cd backend && dotnet test

# Run all tests
npm run test:all
```

## Environment Variables

### Frontend Environment Variables (.env.local)
```
VITE_API_URL=http://localhost:5000
VITE_ENVIRONMENT=development
VITE_APP_NAME=SecuNik LogX
VITE_VERSION=1.0.0
```

### Backend Environment Variables (.env)
```
DATABASE_PATH=./data/secunik.db
UPLOAD_PATH=./uploads
LOGS_PATH=./logs
ASPNETCORE_ENVIRONMENT=Development
ASPNETCORE_URLS=http://localhost:5000;https://localhost:5001

# Optional API Keys (for enhanced analysis)
OPENAI_API_KEY=your_openai_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# SignalR Configuration
SIGNALR_ENABLED=true
CORS_ORIGINS=http://localhost:5173

# Security Configuration
JWT_SECRET=your_jwt_secret_here
ENCRYPTION_KEY=your_encryption_key_here
```

## UI Design Compliance

### Design Authority
ALL frontend development must follow the design specifications established in the project knowledge reference files. The design standards are defined by three authoritative components:

- **Layout.tsx**: Main application layout structure and responsive behavior
- **Sidebar.tsx**: Navigation design with forensics-focused menu items
- **Dashboard.tsx**: Dashboard design with quick actions and analytics

### Design Standards (Non-Negotiable)

#### Color Scheme
- **Primary Background**: `bg-slate-950` (dark slate theme)
- **Primary Gradients**: `from-blue-600 to-purple-600` for main elements
- **Accent Colors**: `text-orange-400` for highlights and threat indicators
- **Text Colors**: `text-white` for headings, `text-slate-400` for secondary text
- **Component Backgrounds**: `bg-slate-900/95` with backdrop blur effects

#### Layout Structure
- **Responsive Layout**: Sidebar + Header + Main content area
- **Sidebar**: Fixed width (320px) with collapse functionality on mobile
- **Navigation**: Forensics-focused menu items with status indicators
- **Content Area**: Full-height with proper padding and spacing

#### Typography and Styling
- **Professional Interface**: Technical styling appropriate for digital forensics
- **Forensics Terminology**: "Forensics Dashboard", "Threat Detection", "Evidence Analysis"
- **Animations**: Framer Motion transitions for smooth interactions
- **Accessibility**: Proper contrast ratios and semantic HTML structure

#### Component Design Patterns
- **Cards**: `bg-slate-800/50` with rounded corners and subtle borders
- **Buttons**: Gradient backgrounds with hover effects and proper focus states
- **Form Elements**: Dark theme with blue accent colors and validation states
- **Status Indicators**: Color-coded with animated pulse effects for real-time updates

### Validation Requirements
Every frontend component in future development must:
1. Visually match the established design patterns from reference files
2. Use the exact color scheme and theme specifications
3. Maintain professional forensics-appropriate styling
4. Follow responsive design patterns for mobile and desktop
5. Include proper animations and transitions using Framer Motion

## Local Deployment

### Prerequisites
Ensure all system requirements are met and dependencies are installed according to the setup instructions above.

### Deployment Steps
```bash
# 1. Build the application
npm run build:all

# 2. Configure production environment
cp .env.example .env.production

# 3. Deploy locally
./scripts/deploy.sh

# 4. Start production services
npm run start:production
```

### Production Configuration
- Frontend served from `./frontend/dist` on port 4173
- Backend API running on port 5000 (HTTP) and 5001 (HTTPS)
- SQLite database in `./data/` directory with automatic backups
- Logs written to `./logs/` directory with rotation

## Troubleshooting

### Common Setup Issues

#### Node.js Version Issues
```bash
# Check Node.js version
node --version

# Install correct version using nvm (if available)
nvm install 18
nvm use 18
```

#### Port Conflicts
```bash
# Check if ports are in use
netstat -an | grep :5173
netstat -an | grep :5000

# Kill processes using required ports
npx kill-port 5173 5000
```

#### Permission Issues (macOS/Linux)
```bash
# Fix script permissions
chmod +x scripts/setup.sh
chmod +x scripts/deploy.sh

# Fix npm permissions
sudo chown -R $(whoami) ~/.npm
```

#### Database Access Issues
```bash
# Ensure data directory exists and has proper permissions
mkdir -p data
chmod 755 data

# Remove corrupted database (will be recreated)
rm -f data/secunik.db
```

### Performance Optimization
- Ensure adequate disk space for evidence file processing
- Monitor memory usage during large file analysis
- Use SSD storage for optimal database performance
- Configure antivirus exclusions for application directories

### Security Considerations
- All data processing occurs locally on the investigator's machine
- No cloud dependencies or remote storage requirements
- Local network binding (localhost/127.0.0.1) for enhanced security
- Optional API keys are user-provided and stored locally only
- Full air-gapped operation capability for secure environments

## Development Workflow

### Code Quality Standards
- TypeScript strict mode enabled with comprehensive type checking
- ESLint and Prettier configuration for consistent code formatting
- Unit tests required for all business logic components
- Integration tests for API endpoints and critical user flows

### Git Workflow
```bash
# Create feature branch
git checkout -b feature/batch-name

# Make changes and commit
git add .
git commit -m "feat: implement batch X functionality"

# Push and create pull request
git push origin feature/batch-name
```

### Testing Strategy
- Unit tests for individual components and services
- Integration tests for API endpoints and database operations
- End-to-end tests for critical user workflows
- Performance tests for file analysis operations

## API Documentation

Once the backend is running, comprehensive API documentation is available at:
- **Swagger UI**: http://localhost:5000/swagger
- **OpenAPI Spec**: http://localhost:5000/swagger/v1/swagger.json

## Support and Resources

For additional information and support:
- **Project Repository**: [Repository URL]
- **Technical Documentation**: See `/docs` directory
- **Issue Tracking**: GitHub Issues
- **Development Chat**: [Team Communication Channel]

## License

This project is licensed under [License Type]. See LICENSE file for details.

---

**SecuNik LogX** - Professional Digital Forensics Platform  
Local-First • Secure • Comprehensive • Production-Ready