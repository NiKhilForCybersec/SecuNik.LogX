# SecuNik LogX - Digital Forensics Platform

SecuNik LogX is a local-first digital forensics and log analysis platform for cybersecurity professionals. It provides comprehensive tools for analyzing log files, extracting indicators of compromise (IOCs), and identifying potential security threats.

## Features

- **Local-First Analysis**: Process files locally without sending sensitive data to external servers
- **Multi-Format Support**: Analyze various log formats including Windows Event Logs, Syslog, JSON, CSV, and more
- **Threat Detection**: Utilize YARA and Sigma rules to identify potential threats
- **IOC Extraction**: Automatically extract indicators of compromise from log files
- **MITRE ATT&CK Mapping**: Map detected threats to MITRE ATT&CK framework
- **Custom Parsers**: Create and manage custom parsers for specialized log formats
- **Rule Management**: Create, import, and manage detection rules
- **Timeline Analysis**: View events in chronological order for better understanding
- **AI-Powered Analysis**: Optional AI-assisted analysis for deeper insights

## Project Structure

The project consists of two main components:

1. **Frontend**: React-based web interface (TypeScript)
2. **Backend**: .NET Core API (C#)

## Getting Started

### Prerequisites

- Node.js 16+ and npm
- .NET 8.0 SDK
- Git

### Frontend Setup

1. Clone the repository
2. Navigate to the project directory
3. Install dependencies:

```bash
npm install
```

4. Create a `.env` file based on `.env.example`
5. Start the development server:

```bash
npm run dev
```

### Backend Setup

1. Navigate to the `SecuNik.LogX.Api` directory
2. Restore dependencies:

```bash
dotnet restore
```

3. Run the API:

```bash
dotnet run
```

## Development

### Frontend Technologies

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Framer Motion
- Recharts
- Axios
- React Router
- Monaco Editor
- React Syntax Highlighter

### Backend Technologies

- .NET 8.0
- Entity Framework Core
- SQLite
- SignalR (for real-time updates)
- YARA Sharp
- CsvHelper
- YamlDotNet

## API Documentation

The API documentation is available at `/swagger` when running the backend server.

## Backend Dependencies

```
# Core Dependencies
Microsoft.AspNetCore.OpenApi>=8.0.0
Microsoft.EntityFrameworkCore.Sqlite>=8.0.0
Microsoft.EntityFrameworkCore.Tools>=8.0.0
Microsoft.AspNetCore.SignalR>=1.1.0
Microsoft.Extensions.Diagnostics.HealthChecks>=8.0.0
Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore>=8.0.0
Swashbuckle.AspNetCore>=6.5.0
System.Text.Json>=8.0.5

# Code Analysis and Compilation
Microsoft.CodeAnalysis.CSharp>=4.8.0
Microsoft.CodeAnalysis.CSharp.Scripting>=4.8.0

# YARA and Parsing
YaraSharp>=1.3.0
System.IO.Compression>=4.3.0
System.IO.Compression.ZipFile>=4.3.0
SharpCompress>=0.34.2
CsvHelper>=30.0.1
Newtonsoft.Json>=13.0.3
System.Text.RegularExpressions>=4.3.1

# YAML Processing
YamlDotNet>=13.1.1
```

## Frontend Dependencies

```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.1",
    "axios": "^1.6.2",
    "framer-motion": "^10.16.16",
    "lucide-react": "^0.294.0",
    "recharts": "^2.8.0",
    "react-dropzone": "^14.2.3",
    "react-hot-toast": "^2.4.1",
    "zustand": "^4.4.7",
    "date-fns": "^2.30.0",
    "clsx": "^2.0.0",
    "tailwind-merge": "^2.0.0",
    "@monaco-editor/react": "^4.6.0",
    "react-syntax-highlighter": "^15.5.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.37",
    "@types/react-dom": "^18.2.15",
    "@typescript-eslint/eslint-plugin": "^6.10.0",
    "@typescript-eslint/parser": "^6.10.0",
    "@vitejs/plugin-react": "^4.1.1",
    "autoprefixer": "^10.4.16",
    "eslint": "^8.53.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.4.4",
    "postcss": "^8.4.31",
    "tailwindcss": "^3.3.5",
    "typescript": "^5.2.2",
    "vite": "^4.5.0"
  }
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.