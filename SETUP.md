# SecuNik LogX Setup Guide

This guide provides detailed instructions for setting up both the frontend and backend components of the SecuNik LogX digital forensics platform.

## System Requirements

- **Operating System**: Windows 10/11, macOS, or Linux
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB+ recommended
- **Storage**: 10GB+ free space
- **Network**: Internet connection for initial setup and optional VirusTotal integration

## Frontend Setup

### Prerequisites

- Node.js 16+ and npm
- Git

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/secunik-logx.git
   cd secunik-logx
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Create environment configuration:
   ```bash
   cp .env.example .env
   ```

4. Edit the `.env` file to configure your environment:
   - Set `VITE_API_URL` to point to your backend API (default: http://localhost:8000/api)
   - Set `VITE_WS_URL` to point to your WebSocket endpoint (default: ws://localhost:8000)
   - Configure other settings as needed

5. Start the development server:
   ```bash
   npm run dev
   ```

6. For production builds:
   ```bash
   npm run build
   ```

## Backend Setup

### Prerequisites

- .NET 8.0 SDK
- SQLite (included in the project)

### Installation Steps

1. Navigate to the backend directory:
   ```bash
   cd SecuNik.LogX.Api
   ```

2. Restore .NET dependencies:
   ```bash
   dotnet restore
   ```

3. Configure the application:
   - Review `appsettings.json` and `appsettings.Development.json`
   - Adjust storage paths, connection strings, and other settings as needed

4. Run the API:
   ```bash
   dotnet run
   ```

5. For production builds:
   ```bash
   dotnet publish -c Release -o ./publish
   ```

## Configuration Options

### Frontend Configuration

The frontend can be configured through the `.env` file:

- `VITE_API_URL`: Backend API URL
- `VITE_WS_URL`: WebSocket URL for real-time updates
- `VITE_MAX_FILE_SIZE`: Maximum file size for uploads
- `VITE_ALLOWED_FILE_TYPES`: Comma-separated list of allowed file extensions
- `VITE_ENABLE_VIRUSTOTAL`: Enable/disable VirusTotal integration
- `VITE_ENABLE_AI_ANALYSIS`: Enable/disable AI analysis features
- `VITE_ENABLE_REAL_TIME_UPDATES`: Enable/disable real-time updates

### Backend Configuration

The backend is configured through `appsettings.json`:

- **ConnectionStrings**: Database connection settings
- **Storage**: File storage configuration
- **OpenAI**: AI analysis settings (optional)
- **VirusTotal**: VirusTotal integration settings (optional)
- **Analysis**: Analysis engine configuration
- **Rules**: Rule engine configuration
- **Parsers**: Parser configuration

## External Integrations

### VirusTotal Integration

1. Create a VirusTotal account at [virustotal.com](https://www.virustotal.com)
2. Obtain an API key from your account settings
3. Add the API key to `appsettings.json` in the VirusTotal section
4. Set `EnableIntegration` to `true`

### OpenAI Integration (Optional)

1. Create an OpenAI account at [openai.com](https://www.openai.com)
2. Obtain an API key
3. Add the API key to `appsettings.json` in the OpenAI section
4. Set `EnableAIAnalysis` to `true`

## Troubleshooting

### Common Issues

1. **API Connection Errors**:
   - Verify the API is running
   - Check that `VITE_API_URL` points to the correct address
   - Ensure no firewall is blocking the connection

2. **File Upload Issues**:
   - Check the `MaxFileSize` setting in the backend
   - Verify the file type is in the allowed list
   - Check storage permissions

3. **Parser Errors**:
   - Ensure custom parsers implement the correct interface
   - Check for syntax errors in parser code
   - Verify the parser is enabled

4. **Rule Engine Issues**:
   - Validate rule syntax
   - Check that rules are enabled
   - Verify rule paths in configuration

## Support

For additional help, please:
- Check the API documentation at `/swagger`
- Review the logs in the `Logs` directory
- Submit issues through the project's issue tracker