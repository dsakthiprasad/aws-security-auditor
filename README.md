# AI-Powered AWS Security Auditor with Intelligent Terraform Remediation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/react-%5E18.0.0-blue)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.95.0-green)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-%20%20%20%20%20-blue)](https://www.docker.com/)
[![CI/CD](https://github.com/your-username/aws-security-auditor/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/your-username/aws-security-auditor/actions)

## Overview

AI-Powered AWS Security Auditor is a comprehensive security scanning and remediation platform designed to help organizations continuously monitor and improve their AWS security posture. The platform combines automated AWS resource scanning with AI-generated remediation guidance and intelligent Terraform code generation for effortless infrastructure-as-code security fixes.

Built with a modern full-stack architecture using FastAPI (backend) and React (frontend), the auditor provides real-time security scoring, detailed findings, and actionable remediation steps through an intuitive dashboard.

## Features

### Core Scanning Capabilities
- **AWS Security Scanning**: Comprehensive assessment of AWS accounts against security best practices
- **IAM Scanner**: Analyze users, roles, groups, and policies for overprivileged permissions and security risks
- **S3 Scanner**: Detect publicly accessible buckets, missing encryption, and insufficient access controls
- **Security Group Scanner**: Identify overly permissive inbound/outbound rules and unused security groups
- **Automated Remediation**: Generate Terraform code to fix identified security issues
- **AI-Powered Explanations**: Leverage LLMs to provide clear, contextual remediation guidance
- **Manual Remediation Guidance**: Step-by-step instructions for console-based fixes
- **Security Scoring Dashboard**: Visualize overall security posture with detailed breakdowns
- **PDF Report Generation**: Export detailed reports for compliance and auditing purposes
- **Demo Mode**: Fully functional demonstration with sample data for exploration

### Technical Features
- **Modern Tech Stack**: FastAPI, SQLAlchemy, React, Tailwind CSS, Chart.js
- **Containerized**: Docker support for consistent deployment across environments
- **CI/CD Ready**: GitHub Actions workflow for automated testing and deployment
- **Cloud Deployable**: Preconfigured for Render (backend) and Vercel (frontend)
- **Extensible Architecture**: Modular design for adding new scanners and compliance frameworks

## Architecture

![Architecture Diagram](docs/architecture.png)

The application follows a client-server architecture:

### Backend (FastAPI)
- **API Layer**: RESTful endpoints built with FastAPI for high performance and automatic OpenAPI documentation
- **Service Layer**: Business logic including AWS scanning services, AI integration, and Terraform generation
- **Data Layer**: SQLAlchemy ORM with SQLite for storing scan results, configurations, and user preferences
- **AWS Integration**: Boto3 SDK for secure interaction with AWS APIs
- **AI Service**: Integration with LLMs for generating remediation explanations and guidance

### Frontend (React)
- **UI Framework**: React 18 with hooks for modern state management
- **Styling**: Tailwind CSS for responsive, utility-first design
- **Data Visualization**: Chart.js for interactive security dashboards
- **State Management**: React Context and hooks for scalable state handling
- **HTTP Client**: Axios for efficient API communication

### Deployment
- **Backend**: Deployed to Render as a web service
- **Frontend**: Deployed to Vercel for optimal React hosting
- **Database**: SQLite for development/testing, configurable for production databases
- **Containerization**: Docker Compose for local development and testing

## Screenshots

![Dashboard](docs/screenshots/dashboard.png)
*Security Dashboard showing overall score and findings breakdown*

![Scan Results](docs/screenshots/scan-results.png)
*Detailed scan findings with severity filtering and resource details*

![Remediation](docs/screenshots/remediation.png)
*AI-generated remediation explanations and Terraform code snippets*

![Reports](docs/screenshots/report.png)
*Generated PDF report with executive summary and technical details*

## Installation

### Prerequisites
- Python 3.8 or higher
- Node.js 16 or higher
- Docker (optional, for containerized deployment)
- AWS Account (for live scanning; Demo Mode uses simulated data)

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/your-username/aws-security-auditor.git
cd aws-security-auditor

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Set up environment variables
cp backend/.env.example backend/.env
# Edit .env with your configuration (see Environment Variables section)

# Run database migrations (if applicable)
# For SQLite, tables are created automatically on first run

# Start the development server
uvicorn backend.app.main:app --reload
```

### Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your configuration (see Environment Variables section)

# Start the development server
npm run dev
```

### Docker Deployment
```bash
# Build and start all services
docker-compose up --build

# The application will be available at:
# - Frontend: http://localhost:3000
# - Backend API: http://localhost:8000
# - API Documentation: http://localhost:8000/docs
```

## Environment Variables

### Backend (`backend/.env`)
```env
# Application Settings
DEBUG=True
ENVIRONMENT=development
API_V1_STR=/api/v1
PROJECT_NAME=AI-Powered AWS Security Auditor

# Database
DATABASE_URL=sqlite:///./security_auditor.db

# AWS Settings (for live scanning)
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1

# AI Service Settings
OPENAI_API_KEY=your_openai_api_key_here  # or other LLM provider
AI_MODEL=gpt-3.5-turbo
AI_MAX_TOKENS=500
AI_TEMPERATURE=0.3

# Security
SECRET_KEY=your_secret_key_for_jwt_here
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
```

### Frontend (`frontend/.env.local`)
```env
# API Configuration
VITE_API_URL=http://localhost:8000/api/v1

# Feature Flags
VITE_ENABLE_DEMO_MODE=true
VITE_ENABLE_AI_EXPLANATIONS=true
VITE_SHOW_ADVANCED_SETTINGS=false
```

## Demo Mode

The application includes a fully functional Demo Mode that simulates AWS scanning results without requiring actual AWS credentials. This is perfect for exploration, presentations, and testing.

To enable Demo Mode:
1. Set `AWS_ACCESS_KEY_ID=demo` and `AWS_SECRET_ACCESS_KEY=demo` in the backend `.env` file
2. Alternatively, set `VITE_ENABLE_DEMO_MODE=true` in the frontend `.env.local` file
3. The application will generate realistic sample data for all scanners
4. AI explanations and Terraform generation work with the sample data

Demo Mode includes:
- Pre-populated findings across all scanner types
- Realistic resource naming conventions
- Varied severity levels (Critical, High, Medium, Low, Info)
- Sample Terraform remediation code
- AI-generated explanations for each finding

## Folder Structure

```
aws-security-auditor/
├── backend/                    # FastAPI backend application
│   ├── app/                    # Main application package
│   │   ├── api/                # API route definitions
│   │   │   └── v1/             # Version 1 API endpoints
│   │   │       ├── health/     # Health check endpoints
│   │   │       ├── scan/       # Scan initiation and results
│   │   │       ├── findings/   # Findings retrieval and filtering
│   │   │       ├── remediation/# Remediation guidance and Terraform generation
│   │   │       └── reports/    # PDF report generation
│   │   ├── core/               # Core configuration and utilities
│   │   ├── models/             # SQLAlchemy database models
│   │   ├── schemas/            # Pydantic models for request/validation
│   │   ├── services/           # Business logic (scanners, AI, Terraform)
│   │   └── main.py             # Application entry point
│   ├── tests/                  # Unit and integration tests
│   ├── requirements.txt        # Python dependencies
│   ├── Dockerfile              # Backend Docker configuration
│   └── alembic/                # Database migrations (if using PostgreSQL/MySQL)
├── frontend/                   # React frontend application
│   ├── public/                 # Static assets
│   ├── src/                    # Source code
│   │   ├── assets/             # Images, icons, logos
│   │   ├── components/         # Reusable UI components
│   │   ├── contexts/           # React Context providers
│   │   ├── hooks/              # Custom React hooks
│   │   ├── pages/              # Page components
│   │   ├── services/           # API service clients
│   │   ├── styles/             # Tailwind CSS configuration
│   │   ├── utils/              # Utility functions and helpers
│   │   └── App.js              # Main application component
│   ├── package.json            # Node.js dependencies and scripts
│   ├── tailwind.config.js      # Tailwind CSS configuration
│   └── vite.config.js          # Vite build configuration
├── docs/                       # Documentation (architecture, API, etc.)
├── docker-compose.yml          # Multi-container Docker setup
├── .github/                    # GitHub Actions workflows
│   └── workflows/
│       └── ci-cd.yml           # Continuous Integration and Deployment
├── README.md                   # This file
└── LICENSE                     # MIT License
```

## API Endpoints

### Health Check
- `GET /health` - Returns service status and version

### Scanning
- `POST /api/v1/scan` - Initiate a new security scan
- `GET /api/v1/scan/{scan_id}` - Get scan status and results
- `GET /api/v1/scans` - List all scans with filtering and pagination

### Findings
- `GET /api/v1/findings` - Retrieve findings with filtering, sorting, and pagination
- `GET /api/v1/findings/{finding_id}` - Get detailed finding information
- `PUT /api/v1/findings/{finding_id}/status` - Update finding status (e.g., resolved, ignored)

### Remediation
- `POST /api/v1/remediation/terraform` - Generate Terraform code for findings
- `GET /api/v1/remediation/guidance/{finding_id}` - Get AI-powered remediation guidance
- `GET /api/v1/remediation/manual/{finding_id}` - Get manual remediation steps

### Reports
- `GET /api/v1/reports/pdf/{scan_id}` - Generate and download PDF report
- `GET /api/v1/reports/summary/{scan_id}` - Get executive summary JSON

### Configuration
- `GET /api/v1/config` - Get application configuration
- `PUT /api/v1/config` - Update application settings

Full interactive API documentation is available at `/docs` when the backend is running.

## Tech Stack

### Backend
- **Framework**: FastAPI 0.95.0+
- **Language**: Python 3.8+
- **Database**: SQLAlchemy 1.4+ with SQLite (development), configurable for PostgreSQL/MySQL
- **AWS**: Boto3 1.26+
- **AI Integration**: OpenAI GPT-3.5-Turbo (configurable for other LLMs)
- **Validation**: Pydantic 1.10+
- **API Docs**: Swagger UI (automatically generated by FastAPI)
- **Testing**: Pytest, pytest-asyncio
- **Container**: Docker, Docker Compose

### Frontend
- **Framework**: React 18.2.0+
- **Language**: JavaScript (ES6+) with React Hooks
- **Styling**: Tailwind CSS 3.3+
- **State Management**: React Context API and useReducer
- **Data Fetching**: Axios 1.4+
- **Data Visualization**: Chart.js 4.3+ with react-chartjs-2
- **Routing**: React Router v6
- **Build Tool**: Vite 4.3+
- **Testing**: Jest, React Testing Library
- **Container**: Docker, Docker Compose

### DevOps & Infrastructure
- **CI/CD**: GitHub Actions
- **Backend Deployment**: Render (Web Service)
- **Frontend Deployment**: Vercel
- **Container Orchestration**: Docker Compose (local development)
- **Monitoring**: Built-in health checks and logging
- **Security**: JWT authentication, environment-based configuration, CORS policies

## CI/CD

The project includes GitHub Actions workflows for automated testing, building, and deployment:

### Workflows
- **CI/CD Pipeline** (`.github/workflows/ci-cd.yml`):
  - Runs on every push to `main` and pull requests
  - Backend: Installs dependencies, runs tests, lints code, builds Docker image
  - Frontend: Installs dependencies, runs tests, lints code, builds production bundle
  - Deploys backend to Render on push to `main`
  - Deploys frontend to Vercel on push to `main`
  - Sends notifications on deployment status

### Local Testing
```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

## Future Improvements

### Planned Features
- **Multi-Account Support**: Scan and manage multiple AWS accounts from a single dashboard
- **Compliance Frameworks**: Built-in checks for CIS AWS Foundations, PCI DSS, HIPAA, GDPR
- **Continuous Monitoring**: Scheduled scans and drift detection
- **Integration Hub**: Connect with SIEM tools, ticketing systems (Jira, ServiceNow), and communication platforms (Slack, Teams)
- **Policy as Code**: Integration with AWS Config Rules and GuardDuty findings
- **Risk Prioritization**: CVSS scoring and business context-based risk ranking
- **Automated Remediation**: One-click apply of Terraform changes through CI/CD pipelines
- **Role-Based Access Control**: Fine-grained permissions for team collaboration
- **Advanced Analytics**: Trend analysis, predictive security scoring, and benchmarking

### Technical Enhancements
- **Performance Optimization**: Caching layer (Redis) for frequent queries
- **Scalability**: Migration to PostgreSQL/MySQL for production, horizontal scaling
- **Enhanced AI**: Fine-tuned models for AWS-specific remediation, multi-language support
- **Infrastructure**: Kubernetes deployment manifests, Helm charts
- **Observability**: Distributed tracing (Jaeger), metrics (Prometheus), logging (ELK stack)
- **Mobile Access**: Progressive Web App (PWA) support and potential mobile applications
- **Accessibility**: WCAG 2.1 AA compliance for inclusive design

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by AWS Well-Architected Framework and AWS Security Hub
- Built with ❤️ using open-source technologies
- Special thanks to the contributors and maintainers of FastAPI, React, Tailwind CSS, and all other dependencies

---

**Note**: Replace `your-username` in the badge URLs and documentation with your actual GitHub username or organization name.

**Disclaimer**: This tool is designed for security assessment and remediation guidance. Always review generated Terraform code and remediation suggestions in a staging environment before applying to production AWS resources. The authors are not responsible for any unintended changes or security issues resulting from the use of this tool.