# AI-Powered AWS Security Auditor with Intelligent Terraform Remediation
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/react-%5E19.0.0-blue)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/docker-%20%20%20%20%20-blue)](https://www.docker.com/)
[![GitHub Actions CI](https://github.com/dsakthiprasad/aws-security-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/dsakthiprasad/aws-security-auditor/actions)
## 🚀 Live Demo

- **Frontend:** https://aws-security-auditor.vercel.app/
- **Backend API:** https://aws-security-auditor.onrender.com
- **Swagger Documentation:** https://aws-security-auditor.onrender.com/docs


## Overview
This project demonstrates cloud security automation, Infrastructure-as-Code generation, AI-assisted remediation, and modern full-stack deployment using AWS, FastAPI, React, Docker, Render, and Vercel.

AI-Powered AWS Security Auditor is a security scanning and remediation tool that evaluates AWS accounts for common misconfigurations and provides actionable guidance to improve security posture. The platform performs automated checks for S3 bucket public access, insecure security group rules, and IAM security issues, then generates clear explanations (using Google Gemini LLM), manual remediation steps, and Terraform code to fix findings where possible.

Built with a modern full-stack architecture using FastAPI (backend) and React (frontend), the auditor delivers results through an interactive dashboard featuring security scoring, visualizations, and PDF export capabilities.



## Features

### Core Scanning Capabilities
- **AWS Security Scanning**: Automated assessment of AWS accounts for:
  - Publicly accessible S3 buckets
  - Insecure security group rules (SSH/RDP open to 0.0.0.0/0, all-traffic open)
  - IAM issues (users without MFA, old access keys, excessive privileges)
- **AI-Powered Explanations**: Leverages Google Gemini LLM to generate clear, contextual explanations for each finding (with fallback hardcoded explanations).
- **Terraform Remediation Generation**: Creates ready-to-apply Terraform code for supported finding types (S3 public buckets, SSH/RDP-open security groups, old IAM access keys).
- **Manual Remediation Guidance**: Provides step-by-step console/CLI instructions for findings that cannot be automated via Terraform.
- **Security Scoring Dashboard**: Calculates a compliance score (0-100) and risk level based on findings severity, visualized with charts and summary cards.
- **PDF Report Generation**: Export dashboard view as a PDF report for sharing and archival.
- **Demo Mode**: Run with simulated data (no AWS credentials required) for exploration and demonstrations.
- **Docker Support**: Containerized backend and frontend for consistent deployment.
- **CI/CD Pipeline**: GitHub Actions workflow that builds, tests (frontend), and creates Docker images.

### Technical Features
- **Backend**: FastAPI, SQLAlchemy (SQLite), Google Gemini API, boto3
- **Frontend**: React 19, Vite, Tailwind CSS, Axios, Recharts (for charts), html2pdf.js (PDF export)
- **API**: RESTful endpoints with JSON responses
- **Database**: SQLite for storing scan history and results
- **Authentication**: None (intended for trusted environments; add auth as needed for production)

## Architecture

The application follows a client-server architecture:

### Backend (FastAPI)
- **API Layer**: RESTful endpoints built with FastAPI for performance and automatic OpenAPI documentation.
- **Service Layer**: Separate services for each scanner (S3, Security Groups, IAM), AI explanations, Terraform remediation generation, and scoring.
- **Data Layer**: SQLAlchemy ORM with SQLite database for persisting scan results and history.
- **AWS Integration**: Boto3 SDK for secure interaction with AWS APIs (uses default credential chain).
- **AI Service**: Integration with Google Gemini (via `google-generativeai`) for generating remediation explanations.

### Frontend (React)
- **UI Framework**: React 19 with hooks for state management.
- **Styling**: Tailwind CSS for responsive, utility-first design.
- **Data Visualization**: Recharts for interactive security dashboards; html2pdf.js for PDF export.
- **State Management**: React Context and hooks (or local state) for managing scan data and UI state.
- **HTTP Client**: Axios for efficient API communication to the backend.
- **Build Tool**: Vite for fast development and production builds.

## Screenshots

- Dashboard Screenshot (Coming Soon)
- Security Findings Screenshot (Coming Soon)
- AI Remediation Screenshot (Coming Soon)
- PDF Report Screenshot (Coming Soon)

## Installation

### Prerequisites
- Python 3.12 or higher
- Node.js 22 or higher
- Docker (optional, for containerized deployment)
- AWS Account (for live scanning; Demo Mode uses simulated data)

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/dsakthiprasad/aws-security-auditor.git
cd aws-security-auditor

# Create and activate virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (see Environment Variables section)
cp .env.example .env  # If .env.example exists; otherwise create .env manually
# Edit .env with your configuration

# Start the development server
uvicorn app.main:app --reload
```

### Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm ci

# Set up environment variables
cp .env.example .env.local  # If .env.example exists; otherwise create .env.local manually
# Edit .env.local with your configuration (see Environment Variables section)

# Start the development server
npm run dev
```

### Docker Deployment
```bash
# Build and start all services
docker-compose up --build

# The application will be available at:
# - Frontend: http://localhost:5173
# - Backend API: http://localhost:8000
# - API Documentation: http://localhost:8000/docs
```

## Environment Variables

### Backend (`.env`)
```env
# Application Mode
DEMO_MODE=false                    # Set to "true" to enable demo mode (uses simulated data)

# AI Service (Google Gemini)
GEMINI_API_KEY=your_gemini_api_key_here  # Required for AI explanations; omitted falls back to hardcoded text

# AWS Credentials (for live scanning)
# These follow the standard AWS SDK credential chain (environment variables, ~/.aws/credentials, IAM role, etc.)
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_SESSION_TOKEN=your_session_token_if_applicable  # Optional
AWS_DEFAULT_REGION=us-east-1                  # Default AWS region for scanning
```

### Frontend (`.env.local`)
```env
# API Configuration
VITE_API_BASE_URL=http://localhost:8000   # Base URL for backend API (adjust for production)
```

> **Note**: The frontend proxy in `vite.config.js` forwards `/api` requests to `http://backend:8000` when using Docker. Adjust `VITE_API_BASE_URL` accordingly for your deployment.

## Demo Mode

The application includes a fully functional Demo Mode that simulates AWS scanning results without requiring actual AWS credentials. This is perfect for exploration, presentations, and testing.

To enable Demo Mode:
1. Set `DEMO_MODE=true` in the backend `.env` file
2. (Optional) Unset or dummy AWS credentials; the scanners will skip live AWS calls when demo mode is active
3. The application will generate realistic sample data for all scanner types
4. AI explanations and Terraform generation work with the sample data

Demo Mode includes:
- Pre-populated findings across all scanner types (S3, Security Groups, IAM)
- Realistic resource naming conventions (bucket names, security group IDs, usernames)
- Varied severity levels (Critical, High, Medium, Low)
- Sample Terraform remediation code (where applicable)
- AI-generated explanations for each finding

## Folder Structure

```
aws-security-auditor/
├── app/                              # FastAPI backend application
│   ├── api/                          # API route definitions
│   │   └── v1/                       # Version 1 API endpoints
│   │       ├── endpoints/            # Individual endpoint modules
│   │       │   ├── health.py         # GET /health
│   │       │   ├── history.py        # GET /history/scans, GET /history/scans/{scan_id}
│   │       │   ├── remediation.py    # GET /remediate/{scan_id}
│   │       │   └── scan.py           # POST /scan
│   │   ├── core/                     # Core configuration (if any)
│   │   ├── crud/                     # Database CRUD operations
│   │   ├── db/                       # Database session and model setup
│   │   ├── demo/                     # Demo data generators (scan, remediation)
│   │   ├── models/                   # SQLAlchemy database models
│   │   ├── prompts/                  # Prompt templates for AI explanations
│   │   ├── services/                 # Business logic (scanners, AI, Terraform, scoring)
│   │   │   ├── explanation.py        # AI explanations using Google Gemini
│   │   │   ├── iam_scanner.py        # IAM vulnerability scanner
│   │   │   ├── orchestrator.py       # Combines results from all scanners
│   │   │   ├── remediation.py        # Terraform remediation generation
│   │   │   ├── scanner.py            # S3 public bucket scanner
│   │   │   ├── security_group_scanner.py # Security group vulnerability scanner
│   │   │   ├── scoring.py            # Score calculation
│   │   └── templates/                # Jinja2 Terraform templates
│   │       └── terraform/            # .j2 files for Terraform generation
│   ├── constants.py                  # Centralized constants for vulnerability types
│   └── main.py                       # FastAPI application entry point
├── frontend/                         # React frontend application
│   ├── public/                       # Static assets (index.html, etc.)
│   ├── src/                          # Source code
│   │   ├── assets/                   # Images, icons, logos
│   │   ├── components/               # Reusable UI components (ScoreCard, ScannerPanel, etc.)
│   │   ├── hooks/                    # Custom React hooks (if any)
│   │   ├── pages/                    # Page components (DashboardPage, etc.)
│   │   ├── services/                 # API service clients (api.js)
│   │   └── App.jsx                   # Root application component
│   ├── package.json                  # Node.js dependencies and scripts
│   ├── tailwind.config.js            # Tailwind CSS configuration
│   └── vite.config.js                # Vite build configuration (with API proxy)
├── docs/                             # Documentation (architecture, etc.)
├── docker-compose.yml                # Multi-container Docker setup
├── .github/                          # GitHub Actions workflows
│   └── workflows/
│       └── ci.yml                    # Continuous Integration workflow
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

## API Endpoints

All API endpoints are prefixed as defined in `app/main.py`. The base URL is `http://<host>:8000`.

### Health Check
- `GET /health`  
  Returns service status, mode (demo/live), and version.

### Scanning
- `POST /scan`  
  Initiate a full AWS security scan (S3, Security Groups, IAM).  
  Accepts a JSON body matching the `ScanRequest` model (currently unused; kept for compatibility).  
  Returns a `ScanResponse` with scan ID, status, findings count, security score, risk level, severity breakdown, and detailed findings.

### History
- `GET /history/scans`  
  Retrieve paginated list of historical scans (basic info).  
  Query parameters: `skip` (default 0), `limit` (default 50).  
  Returns array of scan objects with `scan_id`, `status`, `timestamp`, `findings_count`, `security_score`, `risk_level`.
- `GET /history/scans/{scan_id}`  
  Retrieve a specific scan by its scan ID, including all findings and severity breakdown.  
  Returns detailed scan object with findings array (each finding includes `scanner`, `issue_type`, `finding_data`, etc.).

### Remediation
- `GET /remediate/{scan_id}`  
  Generate Terraform remediation, manual guidance, and AI explanations for a given scan.  
  Returns an object containing:
  - `remediation.terraform`: Array of rendered Terraform blocks (filename, service, content)
  - `remediation.manual_guidance`: Array of manual guidance objects (finding_id, issue_type, guidance, priority)
  - `remediation.ai_explanations`: Array of explanations per unique issue type
  - Metadata (totals, generated_at, warnings)

*Full interactive API documentation is available at `/docs` when the backend is running.*

## Tech Stack

### Backend
- **Language**: Python 3.12+
- **Framework**: FastAPI 0.136.0+
- **Database**: SQLAlchemy 1.4+ with SQLite (development/production)
- **AWS**: Boto3 1.26+ (uses default credential chain)
- **AI**: Google Generative AI (`google-generativeai`) for explanations
- **Validation**: Implicit via Pydantic models (included with FastAPI)
- **API Docs**: Swagger UI (auto-generated by FastAPI)
- **Testing**: (Placeholder; backend tests temporarily skipped in CI)
- **Container**: Docker, Docker Compose

### Frontend
- **Language**: JavaScript (ES6+) with React 19
- **Framework**: React 19 (hooks for state management)
- **Build Tool**: Vite 8+
- **Styling**: Tailwind CSS 3.4+
- **State Management**: React Context and local state (via hooks)
- **Data Fetching**: Axios 1.18+
- **Data Visualization**: 
  - Recharts 3.8+ (for security score and severity breakdown pie chart)
  - html2pdf.js 0.14+ (client-side PDF export)
- **Icons**: Lucide React
- **Routing**: React Router DOM 7.18+
- **Linting**: ESLint
- **Container**: Docker, Docker Compose

### DevOps & Infrastructure
- **CI/CD**: GitHub Actions (`.github/workflows/ci.yml`)
  - Backend: Installs dependencies, skips tests (temporarily), builds Docker image
  - Frontend: Installs dependencies, runs lint, builds production bundle
  - Docker: Builds backend image (does not push to registry)
- **Deployment**: 
  - Backend:  Deployed on Render
  - Frontend: Deployed on Vercel
- **Monitoring**: Built-in health check endpoint
- **Security**: CORS middleware with configurable origins

## CI/CD

The project uses a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs on push and pull request to the `main` branch. The workflow performs the following steps:

1. Checkout repository
2. Set up Python 3.12
3. Install backend dependencies
4. Skip backend tests (temporary)
5. Set up Node.js 22
6. Install frontend dependencies (`npm ci`)
7. Build the frontend (`npm run build`)
8. Build the backend Docker image (without pushing)

*Note: Backend tests are intentionally skipped for now.*

## Project Highlights

- FastAPI Backend
- React + Vite Frontend
- AWS SDK (boto3)
- SQLAlchemy
- Google Gemini AI
- Terraform Remediation Generation
- Docker
- GitHub Actions CI
- Docker Compose
- PDF Report Generation (using html2pdf.js)

## Future Improvements

The following enhancements could be considered for future development (not currently planned or implemented):

- **Multi-Account Support**: Scan and manage multiple AWS accounts from a single dashboard.
- **Compliance Frameworks**: Built-in checks for CIS AWS Foundations, PCI DSS, HIPAA, GDPR.
- **Continuous Monitoring**: Scheduled scans, drift detection, and alerting.
- **Integration Hub**: Connect with SIEM tools (Splunk, Elastic), ticketing systems (Jira, ServiceNow), and communication platforms (Slack, Microsoft Teams).
- **Policy as Code**: Integration with AWS Config Rules and GuardDuty findings for centralized compliance.
- **Automated Remediation**: One-click apply of Terraform changes via CI/CD pipelines (with approval workflows).
- **Role-Based Access Control (RBAC)**: Fine-grained permissions for team collaboration and tenant isolation.
- **Advanced Analytics**: Trend analysis, predictive security scoring, and benchmarking against industry baselines.
- **Enhanced AI**: Fine-tuned models for AWS-specific remediation, multi-language support, and confidence scoring.
- **Infrastructure as Code**: Terraform modules for deploying the auditor itself, Helm charts for Kubernetes.
- **Observability**: Distributed tracing (Jaeger/OpenTelemetry), metrics (Prometheus), and structured logging (ELK stack).
- **Mobile Access**: Progressive Web App (PWA) support and potential native mobile applications.
- **Accessibility**: WCAG 2.1 AA compliance for inclusive design.

## License

This project is licensed under the MIT License. See the LICENSE file for details.