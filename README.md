# AWS Security & Compliance Auditor - Backend

This is the backend for an AI-Powered AWS Security & Compliance Auditor built with FastAPI.

## Folder Structure

```
app/
├── main.py                 # FastAPI application entry point
├── api/
│   ├── v1/
│   │   ├── endpoints/
│   │   │   ├── health.py   # Health check endpoint
│   │   │   └── scan.py     # Placeholder scan endpoint (POST /scan)
│   │   └── __init__.py
│   └── __init__.py
├── models/
│   ├── scan.py             # Pydantic models for scan requests/responses
│   └── __init__.py
├── services/
│   ├── scanner.py          # Placeholder for AWS scanning logic
│   └── __init__.py
└__init__.py

tests/                      # Unit tests (to be added)
requirements.txt            # Python dependencies
```

## Explanation of Each Folder

- **app**: Contains the core application code.
  - **main.py**: Creates the FastAPI app instance and includes API routers.
  - **api**: Contains API versioning and endpoint definitions.
    - **v1**: Version 1 of the API.
      - **endpoints**: Individual API endpoints.
        - **health.py**: GET `/health` endpoint returning service status.
        - **scan.py**: POST `/scan` endpoint to initiate AWS security scans.
  - **models**: Pydantic models for request/response data validation.
    - **scan.py**: Defines `ScanRequest` and `ScanResponse` models.
  - **services**: Business logic and external integrations.
    - **scanner.py**: Placeholder for actual AWS scanning functionality (to be implemented with boto3, etc.).

- **tests**: Directory for unit tests (not yet implemented).

## How to Run

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Start the server:
   ```bash
   uvicorn app.main:app --reload
   ```

3. Access the health check at:
   - `http://localhost:8000/health`

4. Use the scan endpoint (placeholder):
   - `POST http://localhost:8000/scan`
   - With JSON body matching `ScanRequest` model.

## Next Steps

- Implement actual AWS scanning logic in `app/services/scanner.py` using boto3.
- Add authentication and authorization (e.g., API keys, JWT).
- Implement asynchronous scanning using background tasks or a message queue.
- Add database integration for storing scan results.
- Expand compliance framework checks (CIS, GDPR, HIPAA, etc.).
- Add more endpoints for retrieving scan history and findings.

## Dependencies

See `requirements.txt` for minimal dependencies:
- fastapi
- uvicorn

Note: Pydantic is included with FastAPI.