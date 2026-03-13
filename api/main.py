"""Minimal FastAPI scaffold for future web dashboard.

Per PRD §12 Phase 2: Web dashboard, scheduled scans, visualization.
Per MVP §12: Modular architecture for future web integration.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="CloudGuard API",
    description="REST API for CloudGuard AWS Security Scanner",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "cloudguard-api"}


@app.get("/api/v1/scans")
async def list_scans() -> dict[str, str]:
    """Placeholder for future scan listing."""
    return {"message": "Scan storage not yet implemented. Use CLI for scanning."}
