"""
Main FastAPI application for AdversarialShield.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.core.config import settings
from backend.core.database import close_db, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    """
    # Startup
    print("🚀 Starting AdversarialShield...")
    try:
        await init_db()
        print("✅ Database connections initialized")
    except Exception as e:
        print(f"⚠️ Database initialization skipped: {e}")
        print("   Running in demo mode without database...")
    yield
    # Shutdown
    print("🛑 Shutting down AdversarialShield...")
    try:
        await close_db()
        print("✅ Database connections closed")
    except Exception:
        pass


# Create FastAPI application
app = FastAPI(
    title=settings.api_title,
    description=settings.api_description,
    version=settings.api_version,
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health Check Endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return JSONResponse(
        content={
            "status": "healthy",
            "environment": settings.environment,
            "version": settings.api_version,
        }
    )


# Root Endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.api_title,
        "version": settings.api_version,
        "description": settings.api_description,
        "docs": "/docs" if settings.is_development else "disabled",
    }


# API Routes
from backend.api.routes import guardrails, redteam, scanner, usage

app.include_router(redteam.router, prefix="/api/v1/redteam", tags=["Red Team"])
app.include_router(guardrails.router, prefix="/api/v1/guardrails", tags=["Guardrails"])
app.include_router(scanner.router, prefix="/api/v1/scanner", tags=["Scanner"])
app.include_router(usage.router, prefix="/api/v1", tags=["Usage & Cost"])
# app.include_router(threat_intel.router, prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])
# app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.is_development,
        workers=1 if settings.is_development else settings.api_workers,
    )
