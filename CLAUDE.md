# CLAUDE.md - Development Guide for AdversarialShield

This document serves as a comprehensive guide for AI assistants and developers working on the AdversarialShield project. It contains project context, development guidelines, coding standards, and best practices.

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Principles](#architecture-principles)
3. [Development Workflow](#development-workflow)
4. [Coding Standards](#coding-standards)
5. [Testing Guidelines](#testing-guidelines)
6. [Common Tasks](#common-tasks)
7. [Project Structure Reference](#project-structure-reference)
8. [Dependencies & Integration](#dependencies--integration)
9. [Troubleshooting](#troubleshooting)
10. [Release Checklist](#release-checklist)

---

## Project Overview

### Mission
Build a comprehensive AI security platform that tests, detects, and defends against adversarial attacks on multimodal AI systems.

### Core Components
1. **Red Team Engine** - Automated adversarial attack generation
2. **Guardrails System** - Real-time detection and protection
3. **Vulnerability Scanner** - Static and dynamic analysis
4. **Threat Intelligence** - Attack surface mapping and threat modeling

### Technology Stack
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, Celery
- **Frontend**: Next.js 14, React 18, TypeScript, Tailwind CSS
- **Databases**: PostgreSQL, MongoDB, Redis
- **ML/AI**: PyTorch, Transformers, LangChain, LlamaIndex
- **Infrastructure**: Docker, Kubernetes (production)

### Current Phase
**Phase 1: MVP (Months 1-3)**
- ✅ Project infrastructure setup complete
- 🔄 Next: Basic prompt injection generator (Month 2, Week 1-2)

---

## Architecture Principles

### 1. Modularity
- Each component (redteam, guardrails, scanner, threat_intel) is independent
- Clear separation of concerns between modules
- Use dependency injection for loose coupling

### 2. Async-First
- All I/O operations should be async (database, API calls, LLM requests)
- Use `async/await` throughout the backend
- FastAPI endpoints should be async when possible

### 3. Type Safety
- Use type hints for all Python functions
- Use TypeScript (not JavaScript) for frontend
- Enable strict type checking (mypy for Python, TypeScript strict mode)

### 4. Security-First
- Never log sensitive data (API keys, prompts with PII, model outputs)
- Input validation on all API endpoints
- Rate limiting on all public endpoints
- Sanitize all user inputs before processing

### 5. Performance
- Cache frequently accessed data (Redis)
- Use database connection pooling
- Batch operations where possible
- Async task queue (Celery) for long-running operations

### 6. Observability
- Structured logging (JSON format)
- Comprehensive error handling
- Metrics collection (Prometheus)
- Distributed tracing for debugging

---

## Development Workflow

### Branch Strategy
- **Main branch**: `main` (production-ready code)
- **Development branch**: `dev` (integration branch)
- **Feature branches**: `feature/description` or `claude/description-sessionid`
- **Bugfix branches**: `bugfix/description`

### Commit Message Format
Use conventional commits:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

Example:
```
feat(redteam): Add prompt injection attack generator

Implement LLM-based prompt injection attack generator with support
for context manipulation, instruction override, and delimiter confusion
techniques.

- Add PromptInjectionGenerator class
- Integrate with OpenAI and Anthropic APIs
- Add attack pattern templates
- Include unit tests

Closes #42
```

### Pull Request Guidelines
1. Reference the issue number
2. Provide clear description of changes
3. Include screenshots for UI changes
4. Ensure all tests pass
5. Update documentation if needed
6. Request review from at least one team member

---

## Coding Standards

### Python (Backend)

#### Style Guide
- Follow PEP 8
- Use Black for formatting (line length: 88)
- Use Ruff for linting
- Use mypy for type checking

#### Naming Conventions
```python
# Classes: PascalCase
class PromptInjectionGenerator:
    pass

# Functions/methods: snake_case
def generate_attack_payload():
    pass

# Constants: UPPER_SNAKE_CASE
MAX_ATTACK_ATTEMPTS = 10

# Private methods: _leading_underscore
def _internal_helper():
    pass
```

#### Type Hints
Always use type hints:
```python
from typing import Optional, List, Dict, Any

async def generate_attack(
    technique: str,
    target_context: Dict[str, Any],
    max_attempts: int = 5
) -> Optional[str]:
    """
    Generate attack payload for specified technique.

    Args:
        technique: Attack technique to use
        target_context: Context for attack generation
        max_attempts: Maximum generation attempts

    Returns:
        Generated attack payload or None if failed

    Raises:
        ValueError: If technique is not supported
    """
    pass
```

#### Error Handling
```python
# Use specific exceptions
class AttackGenerationError(Exception):
    """Raised when attack generation fails."""
    pass

# Always log errors
try:
    result = await generate_attack()
except AttackGenerationError as e:
    logger.error(f"Attack generation failed: {e}", exc_info=True)
    raise

# Use custom error responses for API
from fastapi import HTTPException

if not is_valid:
    raise HTTPException(
        status_code=400,
        detail="Invalid attack technique specified"
    )
```

#### Database Operations
```python
# Always use async sessions
from sqlalchemy.ext.asyncio import AsyncSession

async def create_attack_log(
    db: AsyncSession,
    attack_data: Dict[str, Any]
) -> AttackLog:
    """Create new attack log entry."""
    attack_log = AttackLog(**attack_data)
    db.add(attack_log)
    await db.commit()
    await db.refresh(attack_log)
    return attack_log
```

#### API Endpoints
```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter()

class AttackRequest(BaseModel):
    """Request model for attack generation."""
    technique: str
    target_model: str
    context: Optional[Dict[str, Any]] = None

class AttackResponse(BaseModel):
    """Response model for attack generation."""
    id: str
    payload: str
    technique: str
    created_at: datetime

@router.post("/attacks", response_model=AttackResponse)
async def generate_attack(
    request: AttackRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> AttackResponse:
    """
    Generate adversarial attack.

    Requires authentication.
    """
    # Implementation
    pass
```

### TypeScript (Frontend)

#### Style Guide
- Use ESLint and Prettier
- Prefer functional components over class components
- Use TypeScript strict mode

#### Component Structure
```typescript
// components/redteam/AttackGenerator.tsx
import { useState } from 'react'
import type { AttackTechnique } from '@/types'

interface AttackGeneratorProps {
  onGenerate: (payload: string) => void
  techniques: AttackTechnique[]
}

export function AttackGenerator({
  onGenerate,
  techniques
}: AttackGeneratorProps) {
  const [selectedTechnique, setSelectedTechnique] = useState<string>('')

  const handleGenerate = async () => {
    // Implementation
  }

  return (
    <div className="attack-generator">
      {/* UI */}
    </div>
  )
}
```

#### API Calls
```typescript
// lib/api-client.ts
import axios from 'axios'

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export interface AttackRequest {
  technique: string
  targetModel: string
  context?: Record<string, any>
}

export async function generateAttack(
  request: AttackRequest
): Promise<AttackResponse> {
  const { data } = await apiClient.post<AttackResponse>(
    '/api/v1/attacks',
    request
  )
  return data
}
```

### Documentation

#### Code Documentation
- Document all public functions/methods
- Include docstrings with Args, Returns, Raises
- Add inline comments for complex logic
- Keep comments up-to-date with code changes

#### API Documentation
- Use OpenAPI/Swagger annotations
- Provide request/response examples
- Document error codes and messages
- Include authentication requirements

---

## Testing Guidelines

### Backend Testing

#### Unit Tests
```python
# backend/tests/test_redteam/test_injection_generator.py
import pytest
from backend.redteam.prompt_injection import PromptInjectionGenerator

@pytest.fixture
async def generator():
    """Create generator instance for testing."""
    return PromptInjectionGenerator(mock_llm_client)

@pytest.mark.asyncio
async def test_generate_context_manipulation(generator):
    """Test context manipulation attack generation."""
    payload = await generator.generate_attack(
        technique="context_manipulation",
        target_context={"role": "assistant"}
    )

    assert payload is not None
    assert len(payload) > 0
    assert "ignore previous" in payload.lower()
```

#### Integration Tests
```python
@pytest.mark.asyncio
async def test_attack_generation_endpoint(client, db_session):
    """Test attack generation API endpoint."""
    response = await client.post(
        "/api/v1/attacks",
        json={
            "technique": "prompt_injection",
            "target_model": "gpt-4"
        }
    )

    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "payload" in data
```

#### Test Coverage
- Maintain minimum 80% code coverage
- Test happy paths and error cases
- Test edge cases and boundary conditions
- Mock external API calls

### Frontend Testing

#### Component Tests
```typescript
// __tests__/components/AttackGenerator.test.tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { AttackGenerator } from '@/components/redteam/AttackGenerator'

describe('AttackGenerator', () => {
  it('renders attack techniques', () => {
    render(<AttackGenerator techniques={mockTechniques} />)

    expect(screen.getByText('Prompt Injection')).toBeInTheDocument()
    expect(screen.getByText('Jailbreak')).toBeInTheDocument()
  })

  it('calls onGenerate when button clicked', async () => {
    const onGenerate = jest.fn()
    render(<AttackGenerator onGenerate={onGenerate} />)

    fireEvent.click(screen.getByText('Generate Attack'))

    await waitFor(() => {
      expect(onGenerate).toHaveBeenCalled()
    })
  })
})
```

---

## Common Tasks

### Starting Development

```bash
# Setup project for first time
bash scripts/setup.sh

# Create .env file
cp .env.example .env
# Edit .env with your API keys

# Start all services
make docker-up

# Or start individually
make backend-dev    # Backend only
make frontend-dev   # Frontend only
```

### Running Tests

```bash
# Run all backend tests
make test

# Run tests with coverage report
pytest --cov=backend --cov-report=html

# Run specific test file
pytest backend/tests/test_redteam/test_injection_generator.py

# Run tests in watch mode
pytest-watch backend/tests

# Run frontend tests
cd frontend && npm test
```

### Code Quality

```bash
# Format code
make format

# Run linters
make lint

# Type checking
mypy backend/

# Run all CI checks locally
make ci
```

### Database Operations

```bash
# Create new migration
make db-revision  # Then enter migration message

# Run migrations
make db-migrate

# Rollback one migration
make db-downgrade

# Seed database with initial data
make seed-data
```

### Adding a New Feature

1. **Create feature branch**
   ```bash
   git checkout -b feature/prompt-injection-generator
   ```

2. **Implement the feature**
   - Create necessary files in appropriate modules
   - Follow coding standards
   - Add type hints and documentation

3. **Add tests**
   - Unit tests for core logic
   - Integration tests for API endpoints
   - Maintain 80%+ coverage

4. **Update documentation**
   - Update relevant .md files
   - Add API documentation
   - Update CHANGELOG.md

5. **Commit and push**
   ```bash
   git add .
   git commit -m "feat(redteam): Add prompt injection generator"
   git push origin feature/prompt-injection-generator
   ```

6. **Create pull request**
   - Reference issue number
   - Provide clear description
   - Request review

### Adding a New API Endpoint

1. **Define Pydantic models** (if needed)
   ```python
   # backend/core/models.py
   class AttackRequest(BaseModel):
       technique: str
       target_model: str
   ```

2. **Create endpoint in router**
   ```python
   # backend/api/routes/redteam.py
   @router.post("/attacks")
   async def generate_attack(request: AttackRequest):
       # Implementation
       pass
   ```

3. **Register router in main.py**
   ```python
   # backend/api/main.py
   from backend.api.routes import redteam
   app.include_router(redteam.router, prefix="/api/v1/redteam")
   ```

4. **Add tests**
   ```python
   # backend/tests/test_api/test_redteam.py
   async def test_generate_attack(client):
       # Test implementation
       pass
   ```

### Adding a New Frontend Component

1. **Create component file**
   ```typescript
   // frontend/components/redteam/NewComponent.tsx
   export function NewComponent() {
     return <div>Component content</div>
   }
   ```

2. **Add types (if needed)**
   ```typescript
   // frontend/types/index.ts
   export interface NewComponentProps {
     // Props definition
   }
   ```

3. **Import and use**
   ```typescript
   // frontend/app/dashboard/redteam/page.tsx
   import { NewComponent } from '@/components/redteam/NewComponent'
   ```

4. **Add tests**
   ```typescript
   // __tests__/components/NewComponent.test.tsx
   ```

---

## Project Structure Reference

### Backend Module Organization

```
backend/
├── api/                    # API layer
│   ├── main.py            # FastAPI app, CORS, lifespan
│   ├── dependencies.py    # Shared dependencies (auth, db)
│   └── routes/            # API endpoints
│       ├── redteam.py     # Red team endpoints
│       ├── guardrails.py  # Guardrails endpoints
│       └── scanner.py     # Scanner endpoints
│
├── core/                  # Core functionality
│   ├── config.py         # Settings management
│   ├── database.py       # DB connections
│   ├── models.py         # SQLAlchemy/Pydantic models
│   └── security.py       # Auth/authorization
│
├── redteam/              # Red team module
│   ├── engine.py         # Main orchestrator
│   ├── attack_generator.py
│   ├── prompt_injection.py
│   ├── jailbreak.py
│   └── multimodal_attacks.py
│
├── guardrails/           # Guardrails module
│   ├── engine.py
│   ├── detectors/        # Detection modules
│   ├── policies/         # Policy definitions
│   └── agents/           # Defense agents
│
├── scanner/              # Scanner module
│   ├── static_analysis/
│   ├── dynamic_analysis/
│   └── compliance/
│
└── threat_intel/         # Threat intelligence
    ├── attack_surface_mapper.py
    └── threat_modeler.py
```

### Frontend Component Organization

```
frontend/
├── app/                   # Next.js app directory
│   ├── layout.tsx        # Root layout
│   ├── page.tsx          # Home page
│   └── dashboard/        # Dashboard pages
│       ├── redteam/
│       ├── guardrails/
│       └── scanner/
│
├── components/           # React components
│   ├── ui/              # Reusable UI components
│   ├── dashboard/       # Dashboard-specific
│   ├── redteam/         # Red team components
│   └── guardrails/      # Guardrails components
│
├── lib/                 # Utilities
│   ├── api-client.ts   # API client
│   └── utils.ts        # Helper functions
│
└── hooks/              # Custom React hooks
    ├── useRedTeam.ts
    └── useGuardrails.ts
```

---

## Dependencies & Integration

### LLM Provider Integration

#### OpenAI
```python
# backend/integrations/llm_providers/openai_client.py
from openai import AsyncOpenAI

class OpenAIClient:
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key)

    async def generate(self, prompt: str, model: str = "gpt-4"):
        response = await self.client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
```

#### Anthropic
```python
# backend/integrations/llm_providers/anthropic_client.py
from anthropic import AsyncAnthropic

class AnthropicClient:
    def __init__(self, api_key: str):
        self.client = AsyncAnthropic(api_key=api_key)

    async def generate(self, prompt: str, model: str = "claude-3-opus-20240229"):
        response = await self.client.messages.create(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
```

### SIEM Integration

#### Wazuh
```python
# backend/integrations/siem/wazuh_connector.py
class WazuhConnector:
    async def send_alert(self, alert_data: dict):
        """Send security alert to Wazuh."""
        pass
```

### Database Models

#### SQLAlchemy Models
```python
# backend/core/models.py
from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
import uuid

class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique = Column(String(100), nullable=False)
    payload = Column(String, nullable=False)
    target_model = Column(String(100))
    response = Column(String)
    success = Column(Boolean, default=False)
    metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
```

---

## Troubleshooting

### Common Issues

#### Database Connection Errors
```
Error: could not connect to server: Connection refused
```
**Solution**: Ensure PostgreSQL is running
```bash
# With Docker
make docker-up

# Or check service
docker-compose ps
```

#### Import Errors
```
ModuleNotFoundError: No module named 'backend'
```
**Solution**: Install package in editable mode
```bash
pip install -e .
```

#### Port Already in Use
```
Error: bind: address already in use
```
**Solution**: Change port in .env or kill process
```bash
# Find process using port 8000
lsof -ti:8000 | xargs kill -9

# Or change port in .env
API_PORT=8001
```

#### Frontend Build Errors
```
Error: Cannot find module 'next'
```
**Solution**: Install dependencies
```bash
cd frontend
npm install
```

### Performance Issues

#### Slow API Response
1. Check database query performance
2. Add database indexes
3. Enable Redis caching
4. Use async operations

#### High Memory Usage
1. Reduce batch sizes
2. Use pagination for large datasets
3. Clear ML model cache periodically
4. Monitor with Prometheus

---

## Release Checklist

### Pre-Release
- [ ] All tests passing
- [ ] Code coverage ≥ 80%
- [ ] Linting passes (no errors)
- [ ] Type checking passes
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in pyproject.toml and package.json

### Security
- [ ] No hardcoded secrets
- [ ] Environment variables documented
- [ ] Dependencies scanned for vulnerabilities
- [ ] Security headers configured
- [ ] Rate limiting enabled

### Performance
- [ ] API response times < 200ms (p95)
- [ ] Database queries optimized
- [ ] Caching implemented
- [ ] Load testing completed

### Deployment
- [ ] Docker images built and tested
- [ ] Database migrations tested
- [ ] Rollback plan documented
- [ ] Monitoring alerts configured
- [ ] Backup strategy verified

---

## Key Contacts & Resources

### Documentation
- **Build Plan**: See BUILD_PLAN.md for 10-month roadmap
- **Architecture**: See docs/architecture.md
- **Quick Start**: See docs/quick_start.md

### External Resources
- **OWASP Top 10 for LLMs**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **MITRE ATLAS**: https://atlas.mitre.org/
- **Guardrails.ai**: https://www.guardrailsai.com/
- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **Next.js Docs**: https://nextjs.org/docs

### Standards & Frameworks
- **NIST AI RMF**: https://www.nist.gov/itl/ai-risk-management-framework
- **EU AI Act**: https://artificialintelligenceact.eu/
- **PEP 8**: https://peps.python.org/pep-0008/

---

## Version History

- **v0.1.0** (Current) - Initial project structure setup
  - Complete backend/frontend scaffolding
  - Docker configuration
  - Database setup
  - Documentation foundation

---

## Notes for AI Assistants

When working on this project:

1. **Always check this file first** for context and guidelines
2. **Follow the coding standards** specified in this document
3. **Update this file** when adding new patterns or conventions
4. **Reference BUILD_PLAN.md** for implementation roadmap
5. **Maintain test coverage** at 80%+ for all new code
6. **Document all public APIs** with type hints and docstrings
7. **Use async/await** for all I/O operations
8. **Never commit secrets** - use environment variables
9. **Keep dependencies updated** but test thoroughly
10. **Ask for clarification** if requirements are unclear

---

**Last Updated**: 2025-11-16
**Current Phase**: Phase 1 - MVP (Month 1 Complete)
**Next Milestone**: Basic Prompt Injection Generator (Month 2, Week 1-2)
