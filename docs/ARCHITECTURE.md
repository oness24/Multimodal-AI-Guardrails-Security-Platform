# AdversarialShield - Architecture Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Architecture](#component-architecture)
4. [Data Flow](#data-flow)
5. [Security Architecture](#security-architecture)
6. [Deployment Architecture](#deployment-architecture)
7. [Scalability & Performance](#scalability--performance)
8. [Technology Stack](#technology-stack)

---

## System Overview

AdversarialShield is a comprehensive AI security platform designed to test, detect, and defend against adversarial attacks on multimodal AI systems. The platform provides:

- **Red Team Engine**: Automated adversarial attack generation
- **Guardrails System**: Real-time detection and protection
- **Vulnerability Scanner**: Static and dynamic analysis
- **Threat Intelligence**: Attack surface mapping and threat modeling
- **SIEM Integration**: Enterprise alerting and incident response
- **CI/CD Integration**: Automated security gates for development pipelines

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Client Layer                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   Web UI     │  │   CLI Tool   │  │  CI/CD       │              │
│  │  (Next.js)   │  │  (Python)    │  │  Plugins     │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
└─────────┼──────────────────┼──────────────────┼──────────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
          ┌─────────────────▼────────────────────────────────┐
          │          API Gateway (FastAPI)                   │
          │  ┌─────────────────────────────────────────┐    │
          │  │  Authentication & Authorization         │    │
          │  │  Rate Limiting & Caching                │    │
          │  │  Request Validation                     │    │
          │  └─────────────────────────────────────────┘    │
          └──────────┬───────────────────┬──────────────────┘
                     │                   │
    ┌────────────────┼───────────────────┼────────────────┐
    │                │                   │                │
┌───▼────┐  ┌───────▼──────┐  ┌────────▼────┐  ┌───────▼──────┐
│ Red    │  │ Guardrails   │  │  Scanner    │  │  Threat      │
│ Team   │  │   System     │  │   Module    │  │  Intel       │
│ Engine │  │              │  │             │  │  Module      │
└───┬────┘  └───────┬──────┘  └────────┬────┘  └───────┬──────┘
    │               │                  │               │
    └───────────────┴──────────────────┴───────────────┘
                           │
          ┌────────────────▼───────────────────┐
          │      Shared Services Layer         │
          │  ┌──────────────────────────────┐  │
          │  │  LLM Provider Integrations   │  │
          │  │  (OpenAI, Anthropic, Ollama) │  │
          │  └──────────────────────────────┘  │
          │  ┌──────────────────────────────┐  │
          │  │  Data Storage                │  │
          │  │  (PostgreSQL, Redis, Mongo)  │  │
          │  └──────────────────────────────┘  │
          │  ┌──────────────────────────────┐  │
          │  │  SIEM Connectors             │  │
          │  │  (Wazuh, Splunk)             │  │
          │  └──────────────────────────────┘  │
          └────────────────────────────────────┘
```

---

## Component Architecture

### 1. API Gateway Layer

**Location**: `backend/api/`

**Responsibilities**:
- Request routing
- Authentication/authorization
- Rate limiting
- CORS handling
- Request/response validation
- Error handling

**Key Files**:
- `main.py` - FastAPI application, middleware, lifespan events
- `dependencies.py` - Shared dependencies (auth, db sessions)
- `routes/` - API endpoint definitions

**Technologies**:
- FastAPI (async web framework)
- Pydantic (data validation)
- JWT (authentication)
- Redis (rate limiting, caching)

---

### 2. Red Team Engine

**Location**: `backend/redteam/`

**Responsibilities**:
- Generate adversarial attacks
- Prompt injection techniques
- Jailbreak testing
- Multimodal attacks (image, audio)

**Architecture**:
```
RedTeamEngine
├── PromptInjectionGenerator
│   ├── Context Manipulation
│   ├── Instruction Override
│   ├── Delimiter Confusion
│   └── Role Playing
├── JailbreakEngine
│   ├── DAN (Do Anything Now)
│   ├── Character Role-Play
│   ├── Hypothetical Scenarios
│   └── Translation Bypass
└── MultimodalAttacks
    ├── VisualPromptInjection
    ├── SteganographyAttacks
    └── AudioInjection
```

**Key Files**:
- `prompt_injection.py` - Prompt injection generator
- `jailbreak.py` - Jailbreak testing engine
- `multimodal/` - Multimodal attack generators

**Integration**:
- Uses LLM providers (OpenAI, Anthropic, Ollama)
- Stores attack patterns in MongoDB
- Logs results to PostgreSQL

---

### 3. Guardrails System

**Location**: `backend/guardrails/`

**Responsibilities**:
- Real-time input validation
- Output filtering
- Policy enforcement
- Multi-layer defense

**Architecture**:
```
GuardrailsEngine
├── Detectors
│   ├── PromptInjectionDetector (pattern-based)
│   ├── PIIDetector (regex + NER)
│   └── ToxicityDetector (transformer model)
├── Agents
│   ├── SanitizationAgent (input cleaning)
│   ├── ValidationAgent (policy checking)
│   └── ContextualValidator (semantic analysis)
└── Filters
    └── ResponseFilter (output sanitization)
```

**Key Files**:
- `engine.py` - Main orchestrator
- `detectors/` - Detection modules
- `agents/` - Defense agents
- `policies/policy_engine.py` - Policy management
- `filters/response_filter.py` - Output filtering

**Flow**:
1. Input received → Detectors analyze
2. Violations found → Agents respond
3. Policy engine decides action (allow/block/modify)
4. Response filtered before return

---

### 4. Vulnerability Scanner

**Location**: `backend/scanner/`

**Responsibilities**:
- Static code analysis
- Dynamic runtime testing
- Compliance checking

**Architecture**:
```
ScannerModule
├── StaticAnalysis
│   ├── ASTAnalyzer (Python code analysis)
│   ├── PromptTemplateScanner
│   └── ConfigurationScanner
├── DynamicAnalysis
│   ├── ExfiltrationTests
│   ├── LeakageTests
│   ├── AccessTests
│   └── FuzzingEngine
└── ComplianceChecker
    ├── NIST_AI_RMF
    ├── OWASP_LLM_Top10
    └── EU_AI_Act
```

**Key Files**:
- `vulnerability_scanner.py` - Static analysis engine
- `dynamic_scanner.py` - Runtime testing
- `compliance_checker.py` - Framework compliance

**OWASP LLM Top 10 Coverage**:
- LLM01: Prompt Injection
- LLM02: Insecure Output Handling
- LLM03: Training Data Poisoning
- LLM04: Model Denial of Service
- LLM05: Supply Chain Vulnerabilities
- LLM06: Sensitive Information Disclosure
- LLM07: Insecure Plugin Design
- LLM08: Excessive Agency
- LLM09: Overreliance
- LLM10: Model Theft

---

### 5. Threat Intelligence Module

**Location**: `backend/threat_intel/`

**Responsibilities**:
- Attack surface mapping
- STRIDE threat modeling
- OWASP threat analysis
- MITRE ATLAS integration

**Architecture**:
```
ThreatIntelModule
├── AttackSurfaceMapper
│   ├── Component Discovery
│   ├── Data Flow Mapping
│   ├── Entry Point Identification
│   └── Risk Scoring
├── STRIDEModeler
│   ├── Spoofing Threats
│   ├── Tampering Threats
│   ├── Repudiation Threats
│   ├── Information Disclosure
│   ├── Denial of Service
│   └── Elevation of Privilege
├── OWASPThreatModeler
│   └── LLM01-LLM10 Analysis
└── MITREATLASIntegration
    ├── Technique Mapping
    ├── Tactic Coverage
    └── Navigator Generation
```

**Key Files**:
- `attack_surface_mapper.py` - Attack surface analysis
- `stride_modeler.py` - STRIDE threat modeling
- `owasp_threat_modeler.py` - OWASP analysis
- `mitre_atlas.py` - ATLAS framework integration

**Output**:
- Threat models (JSON)
- Risk scores (0-10 scale)
- Mitigation recommendations
- ATT&CK Navigator layers

---

### 6. Alerting & SIEM Integration

**Location**: `backend/alerting/`

**Responsibilities**:
- Alert management
- Event correlation
- SIEM integration
- Incident response

**Architecture**:
```
AlertingSystem
├── AlertManager
│   ├── Alert Creation
│   ├── Correlation Engine
│   ├── Aggregation
│   └── Deduplication (fingerprinting)
├── SIEMConnectors
│   ├── WazuhConnector (CEF format)
│   ├── SplunkConnector (HEC)
│   └── GenericSyslog
├── Notifications
│   ├── EmailNotifier (SMTP)
│   ├── SlackNotifier (Webhooks)
│   └── PagerDutyNotifier (Events API)
└── IncidentResponse
    ├── Playbook Engine
    ├── Automated Steps
    └── Timeline Tracking
```

**Key Files**:
- `alert_manager.py` - Central alert management
- `siem_connectors.py` - SIEM integrations
- `notifications.py` - Multi-channel notifications
- `incident_response.py` - Automated response

**Alert Flow**:
1. Event detected → Alert created
2. Fingerprint generated (SHA256)
3. Correlation check (5-min window)
4. SIEM forwarding (CEF/LEEF)
5. Notification sent
6. Incident created (if critical)
7. Playbook executed

---

### 7. CI/CD Integration

**Location**: `cli.py`, `backend/api/routes/cicd.py`

**Responsibilities**:
- Local security scanning
- Pipeline integration
- Security gates
- Badge generation

**Components**:
- **CLI Tool**: Local scanning and testing
- **GitHub Actions**: Automated workflows
- **GitLab CI**: Pipeline integration
- **Pre-commit Hooks**: Local quality gates
- **API Endpoints**: Programmatic access

**Security Gate Flow**:
1. Code committed → Pre-commit hooks run
2. Code pushed → CI pipeline triggered
3. Security scan executed
4. Results analyzed
5. Gate decision (pass/block)
6. PR commented (GitHub)
7. Merge allowed/blocked

---

## Data Flow

### Attack Generation Flow

```
User Request
    │
    ▼
API Gateway (auth, rate limit)
    │
    ▼
RedTeam Engine
    │
    ├──▶ Select Technique
    │
    ├──▶ Generate with LLM
    │    (OpenAI/Anthropic/Ollama)
    │
    ├──▶ Validate Payload
    │
    ├──▶ Store in MongoDB
    │
    └──▶ Return to User
```

### Guardrails Validation Flow

```
LLM Input
    │
    ▼
Guardrails Engine
    │
    ├──▶ Detectors Run in Parallel
    │    ├─ Prompt Injection Detector
    │    ├─ PII Detector
    │    └─ Toxicity Detector
    │
    ├──▶ Violations Collected
    │
    ├──▶ Policy Engine Decision
    │    (allow / block / modify)
    │
    ├──▶ Agents Respond
    │    └─ Sanitization if needed
    │
    ├──▶ Alert Created (if violation)
    │
    └──▶ Return Validated Input
```

### Vulnerability Scan Flow

```
Code Submitted
    │
    ▼
Scanner Module
    │
    ├──▶ Static Analysis
    │    ├─ AST Parsing
    │    ├─ Pattern Matching
    │    └─ OWASP Mapping
    │
    ├──▶ Risk Scoring
    │
    ├──▶ Report Generation
    │    ├─ JSON
    │    ├─ SARIF
    │    └─ Text
    │
    ├──▶ Store Results (PostgreSQL)
    │
    └──▶ Return Report
```

---

## Security Architecture

### Authentication & Authorization

**Authentication Methods**:
1. **JWT Tokens** (for web UI and API)
   - Access token (1 hour expiration)
   - Refresh token (30 days expiration)
   - HMAC SHA-256 signing

2. **API Keys** (for CI/CD and programmatic access)
   - Format: `advshield_<32-bytes>`
   - Scoped permissions
   - Revocable
   - Expiration support

**Authorization Model**:
- Role-Based Access Control (RBAC)
- Scopes: `admin`, `read`, `write`, `scan`, `attack`, `guardrails`
- User activation/deactivation
- Admin-only endpoints

**Password Security**:
- BCrypt hashing (cost factor 12)
- Minimum 8 characters
- No password reuse checking (in MVP)

### Network Security

**HTTPS/TLS**:
- Required in production
- Certificate validation
- HTTP → HTTPS redirect

**CORS Configuration**:
- Configured allowed origins
- Credentials support
- Method whitelisting

**Rate Limiting**:
- Token bucket algorithm
- Per-IP and per-user limits
- Configurable thresholds
- Burst allowance (2x normal rate)

### Data Security

**Sensitive Data Handling**:
- API keys never logged
- Passwords hashed (never stored plaintext)
- PII detection in inputs/outputs
- Secrets redaction in logs

**Encryption**:
- At rest: Database encryption (configurable)
- In transit: TLS 1.2+
- API keys: Hashed storage (production)

---

## Deployment Architecture

### Development Environment

```
Docker Compose
├── Backend (FastAPI)
│   └── Port 8000
├── Frontend (Next.js)
│   └── Port 3000
├── PostgreSQL
│   └── Port 5432
├── Redis
│   └── Port 6379
└── MongoDB
    └── Port 27017
```

### Production Environment

```
Load Balancer (nginx)
    │
    ├──▶ Backend Cluster
    │    ├─ API Server 1 (FastAPI)
    │    ├─ API Server 2 (FastAPI)
    │    └─ API Server N (FastAPI)
    │
    ├──▶ Frontend (Next.js)
    │    └─ Static + SSR
    │
    ├──▶ PostgreSQL
    │    ├─ Primary
    │    └─ Replica (read)
    │
    ├──▶ Redis Cluster
    │    ├─ Master
    │    └─ Replicas
    │
    └──▶ MongoDB ReplicaSet
         ├─ Primary
         └─ Secondaries
```

### Kubernetes Deployment (Optional)

```
Kubernetes Cluster
├── Ingress (nginx)
├── Deployments
│   ├── adversarialshield-api (3 replicas)
│   ├── adversarialshield-frontend (2 replicas)
│   └── adversarialshield-worker (2 replicas)
├── StatefulSets
│   ├── postgresql
│   ├── redis
│   └── mongodb
└── Services
    ├── api-service (LoadBalancer)
    ├── frontend-service
    └── database-services (ClusterIP)
```

---

## Scalability & Performance

### Horizontal Scaling

**API Servers**:
- Stateless design
- Load balanced
- Auto-scaling based on CPU/memory
- Target: 1000+ req/sec

**Workers** (Future):
- Celery task queue
- Distributed attack generation
- Async scanning jobs

### Caching Strategy

**Redis Caching**:
- Scan results (TTL: 1 hour)
- Guardrails policies (TTL: 5 min)
- User sessions (TTL: 1 hour)
- API responses (selective)

**In-Memory Caching**:
- LRU cache for hot data
- Guardrails pattern matching
- Model configurations

### Database Optimization

**PostgreSQL**:
- Connection pooling (20-50 connections)
- Indexes on frequently queried columns
- Partitioning for large tables
- Read replicas for analytics

**Redis**:
- Cluster mode for high availability
- Persistence (AOF + RDB)
- Key eviction policies

**MongoDB**:
- Sharding for attack patterns
- Indexes on query fields
- Aggregation pipeline optimization

### Performance Targets

- **API Response Time**: < 200ms (p95)
- **Throughput**: 1000+ req/sec
- **Uptime**: 99.9% SLA
- **Cache Hit Rate**: > 80%
- **Database Query Time**: < 50ms (p95)

---

## Technology Stack

### Backend

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | FastAPI | 0.104+ |
| Language | Python | 3.11+ |
| Async Runtime | uvicorn | Latest |
| ORM | SQLAlchemy | 2.0+ |
| Database | PostgreSQL | 15+ |
| Cache | Redis | 7+ |
| NoSQL | MongoDB | 7+ |
| Task Queue | Celery | Latest |
| Auth | python-jose | Latest |

### Frontend

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Next.js | 14+ |
| Language | TypeScript | 5+ |
| UI Library | shadcn/ui | Latest |
| Styling | Tailwind CSS | 3+ |
| State | Zustand | Latest |
| Charts | Recharts | Latest |

### AI/ML

| Component | Technology |
|-----------|-----------|
| LLM Access | OpenAI, Anthropic, Ollama |
| Embeddings | sentence-transformers |
| NLP | spaCy, transformers |
| Vision | CLIP, PIL |

### DevOps

| Component | Technology |
|-----------|-----------|
| Containers | Docker |
| Orchestration | Kubernetes (optional) |
| CI/CD | GitHub Actions, GitLab CI |
| Monitoring | Prometheus + Grafana |
| Logging | ELK Stack |

---

## Monitoring & Observability

### Metrics Collection

**Application Metrics**:
- Request count, latency, error rate
- Attack generation rate
- Guardrails block rate
- Scan completion time

**System Metrics**:
- CPU, memory, disk usage
- Database connections
- Cache hit/miss rates
- Queue lengths

**Business Metrics**:
- Active users
- API key usage
- Vulnerabilities found
- Threats detected

### Logging

**Structured Logging (JSON)**:
```json
{
  "timestamp": "2025-11-16T12:00:00Z",
  "level": "INFO",
  "service": "guardrails",
  "event": "violation_detected",
  "user_id": "user-123",
  "risk_score": 7.5,
  "detector": "prompt_injection"
}
```

**Log Levels**:
- DEBUG: Development diagnostics
- INFO: Normal operations
- WARNING: Potential issues
- ERROR: Errors requiring attention
- CRITICAL: System failures

### Tracing (Future)

- Distributed tracing with OpenTelemetry
- Request correlation IDs
- Performance profiling

---

## Security Best Practices

1. **Never commit secrets** - Use environment variables
2. **Validate all inputs** - Use Pydantic models
3. **Sanitize outputs** - Prevent injection attacks
4. **Use parameterized queries** - Prevent SQL injection
5. **Implement rate limiting** - Prevent abuse
6. **Enable HTTPS** - Encrypt in transit
7. **Hash passwords** - Use BCrypt
8. **Rotate API keys** - Regular rotation policy
9. **Monitor logs** - Security event detection
10. **Regular updates** - Dependency management

---

## Future Enhancements

### Short Term (3-6 months)

- ML-based detection models
- WebSocket support for real-time updates
- GraphQL API (alternative to REST)
- Advanced analytics dashboard

### Medium Term (6-12 months)

- Multi-tenancy support
- Enterprise SSO integration (SAML, OAuth)
- Custom policy builder (no-code)
- Automated remediation suggestions

### Long Term (12+ months)

- On-premise deployment option
- Federated learning for threat detection
- Browser extension for testing
- Mobile app

---

## Conclusion

AdversarialShield provides a comprehensive, scalable, and secure platform for AI security testing. The modular architecture allows for independent scaling and enhancement of each component while maintaining system cohesion.

For implementation details, see:
- [API Reference](api_reference.md)
- [Development Guide](../CLAUDE.md)
- [Quick Start](../QUICKSTART.md)
- [Deployment Guide](DEPLOYMENT.md)
