# AdversarialShield - Multimodal AI Security Testing & Guardrails Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Node](https://img.shields.io/badge/node-18%2B-green.svg)](https://nodejs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

> **Enterprise-grade AI security platform for testing, detecting, and defending against adversarial attacks on LLM-powered applications.**

AdversarialShield is a comprehensive AI cybersecurity platform that automatically tests, detects, and defends against advanced threats targeting AI systems. It combines red teaming capabilities, real-time guardrails, vulnerability scanning, and threat intelligence into a unified security platform aligned with **OWASP Top 10 for LLMs** and **MITRE ATLAS** frameworks.

## 🎯 Key Features

### 🔴 Automated AI Red Teaming Engine
- **Prompt Injection Attack Generator**: Sophisticated injection techniques including context manipulation, instruction override, and indirect injection
- **Jailbreak Pattern Database**: Evolving library of jailbreak techniques (DAN, roleplay, hypothetical scenarios)
- **Attack Taxonomy**: Organized by OWASP Top 10 for LLMs and MITRE ATLAS framework
- **Model Version Tracking**: Track attack success rates across different model versions
- **Feedback Loop**: Learns from successful attacks to evolve detection patterns

### 🛡️ Real-Time Guardrails & Detection System
- **Multi-Layer Defense**: Input validation → Threat detection → Output sanitization
- **Prompt Injection Detector**: Pattern-based and ML-ready detection with confidence scoring
- **PII Detection**: Automatic detection and masking of sensitive information (emails, SSN, credit cards, etc.)
- **Output Sanitizer**: Prevents code injection, XSS, SQL injection in LLM outputs (OWASP LLM02)
- **Toxicity Detection**: Content filtering with configurable thresholds
- **Token Limit Enforcement**: Prevents DoS via context overflow attacks

### 🔍 AI Vulnerability Scanner
- **AST-Based Analysis**: Deep code analysis for Python, JavaScript, TypeScript
- **Pattern-Based Scanning**: Detects hardcoded secrets, SQL injection, command injection, weak crypto
- **LLM-Specific Checks**: Identifies prompt injection risks, insecure output handling
- **Compliance Mapping**: Vulnerabilities mapped to CWE IDs and OWASP categories

### 💰 Cost & Rate Management
- **Token Bucket Rate Limiting**: Configurable requests per minute/day limits
- **Budget Controls**: Daily, monthly, and per-request cost limits
- **Usage Tracking**: Real-time cost monitoring across providers
- **Multi-Provider Support**: OpenAI, Anthropic Claude, Ollama (local)

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Docker & Docker Compose (optional, for full stack)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/oness24/Multimodal-AI-Guardrails-Security-Platform.git
cd Multimodal-AI-Guardrails-Security-Platform
```

2. **Install dependencies**
```bash
# Backend
pip install -r requirements.txt
# or
pip install fastapi uvicorn pydantic pydantic-settings redis motor asyncpg sqlalchemy httpx openai anthropic tiktoken

# Frontend
cd frontend && npm install
```

3. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your API keys
```

4. **Start the application**

**Option A: Development mode (recommended for testing)**
```bash
# Terminal 1 - Backend
cd Multimodal-AI-Guardrails-Security-Platform
python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 - Frontend
cd frontend
npm run dev
```

**Option B: Docker (full stack with databases)**
```bash
docker-compose -f docker/docker-compose.yml up -d
```

5. **Access the platform**
- 🌐 Frontend: http://localhost:3000
- 🔌 Backend API: http://localhost:8000
- 📚 API Documentation: http://localhost:8000/docs
- ❤️ Health Check: http://localhost:8000/health

## � API Endpoints

### Guardrails
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/guardrails/validate` | POST | Validate input against security policies |
| `/api/v1/guardrails/policies` | GET | List active security policies |

### Red Team
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/redteam/attack` | POST | Generate attack payloads |
| `/api/v1/redteam/test` | POST | Execute attack test against target |
| `/api/v1/redteam/patterns` | GET | Get attack pattern catalog |

### Scanner
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scanner/scan` | POST | Scan code for vulnerabilities |
| `/api/v1/scanner/analyze` | POST | Deep AST analysis |

### Usage & Cost Tracking
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/usage/status` | GET | Current budget status |
| `/api/v1/usage/daily` | GET | Today's usage summary |
| `/api/v1/usage/monthly` | GET | Monthly usage summary |
| `/api/v1/usage/estimate` | GET | Estimate cost for a request |

## 📚 Documentation

- [Quick Start Guide](docs/quick_start.md)
- [Architecture Overview](docs/architecture.md)
- [Build Plan](BUILD_PLAN.md)
- [API Documentation](http://localhost:8000/docs) (Interactive Swagger UI)

## 🏗️ Project Structure

```
Multimodal-AI-Guardrails-Security-Platform/
├── backend/                    # Python FastAPI backend
│   ├── api/                   # API routes and endpoints
│   │   └── routes/           # Guardrails, RedTeam, Scanner, Usage
│   ├── core/                  # Configuration, database, models
│   ├── guardrails/            # Real-time guardrails system
│   │   ├── detectors/        # Injection, PII, Toxicity, Output sanitizer
│   │   └── engine.py         # Main guardrails engine
│   ├── redteam/               # Red team attack generation
│   │   └── engine.py         # Attack generator with feedback loop
│   ├── scanner/               # Vulnerability scanning
│   │   └── static_analysis/  # AST analyzer, code patterns
│   ├── integrations/          # LLM providers (OpenAI, Anthropic, Ollama)
│   ├── threat_intel/          # Pattern learner, threat feeds
│   └── utils/                 # Rate limiter, token counter
├── frontend/                  # Next.js 14 React frontend
│   ├── app/                  # App router pages
│   ├── components/           # React components
│   └── styles/               # Tailwind CSS styles
├── data/                      # Attack patterns & vulnerability DB
│   ├── attack_patterns/      # OWASP/MITRE attack templates
│   └── vulnerabilities/      # LLM vulnerability catalog
├── docker/                    # Docker configuration
├── docs/                      # Documentation
└── scripts/                   # Utility scripts
```

## 🛠️ Technology Stack

### Backend
| Component | Technology |
|-----------|------------|
| Framework | FastAPI (Python 3.10+) |
| LLM Providers | OpenAI, Anthropic Claude, Ollama |
| Token Counting | tiktoken |
| Async HTTP | httpx |
| Validation | Pydantic v2 |
| Database | PostgreSQL, MongoDB, Redis |

### Frontend
| Component | Technology |
|-----------|------------|
| Framework | Next.js 14 (App Router) |
| UI Library | React 18 |
| Styling | Tailwind CSS |
| Language | TypeScript |

### Security Features
| Feature | Implementation |
|---------|----------------|
| Rate Limiting | Token bucket algorithm |
| Cost Control | Per-request, daily, monthly budgets |
| Input Validation | Multi-pattern detection |
| Output Sanitization | XSS, SQLi, command injection prevention |

## 🧪 Testing

```bash
# Run backend tests
cd backend && python -m pytest

# Run with coverage
python -m pytest --cov=backend

# Test specific module
python -m pytest tests/test_guardrails/
```

## 🔒 Security Coverage

### OWASP Top 10 for LLMs
| ID | Vulnerability | Status |
|----|---------------|--------|
| LLM01 | Prompt Injection | ✅ Implemented |
| LLM02 | Insecure Output Handling | ✅ Implemented |
| LLM03 | Training Data Poisoning | 🔄 Planned |
| LLM04 | Model Denial of Service | ✅ Implemented |
| LLM05 | Supply Chain Vulnerabilities | 🔄 Planned |
| LLM06 | Sensitive Information Disclosure | ✅ Implemented |
| LLM07 | Insecure Plugin Design | 🔄 Planned |
| LLM08 | Excessive Agency | 🔄 Planned |
| LLM09 | Overreliance | 🔄 Planned |
| LLM10 | Model Theft | 🔄 Planned |

### MITRE ATLAS Coverage
- ✅ Adversarial Suffix Attacks
- ✅ Prompt Injection Techniques
- ✅ Jailbreak Methods
- 🔄 Data Poisoning (Planned)
- 🔄 Model Extraction (Planned)

## 📊 Roadmap

### Phase 1: Core Platform ✅ Complete
- [x] Project infrastructure setup
- [x] FastAPI backend with async support
- [x] Next.js 14 frontend dashboard
- [x] Prompt injection detector
- [x] PII detection and masking
- [x] Output sanitization (LLM02)
- [x] Rate limiting and cost tracking
- [x] Red team attack generator
- [x] Static code scanner (AST + patterns)
- [x] Attack pattern database
- [x] Feedback loop for pattern learning

### Phase 2: Advanced Detection (In Progress)
- [ ] ML-based injection classifier
- [ ] Behavioral anomaly detection
- [ ] Multimodal attack support (images)
- [ ] Real-time streaming detection
- [ ] Custom policy builder UI

### Phase 3: Enterprise Features
- [ ] SIEM integration (Splunk, Wazuh)
- [ ] CI/CD pipeline plugins
- [ ] SSO/SAML authentication
- [ ] Multi-tenant support
- [ ] Compliance reporting (SOC2, HIPAA)
- [ ] Attack surface mapping

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS Framework](https://atlas.mitre.org/)
- AI Security Research Community

## 📧 Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/oness24/Multimodal-AI-Guardrails-Security-Platform/issues)
- **Documentation**: [docs/](docs/)

## ⚠️ Disclaimer

This platform is designed for **authorized security testing and research purposes only**. Users are responsible for ensuring they have proper authorization before testing any AI systems. The authors are not responsible for misuse of this tool.

---

<p align="center">
  <b>Built for the AI Security Community</b><br>
  <a href="https://github.com/oness24/Multimodal-AI-Guardrails-Security-Platform">⭐ Star this repo</a> •
  <a href="https://github.com/oness24/Multimodal-AI-Guardrails-Security-Platform/issues">🐛 Report Bug</a> •
  <a href="https://github.com/oness24/Multimodal-AI-Guardrails-Security-Platform/issues">✨ Request Feature</a>
</p>
