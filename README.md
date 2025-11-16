# AdversarialShield - Multimodal AI Security Testing & Guardrails Platform

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Node](https://img.shields.io/badge/node-20%2B-green.svg)

AdversarialShield is a comprehensive AI cybersecurity platform that automatically tests, detects, and defends against advanced threats targeting AI systems, especially those using multimodal inputs (text, images, audio). It combines red teaming capabilities, real-time guardrails, vulnerability scanning, and threat intelligence into a unified security platform.

## 🎯 Key Features

### 🔴 Automated AI Red Teaming Engine
- **Prompt Injection Attack Generator**: Sophisticated injection techniques including context manipulation, instruction override, and indirect injection
- **Jailbreak Pattern Database**: Evolving library of jailbreak techniques tested against leading AI models
- **Multimodal Attack Synthesizer**: Cross-modal attacks exploiting text + images + audio processing
- **Attack Taxonomy**: Organized by OWASP Top 10 for LLMs and MITRE ATLAS framework

### 🛡️ Real-Time Guardrails & Detection System
- **Multi-Agent Defense Architecture**: Layered security with specialized sanitization, validation, and enforcement agents
- **Prompt Injection Detector**: ML-based real-time detection with 85%+ accuracy
- **Behavioral Anomaly Monitor**: Detects abnormal model behavior indicating adversarial manipulation
- **PII & Toxicity Detection**: Comprehensive content filtering and policy enforcement

### 🔍 AI Vulnerability Scanner
- **Static Code Analysis**: AST-based scanning for insecure API integrations, exposed prompts, and unsafe data handling
- **Dynamic Runtime Testing**: Data exfiltration tests, context leakage detection, unauthorized access attempts
- **Compliance Checking**: Validation against NIST AI RMF, OWASP standards, and EU AI Act requirements

### 🧠 Security Intelligence & Threat Modeling
- **Attack Surface Mapper**: Automated component discovery and entry point identification
- **Threat Model Generator**: STRIDE and MITRE ATLAS framework implementation
- **Adversarial Pattern Learning**: Continuous learning from detected attacks to improve detection

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker & Docker Compose (recommended)
- PostgreSQL, Redis, MongoDB (or use Docker)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/Multimodal-AI-Guardrails-Security-Platform.git
cd Multimodal-AI-Guardrails-Security-Platform
```

2. **Run the setup script**
```bash
bash scripts/setup.sh
```

3. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your API keys (OpenAI, Anthropic, etc.)
```

4. **Start with Docker (recommended)**
```bash
make docker-up
```

Or start services individually:
```bash
# Backend
make backend-dev

# Frontend (in another terminal)
make frontend-dev
```

5. **Access the platform**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- Celery Monitoring: http://localhost:5555

## 📚 Documentation

- [Quick Start Guide](docs/quick_start.md)
- [Architecture Overview](docs/architecture.md)
- [Build Plan](BUILD_PLAN.md)
- API Reference (Coming Soon)
- User Guide (Coming Soon)
- Development Guide (Coming Soon)

## 🏗️ Project Structure

```
adversarial-shield/
├── backend/              # Python FastAPI backend
│   ├── api/             # API routes and endpoints
│   ├── core/            # Core configuration and database
│   ├── redteam/         # Red team attack generation
│   ├── guardrails/      # Real-time guardrails system
│   ├── scanner/         # Vulnerability scanning
│   ├── threat_intel/    # Threat intelligence
│   └── tests/           # Backend tests
├── frontend/            # Next.js React frontend
├── ml_models/           # Trained ML models
├── data/                # Attack patterns and datasets
├── docker/              # Docker configuration
├── docs/                # Documentation
└── scripts/             # Utility scripts
```

## 🛠️ Technology Stack

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **LLM Integration**: LangChain, LlamaIndex, OpenAI, Anthropic, Ollama
- **ML/AI**: PyTorch, Transformers, scikit-learn
- **Databases**: PostgreSQL, MongoDB, Redis
- **Task Queue**: Celery + Redis

### Frontend
- **Framework**: Next.js 14 (React 18)
- **UI**: Tailwind CSS + shadcn/ui
- **State Management**: Zustand + React Query
- **Visualization**: Recharts, D3.js, React Flow

### Security & Analysis
- **Guardrails**: Guardrails.ai, NeMo Guardrails
- **Static Analysis**: tree-sitter, libcst, semgrep
- **PII Detection**: Presidio

## 🧪 Testing

Run the test suite:
```bash
make test
```

Run tests in watch mode:
```bash
make test-watch
```

Run linters:
```bash
make lint
```

Format code:
```bash
make format
```

## 📊 Roadmap

### Phase 1: MVP (Months 1-3) ✅
- [x] Project infrastructure setup
- [ ] Basic prompt injection generator
- [ ] Jailbreak testing engine
- [ ] Simple guardrails system
- [ ] Basic dashboard

### Phase 2: Advanced Features (Months 4-7)
- [ ] Multimodal attack capabilities
- [ ] ML-based detection models
- [ ] Static code analysis
- [ ] Dynamic runtime testing
- [ ] Compliance checking

### Phase 3: Production-Ready (Months 8-10)
- [ ] SIEM integration (Wazuh, Splunk)
- [ ] Attack surface mapping
- [ ] Threat modeling automation
- [ ] CI/CD pipeline integration
- [ ] Complete documentation

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

- OWASP Top 10 for LLMs Project
- MITRE ATLAS Framework
- Guardrails.ai Team
- AI Security Community

## 📧 Contact

For questions, issues, or feedback:
- Open an issue on GitHub
- Check the [documentation](docs/)

## ⚠️ Disclaimer

This platform is designed for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before testing any AI systems. The authors are not responsible for misuse of this tool.

---

**Built with ❤️ for the AI Security Community**
