# Quick Start Guide

Welcome to AdversarialShield! This guide will help you get started with the platform.

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker & Docker Compose
- Git

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Multimodal-AI-Guardrails-Security-Platform.git
cd Multimodal-AI-Guardrails-Security-Platform
```

### 2. Set Up Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:
- `OPENAI_API_KEY` - Your OpenAI API key
- `ANTHROPIC_API_KEY` - Your Anthropic API key
- `SECRET_KEY` - Generate a secure secret key

### 3. Start with Docker Compose

```bash
cd docker
docker-compose up -d
```

This will start:
- Backend API (http://localhost:8000)
- Frontend (http://localhost:3000)
- PostgreSQL database
- Redis cache
- MongoDB
- Celery worker
- Flower (Celery monitoring at http://localhost:5555)

### 4. Verify Installation

Check if all services are running:

```bash
docker-compose ps
```

Access the API docs:
- http://localhost:8000/docs

Access the frontend:
- http://localhost:3000

## Development Setup (Without Docker)

### Backend Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -e ".[dev]"
```

3. Start PostgreSQL, Redis, and MongoDB locally

4. Run database migrations:
```bash
alembic upgrade head
```

5. Start the backend:
```bash
python -m backend.api.main
```

### Frontend Setup

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Start the development server:
```bash
npm run dev
```

## Next Steps

- Read the [Architecture Documentation](architecture.md)
- Explore the [API Reference](api_reference.md)
- Check out the [User Guide](user_guide.md)
- Review the [Development Guide](development_guide.md)

## Troubleshooting

### Port Already in Use

If you see port conflicts, modify the ports in `docker-compose.yml` or `.env` file.

### Database Connection Issues

Ensure PostgreSQL, Redis, and MongoDB are running and accessible at the URLs specified in your `.env` file.

### API Key Issues

Make sure your LLM API keys are correctly set in the `.env` file and have sufficient credits.

## Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation in the `docs/` folder
