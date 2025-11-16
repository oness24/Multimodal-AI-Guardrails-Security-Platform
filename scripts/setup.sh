#!/bin/bash

# Setup script for AdversarialShield
# This script helps set up the development environment

set -e

echo "🚀 Setting up AdversarialShield development environment..."

# Check Python version
echo "📍 Checking Python version..."
python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.11"

if (( $(echo "$python_version < $required_version" | bc -l) )); then
    echo "❌ Python $required_version or higher is required. Found: $python_version"
    exit 1
fi
echo "✅ Python version: $python_version"

# Check Node.js version
echo "📍 Checking Node.js version..."
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed"
    exit 1
fi
node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if (( node_version < 18 )); then
    echo "❌ Node.js 18 or higher is required"
    exit 1
fi
echo "✅ Node.js version: $(node --version)"

# Check Docker
echo "📍 Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker is not installed (optional for local development)"
else
    echo "✅ Docker version: $(docker --version)"
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env file created. Please edit it with your API keys."
else
    echo "✅ .env file already exists"
fi

# Setup Python virtual environment
echo "📦 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
echo "📦 Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
echo "✅ Python dependencies installed"

# Setup frontend
echo "📦 Installing frontend dependencies..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
    echo "✅ Frontend dependencies installed"
else
    echo "✅ Frontend dependencies already installed"
fi
cd ..

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs
mkdir -p tmp
mkdir -p ml_models/injection_detector
mkdir -p ml_models/anomaly_detector
mkdir -p ml_models/embeddings
mkdir -p data/attack_patterns
mkdir -p data/vulnerabilities
mkdir -p data/training_data
echo "✅ Directories created"

# Setup pre-commit hooks (if available)
if command -v pre-commit &> /dev/null; then
    echo "🔧 Setting up pre-commit hooks..."
    pre-commit install
    echo "✅ Pre-commit hooks installed"
fi

echo ""
echo "✨ Setup complete! ✨"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your API keys"
echo "2. Start services with Docker:"
echo "   cd docker && docker-compose up -d"
echo "3. Or run locally:"
echo "   Backend: source venv/bin/activate && python -m backend.api.main"
echo "   Frontend: cd frontend && npm run dev"
echo ""
echo "📚 Read docs/quick_start.md for more information"
