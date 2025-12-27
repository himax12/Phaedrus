# AI-Powered Forensic Log Investigation Framework

A next-generation log investigation system using Ollama and open-source tools. Transform raw logs into structured evidence, ensure forensic integrity via Merkle Trees, and provide explainable AI insights.

## Features

- **🔍 Intelligent Log Parsing**: Drain3-powered automated template extraction
- **🔐 Forensic Integrity**: Merkle Tree logchain with tamper detection
- **🤖 AI Correlation**: Anomaly detection and attack path reconstruction
- **💬 Natural Language Queries**: Ollama-powered Text-to-SQL agent
- **📊 Explainability**: SHAP waterfall plots for AI decisions
- **📄 ISO 27037 Reports**: Court-ready forensic documentation

## Tech Stack

| Component | Tool |
|-----------|------|
| LLM | Ollama (llama3.2) |
| Log Parsing | Drain3 |
| Explainability | SHAP |
| Graph Analysis | NetworkX |
| API | FastAPI |
| Database | SQLite (dev) / ClickHouse (prod) |
| Reports | Jinja2 + WeasyPrint |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (fast Python package manager)
- [Ollama](https://ollama.ai/) with a model pulled (e.g., `ollama pull llama3.2`)

### Installation

```bash
# Clone and enter the project
cd forensic_framework

# Install dependencies with uv
uv sync

# Install dev dependencies
uv sync --extra dev

# (Optional) Install ML dependencies for LogBERT
uv sync --extra ml
```

### Running the API

```bash
# Start the FastAPI server
uv run uvicorn src.forensic_framework.main:app --reload --port 8000
```

### Running Tests

```bash
uv run pytest tests/ -v
```

## Project Structure

```
forensic_framework/
├── src/forensic_framework/
│   ├── ingestion/       # Drain3 log parsing
│   ├── integrity/       # Merkle Tree logchain
│   ├── ai_engine/       # Ollama agent, anomaly detection
│   ├── explainability/  # SHAP visualizations
│   ├── reporting/       # ISO 27037 PDF reports
│   ├── api/             # FastAPI routes
│   └── storage/         # Database layer
├── tests/
└── pyproject.toml
```

## Usage Examples

### Parse Logs with Drain3

```python
from forensic_framework.ingestion import DrainParser

parser = DrainParser()
result = parser.parse("Failed password for root from 192.168.1.100 port 22 ssh2")
print(result.template)  # "Failed password for <*> from <*> port <*> ssh2"
```

### Verify Log Integrity

```python
from forensic_framework.integrity import LogChain

chain = LogChain()
chain.add_evidence_block(logs)
is_valid = chain.verify()  # Returns False if tampered
```

### Natural Language Query

```python
from forensic_framework.ai_engine import OllamaAgent

agent = OllamaAgent()
result = agent.query("Show me all failed SSH logins from yesterday")
# Generates safe SQL and returns results
```

## License

MIT
