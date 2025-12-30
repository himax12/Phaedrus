AI-Powered Forensic Log Investigation Framework

A next-generation log investigation system using Ollama and open-source tools.
It transforms raw logs into structured forensic evidence, ensures integrity using Merkle Trees, and provides explainable AI insights suitable for audits, incident response, and legal proceedings.

Features

Intelligent log parsing using Drain3 automated template extraction

Forensic integrity via Merkle Tree–based logchain with tamper detection

AI-driven anomaly detection and attack path reconstruction

Natural language investigation using an Ollama-powered Text-to-SQL agent

Explainable AI decisions using SHAP waterfall plots

ISO 27037–aligned, court-ready forensic reports

Tech Stack
Component	Tool
LLM	Ollama (llama3.2)
Log Parsing	Drain3
Explainability	SHAP
Graph Analysis	NetworkX
API	FastAPI
Database	SQLite (dev) / ClickHouse (prod)
Reports	Jinja2 + WeasyPrint
UI	Streamlit
Architecture (Mermaid.js)
flowchart TB
    A["User / UI / API submits logs"]
    B["Drain3 Log Parser"]
    C["Parsed Templates & Entities"]
    D["Merkle Tree Logchain"]
    E["Integrity Verification"]
    F["Ollama AI Engine (Anomaly Detection / Text-to-SQL)"]
    G["Correlations & Anomalies"]
    H["SHAP Explainability Engine"]
    I["Feature-wise Explanations"]
    J["ISO 27037 PDF Report Generator"]
    K["FastAPI Backend (/ingest, /query, /verify, /report)"]
    L["Streamlit UI"]

    A --> K
    K --> B
    B --> C
    C --> D
    C --> F
    D --> E
    F --> G
    G --> H
    H --> I

    E --> J
    I --> J
    G --> J

    J --> K
    K --> L

Quick Start
Prerequisites

Python 3.11+

uv (fast Python package manager)

Ollama with a model pulled

ollama pull llama3.2

Installation
# Enter the project
cd forensic_framework

# Install dependencies
uv sync

# Install development dependencies
uv sync --extra dev

# Optional: ML dependencies
uv sync --extra ml

Running the API
uv run uvicorn src.forensic_framework.main:app --reload --port 8000


Available endpoints:

/ingest

/query

/verify

/report

Running Tests
uv run pytest tests/ -v

Project Structure
forensic_framework/
├── src/forensic_framework/
│   ├── ingestion/        # Drain3 log parsing
│   ├── integrity/        # Merkle Tree logchain
│   ├── ai_engine/        # Ollama agents and anomaly detection
│   ├── explainability/   # SHAP visualizations
│   ├── reporting/        # ISO 27037 PDF reports
│   ├── api/              # FastAPI routes
│   └── storage/          # Database layer
├── tests/
└── pyproject.toml

Usage Examples
Parse Logs with Drain3
from forensic_framework.ingestion import DrainParser

parser = DrainParser()
result = parser.parse(
    "Failed password for root from 192.168.1.100 port 22 ssh2"
)

print(result.template)
# Failed password for <*> from <*> port <*> ssh2

Verify Log Integrity
from forensic_framework.integrity import LogChain

chain = LogChain()
chain.add_evidence_block(logs)

is_valid = chain.verify()
# Returns False if logs were tampered

Natural Language Query
from forensic_framework.ai_engine import OllamaAgent

agent = OllamaAgent()
result = agent.query(
    "Show me all failed SSH logins from yesterday"
)


The agent converts intent into safe SQL and returns structured results.

Forensic Guarantees

Deterministic evidence hashing

Tamper-evident chain of custody

Explainable AI decisions

ISO 27037–aligned reporting

The system prioritizes verifiability over prediction.

License

MIT License
