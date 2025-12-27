"""
Ollama-powered Text-to-SQL Agent with safety guards.

This agent provides natural language querying capabilities for log investigation.
It uses RAG-style schema prompting and enforces strict safety measures.

Safety Features:
1. Read-only queries only (SELECT)
2. SQL injection guard (blocked keywords)
3. Query validation before execution
4. Human-in-the-loop for suspicious patterns
"""

import re
from dataclasses import dataclass
from typing import Any, Callable

import ollama
from ollama import Client

from ..config import get_settings


@dataclass
class QueryResult:
    """Result of a natural language query."""

    success: bool
    sql: str | None
    results: list[dict[str, Any]] | None
    error: str | None
    requires_approval: bool = False
    approval_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "sql": self.sql,
            "results": self.results,
            "error": self.error,
            "requires_approval": self.requires_approval,
            "approval_reason": self.approval_reason,
        }


class SQLSafetyGuard:
    """
    SQL injection and safety guard.

    Validates generated SQL to prevent:
    - Data modification (INSERT, UPDATE, DELETE)
    - Schema changes (CREATE, ALTER, DROP)
    - Privilege escalation (GRANT, REVOKE)
    - Code execution (EXEC, EXECUTE)
    """

    def __init__(self, blocked_keywords: list[str] | None = None):
        """Initialize with blocked keywords."""
        settings = get_settings()
        self.blocked_keywords = blocked_keywords or settings.sql_blocked_keywords

        # Patterns that require human approval
        self.suspicious_patterns = [
            r"UNION\s+SELECT",
            r";\s*SELECT",  # Multiple statements
            r"--",  # SQL comments (potential injection)
            r"/\*",  # Block comments
            r"INTO\s+OUTFILE",
            r"LOAD_FILE",
            r"BENCHMARK\s*\(",
            r"SLEEP\s*\(",
        ]

    def validate(self, sql: str) -> tuple[bool, str | None, bool]:
        """
        Validate SQL for safety.

        Args:
            sql: SQL query to validate

        Returns:
            Tuple of (is_safe, error_message, requires_approval)
        """
        sql_upper = sql.upper()

        # Check blocked keywords
        for keyword in self.blocked_keywords:
            # Match whole word only
            pattern = rf"\b{keyword}\b"
            if re.search(pattern, sql_upper):
                return False, f"Blocked keyword detected: {keyword}", False

        # Check if it's a SELECT query
        sql_stripped = sql_upper.strip()
        if not sql_stripped.startswith("SELECT") and not sql_stripped.startswith("WITH"):
            return False, "Only SELECT queries are allowed", False

        # Check for suspicious patterns (require approval)
        for pattern in self.suspicious_patterns:
            if re.search(pattern, sql_upper):
                return True, None, True  # Safe but requires approval

        return True, None, False


class OllamaAgent:
    """
    Ollama-powered natural language to SQL agent.

    Uses a local Ollama model for Text-to-SQL translation
    with schema-aware prompting and strict safety guards.
    """

    # Schema template for RAG-style prompting
    SCHEMA_PROMPT = """You are a forensic log analyst assistant. You help investigators query log data using SQL.

## Database Schema

### forensic_logs Table
```sql
CREATE TABLE forensic_logs (
    id INTEGER PRIMARY KEY,
    ingestion_id TEXT UNIQUE,
    arrival_timestamp DATETIME,
    template_id INTEGER,
    template TEXT,
    severity TEXT,  -- 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    log_type TEXT,  -- 'auth', 'syslog', 'application', etc.
    masked_message TEXT,
    raw_message TEXT,
    source_host TEXT,
    source_file TEXT
);
```

### evidence_blocks Table
```sql
CREATE TABLE evidence_blocks (
    block_id INTEGER PRIMARY KEY,
    merkle_root TEXT,
    prev_block_hash TEXT,
    block_hash TEXT,
    timestamp DATETIME,
    log_count INTEGER
);
```

### anomaly_scores Table
```sql
CREATE TABLE anomaly_scores (
    id INTEGER PRIMARY KEY,
    log_id TEXT REFERENCES forensic_logs(ingestion_id),
    score REAL,  -- 0.0 to 1.0
    is_anomaly BOOLEAN,
    detection_method TEXT,
    explanation TEXT
);
```

## Rules
1. Generate ONLY SELECT queries
2. Use proper SQL syntax
3. Always limit results (use LIMIT clause)
4. For time ranges, use datetime functions
5. Return ONLY the SQL query, no explanations

## Examples
User: Show me failed login attempts from yesterday
SQL: SELECT * FROM forensic_logs WHERE template LIKE '%Failed%' AND arrival_timestamp >= datetime('now', '-1 day') LIMIT 100;

User: Find all anomalies with score above 0.8
SQL: SELECT l.*, a.score, a.explanation FROM forensic_logs l JOIN anomaly_scores a ON l.ingestion_id = a.log_id WHERE a.score > 0.8 ORDER BY a.score DESC LIMIT 50;

User: Count logs by severity
SQL: SELECT severity, COUNT(*) as count FROM forensic_logs GROUP BY severity ORDER BY count DESC;
"""

    def __init__(
        self,
        host: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
        execute_fn: Callable[[str], list[dict[str, Any]]] | None = None,
    ):
        """
        Initialize Ollama agent.

        Args:
            host: Ollama server URL (default: localhost:11434)
            model: Model to use (default: llama3.2)
            timeout: Request timeout in seconds
            execute_fn: Function to execute SQL queries (for integration)
        """
        settings = get_settings()

        self.host = host or settings.ollama_host
        self.model = model or settings.ollama_model
        self.timeout = timeout or settings.ollama_timeout
        self.execute_fn = execute_fn

        self.client = Client(host=self.host)
        self.safety_guard = SQLSafetyGuard()

        # Conversation history for context
        self._history: list[dict[str, str]] = []

    def _generate_sql(self, question: str) -> str:
        """Generate SQL from natural language question."""
        messages = [
            {"role": "system", "content": self.SCHEMA_PROMPT},
            *self._history,
            {"role": "user", "content": question},
        ]

        response = self.client.chat(
            model=self.model,
            messages=messages,
            options={"temperature": 0.1},  # Low temperature for deterministic SQL
        )

        sql = response["message"]["content"].strip()

        # Clean up SQL (remove markdown code blocks if present)
        if sql.startswith("```"):
            lines = sql.split("\n")
            sql = "\n".join(lines[1:-1])  # Remove first and last lines

        return sql

    def query(
        self,
        question: str,
        execute: bool = False,
        require_approval: bool = True,
    ) -> QueryResult:
        """
        Convert natural language to SQL and optionally execute.

        Args:
            question: Natural language question
            execute: Whether to execute the query
            require_approval: Whether to require human approval for suspicious queries

        Returns:
            QueryResult with SQL and optional results
        """
        try:
            # Generate SQL
            sql = self._generate_sql(question)

            # Validate SQL
            is_safe, error, needs_approval = self.safety_guard.validate(sql)

            if not is_safe:
                return QueryResult(
                    success=False,
                    sql=sql,
                    results=None,
                    error=f"SQL Safety Check Failed: {error}",
                )

            if needs_approval and require_approval:
                return QueryResult(
                    success=True,
                    sql=sql,
                    results=None,
                    error=None,
                    requires_approval=True,
                    approval_reason="Query contains patterns that require human review",
                )

            # Execute if requested
            results = None
            if execute and self.execute_fn:
                try:
                    results = self.execute_fn(sql)
                except Exception as e:
                    return QueryResult(
                        success=False,
                        sql=sql,
                        results=None,
                        error=f"Query execution failed: {str(e)}",
                    )

            # Add to history for context
            self._history.append({"role": "user", "content": question})
            self._history.append({"role": "assistant", "content": sql})

            # Keep history manageable
            if len(self._history) > 10:
                self._history = self._history[-10:]

            return QueryResult(
                success=True,
                sql=sql,
                results=results,
                error=None,
            )

        except Exception as e:
            return QueryResult(
                success=False,
                sql=None,
                results=None,
                error=f"Query generation failed: {str(e)}",
            )

    def explain_query(self, sql: str) -> str:
        """
        Get natural language explanation of a SQL query.

        Args:
            sql: SQL query to explain

        Returns:
            Natural language explanation
        """
        prompt = f"""Explain this SQL query in simple terms for a forensic investigator:

```sql
{sql}
```

Provide a clear, concise explanation of what this query does and what results to expect."""

        response = self.client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )

        return response["message"]["content"]

    def suggest_queries(self, context: str) -> list[str]:
        """
        Suggest relevant queries based on investigation context.

        Args:
            context: Description of the investigation

        Returns:
            List of suggested natural language queries
        """
        prompt = f"""Based on this forensic investigation context, suggest 5 relevant log queries:

Context: {context}

Provide 5 specific queries that would help investigate this case. Format as a numbered list."""

        response = self.client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )

        # Parse response into list
        content = response["message"]["content"]
        lines = content.strip().split("\n")
        queries = [
            re.sub(r"^\d+\.\s*", "", line.strip())
            for line in lines
            if line.strip() and re.match(r"^\d+\.", line.strip())
        ]

        return queries[:5]  # Limit to 5

    def is_available(self) -> bool:
        """Check if Ollama is available and model is loaded."""
        try:
            models = self.client.list()
            model_names = [m["name"].split(":")[0] for m in models.get("models", [])]
            return self.model.split(":")[0] in model_names
        except Exception:
            return False

    def clear_history(self) -> None:
        """Clear conversation history."""
        self._history = []


def main():
    """Demo Ollama agent functionality."""
    print("Ollama Text-to-SQL Agent Demo\n")

    agent = OllamaAgent()

    # Check availability
    print("Checking Ollama availability...")
    if not agent.is_available():
        print(f"  ✗ Ollama not available or model '{agent.model}' not loaded")
        print(f"  Run: ollama pull {agent.model}")
        return

    print(f"  ✓ Ollama available with model: {agent.model}\n")

    # Test queries
    test_questions = [
        "Show me all failed login attempts",
        "Find the top 10 most suspicious activities",
        "How many logs per severity level?",
    ]

    for question in test_questions:
        print(f"Question: {question}")
        result = agent.query(question)

        if result.success:
            print(f"  SQL: {result.sql}")
            if result.requires_approval:
                print(f"  ⚠ Requires approval: {result.approval_reason}")
        else:
            print(f"  ✗ Error: {result.error}")
        print()

    # Test safety guard
    print("Testing safety guard...")
    malicious_queries = [
        "DROP TABLE forensic_logs",
        "DELETE FROM forensic_logs WHERE id = 1",
        "SELECT * FROM logs; DROP TABLE logs--",
    ]

    guard = SQLSafetyGuard()
    for sql in malicious_queries:
        is_safe, error, _ = guard.validate(sql)
        print(f"  Query: {sql[:40]}...")
        print(f"  Safe: {'✗ No' if not is_safe else '✓ Yes'} - {error or 'Passed'}")


if __name__ == "__main__":
    main()
