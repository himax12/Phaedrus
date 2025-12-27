"""
Forensic Framework - Streamlit UI

A user-friendly interface for log investigation and forensic analysis.
"""

import streamlit as st
import httpx
import json
import logging
import sys
from datetime import datetime
from typing import Any

# ============================================================================
# JSON LOGGING SETUP
# ============================================================================

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add extra fields if present
        if hasattr(record, "request"):
            log_data["request"] = record.request
        if hasattr(record, "response"):
            log_data["response"] = record.response
        if hasattr(record, "duration_ms"):
            log_data["duration_ms"] = record.duration_ms
        if hasattr(record, "endpoint"):
            log_data["endpoint"] = record.endpoint
        if hasattr(record, "status_code"):
            log_data["status_code"] = record.status_code
        if hasattr(record, "error"):
            log_data["error"] = record.error
        if hasattr(record, "action"):
            log_data["action"] = record.action
        if hasattr(record, "data"):
            log_data["data"] = record.data
            
        return json.dumps(log_data, default=str)


def setup_logging():
    """Configure JSON logging for the UI."""
    logger = logging.getLogger("forensic_ui")
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with JSON format
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(JSONFormatter())
    logger.addHandler(console_handler)
    
    return logger


# Initialize logger
logger = setup_logging()


def log_api_call(endpoint: str, method: str, request_data: Any = None):
    """Log API request details."""
    logger.info(
        f"API Request: {method} {endpoint}",
        extra={
            "action": "api_request",
            "endpoint": endpoint,
            "request": request_data,
        }
    )


def log_api_response(endpoint: str, status_code: int, response_data: Any, duration_ms: float):
    """Log API response details."""
    logger.info(
        f"API Response: {endpoint} -> {status_code}",
        extra={
            "action": "api_response", 
            "endpoint": endpoint,
            "status_code": status_code,
            "response": response_data,
            "duration_ms": duration_ms,
        }
    )


def log_error(endpoint: str, error: str, request_data: Any = None):
    """Log API error."""
    logger.error(
        f"API Error: {endpoint} - {error}",
        extra={
            "action": "api_error",
            "endpoint": endpoint,
            "error": error,
            "request": request_data,
        }
    )


def log_user_action(action: str, data: Any = None):
    """Log user actions in the UI."""
    logger.info(
        f"User Action: {action}",
        extra={
            "action": "user_action",
            "data": data,
        }
    )


# ============================================================================
# PAGE CONFIG
# ============================================================================

# Configure page
st.set_page_config(
    page_title="Forensic Framework",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# API base URL
API_URL = "http://localhost:8000"

logger.info("Streamlit UI started", extra={"action": "app_start", "data": {"api_url": API_URL}})


# ============================================================================
# API FUNCTIONS WITH LOGGING
# ============================================================================

def check_api_health():
    """Check if the API is running."""
    endpoint = f"{API_URL}/health"
    log_api_call(endpoint, "GET")
    start_time = datetime.now()
    
    try:
        response = httpx.get(endpoint, timeout=5)
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        result = response.status_code == 200
        log_api_response(endpoint, response.status_code, {"healthy": result}, duration_ms)
        return result
    except Exception as e:
        log_error(endpoint, str(e))
        return False


def ingest_logs(logs: list[str], source_host: str, log_type: str):
    """Ingest logs via API."""
    endpoint = f"{API_URL}/ingest/batch"
    request_data = {
        "logs": logs,
        "source_host": source_host,
        "log_type": log_type,
        "log_count": len(logs),
    }
    
    log_api_call(endpoint, "POST", request_data)
    start_time = datetime.now()
    
    try:
        response = httpx.post(
            endpoint,
            json={
                "logs": logs,
                "source_host": source_host,
                "log_type": log_type,
            },
            timeout=30,
        )
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        result = response.json()
        
        log_api_response(endpoint, response.status_code, result, duration_ms)
        return result
    except Exception as e:
        log_error(endpoint, str(e), request_data)
        return {"error": str(e)}


def query_logs(question: str, execute: bool = False):
    """Query logs using natural language."""
    endpoint = f"{API_URL}/query/natural"
    request_data = {
        "question": question,
        "execute": execute,
        "require_approval": False,
    }
    
    log_api_call(endpoint, "POST", request_data)
    start_time = datetime.now()
    
    try:
        response = httpx.post(
            endpoint,
            json=request_data,
            timeout=60,
        )
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        result = response.json()
        
        log_api_response(endpoint, response.status_code, result, duration_ms)
        return result
    except Exception as e:
        log_error(endpoint, str(e), request_data)
        return {"error": str(e)}


def verify_chain():
    """Verify the chain integrity."""
    endpoint = f"{API_URL}/verify/chain"
    log_api_call(endpoint, "GET")
    start_time = datetime.now()
    
    try:
        response = httpx.get(endpoint, timeout=10)
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        result = response.json()
        
        log_api_response(endpoint, response.status_code, result, duration_ms)
        return result
    except Exception as e:
        log_error(endpoint, str(e))
        return {"error": str(e)}


def get_templates():
    """Get discovered log templates."""
    endpoint = f"{API_URL}/ingest/templates"
    log_api_call(endpoint, "GET")
    start_time = datetime.now()
    
    try:
        response = httpx.get(endpoint, timeout=10)
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        result = response.json()
        
        log_api_response(endpoint, response.status_code, result, duration_ms)
        return result
    except Exception as e:
        log_error(endpoint, str(e))
        return {"error": str(e)}


# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/search--v1.png", width=80)
    st.title("Forensic Framework")
    st.markdown("---")
    
    # API Status
    api_status = check_api_health()
    if api_status:
        st.success("✅ API Connected")
    else:
        st.error("❌ API Offline")
        st.info("Start the API with:\n```\nuv run uvicorn src.forensic_framework.main:app --port 8000\n```")
    
    st.markdown("---")
    
    # Navigation
    page = st.radio(
        "Navigation",
        ["🏠 Dashboard", "📥 Ingest Logs", "🔍 Query", "🔐 Integrity", "📊 Templates"],
        label_visibility="collapsed",
    )

# Main content
if page == "🏠 Dashboard":
    st.title("🔍 Forensic Log Investigation")
    st.markdown("AI-powered log analysis with Drain3, Ollama, and Merkle Tree integrity.")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("API Status", "Online" if api_status else "Offline")
    
    with col2:
        if api_status:
            templates = get_templates()
            if "stats" in templates:
                st.metric("Templates Discovered", templates["stats"].get("total_clusters", 0))
            else:
                st.metric("Templates Discovered", "N/A")
        else:
            st.metric("Templates Discovered", "N/A")
    
    with col3:
        if api_status:
            chain = verify_chain()
            if "chain_length" in chain:
                st.metric("Evidence Blocks", chain.get("chain_length", 0))
            else:
                st.metric("Evidence Blocks", "N/A")
        else:
            st.metric("Evidence Blocks", "N/A")
    
    st.markdown("---")
    
    st.subheader("Quick Actions")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📥 Ingest Sample Logs", use_container_width=True):
            sample_logs = [
                "Failed password for root from 192.168.1.100 port 22 ssh2",
                "Failed password for admin from 10.0.0.50 port 22 ssh2",
                "Accepted publickey for user1 from 172.16.0.1 port 54321 ssh2",
                "session opened for user root by root(uid=0)",
            ]
            result = ingest_logs(sample_logs, "webserver", "auth")
            if "error" in result:
                st.error(f"Error: {result['error']}")
            else:
                st.success(f"✅ Ingested {result.get('ingested_count', 0)} logs!")
    
    with col2:
        if st.button("🔐 Verify Chain Integrity", use_container_width=True):
            result = verify_chain()
            if "error" in result:
                st.error(f"Error: {result['error']}")
            else:
                st.json(result)

elif page == "📥 Ingest Logs":
    st.title("📥 Log Ingestion")
    st.markdown("Parse and ingest logs using Drain3 automated template extraction.")
    
    # Input method
    input_method = st.radio("Input Method", ["Paste Logs", "Upload File"], horizontal=True)
    
    if input_method == "Paste Logs":
        logs_text = st.text_area(
            "Enter logs (one per line)",
            height=200,
            placeholder="Failed password for root from 192.168.1.100 port 22 ssh2\nAccepted publickey for user1 from 10.0.0.1 port 22 ssh2",
        )
    else:
        uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"])
        if uploaded_file:
            logs_text = uploaded_file.read().decode("utf-8")
            st.text_area("File contents", logs_text, height=200, disabled=True)
        else:
            logs_text = ""
    
    col1, col2 = st.columns(2)
    with col1:
        source_host = st.text_input("Source Host", value="webserver")
    with col2:
        log_type = st.selectbox("Log Type", ["auth", "syslog", "application", "security", "access"])
    
    if st.button("🚀 Ingest Logs", type="primary", use_container_width=True):
        if logs_text.strip():
            logs = [line.strip() for line in logs_text.strip().split("\n") if line.strip()]
            with st.spinner("Ingesting logs..."):
                result = ingest_logs(logs, source_host, log_type)
            
            if "error" in result:
                st.error(f"Error: {result['error']}")
            elif "detail" in result:
                st.error(f"Error: {result['detail']}")
            else:
                st.success(f"✅ Successfully ingested {result.get('ingested_count', 0)} logs!")
                st.info(f"📋 Templates discovered: {result.get('templates_discovered', 0)}")
                
                with st.expander("View Log IDs"):
                    st.json(result.get("log_ids", []))
        else:
            st.warning("Please enter some logs to ingest.")

elif page == "🔍 Query":
    st.title("🔍 Natural Language Query")
    st.markdown("Ask questions about your logs using natural language. Powered by Ollama.")
    
    question = st.text_input(
        "Ask a question",
        placeholder="Show me all failed login attempts from yesterday",
    )
    
    execute = st.checkbox("Execute query and show results", value=False)
    
    if st.button("🔍 Search", type="primary", use_container_width=True):
        if question.strip():
            with st.spinner("Generating SQL query..."):
                result = query_logs(question, execute)
            
            if "error" in result:
                st.error(f"Error: {result['error']}")
            elif result.get("success"):
                st.subheader("Generated SQL")
                st.code(result.get("sql", "No SQL generated"), language="sql")
                
                if result.get("requires_approval"):
                    st.warning(f"⚠️ Requires approval: {result.get('approval_reason')}")
                
                if result.get("results"):
                    st.subheader("Query Results")
                    st.dataframe(result["results"])
            else:
                st.error(f"Query failed: {result.get('error', 'Unknown error')}")
        else:
            st.warning("Please enter a question.")
    
    st.markdown("---")
    st.subheader("Example Queries")
    examples = [
        "Show me all failed login attempts",
        "Find logs from the last hour",
        "Count logs by severity level",
        "Show authentication events with severity ERROR",
    ]
    for ex in examples:
        if st.button(f"📝 {ex}", key=ex):
            st.session_state["query"] = ex

elif page == "🔐 Integrity":
    st.title("🔐 Chain Integrity Verification")
    st.markdown("Verify the Merkle Tree logchain to detect any tampering.")
    
    if st.button("🔍 Verify Chain", type="primary", use_container_width=True):
        with st.spinner("Verifying chain integrity..."):
            result = verify_chain()
        
        if "error" in result:
            st.error(f"Error: {result['error']}")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Chain Length", result.get("chain_length", 0))
            with col2:
                st.metric("Pending Logs", result.get("pending_logs", 0))
            
            if result.get("latest_block"):
                st.subheader("Latest Block")
                st.json(result["latest_block"])
    
    st.markdown("---")
    
    if st.button("🔒 Seal Evidence Block", use_container_width=True):
        try:
            response = httpx.post(f"{API_URL}/verify/seal?force=true", timeout=10)
            result = response.json()
            if result.get("success"):
                st.success(f"✅ Sealed block #{result.get('block_id')} with {result.get('log_count')} logs")
                st.code(f"Merkle Root: {result.get('merkle_root')}")
            else:
                st.info("No pending logs to seal.")
        except Exception as e:
            st.error(f"Error: {e}")

elif page == "📊 Templates":
    st.title("📊 Log Templates")
    st.markdown("View discovered log templates from Drain3 parsing.")
    
    if st.button("🔄 Refresh Templates", use_container_width=True):
        st.rerun()
    
    result = get_templates()
    
    if "error" in result:
        st.error(f"Error: {result['error']}")
    else:
        if "stats" in result:
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Templates", result["stats"].get("total_clusters", 0))
            with col2:
                st.metric("Total Logs Parsed", result["stats"].get("total_logs_parsed", 0))
        
        st.markdown("---")
        
        if "templates" in result and result["templates"]:
            for template in result["templates"]:
                with st.expander(f"Template #{template['cluster_id']} ({template['size']} logs)"):
                    st.code(template["template"])
        else:
            st.info("No templates discovered yet. Ingest some logs first!")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "Forensic Framework v1.0 | Powered by Drain3, Ollama, and FastAPI"
    "</div>",
    unsafe_allow_html=True,
)
