"""
Query API routes with Ollama natural language processing.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..ai_engine import OllamaAgent
from ..storage import get_db

logger = logging.getLogger("forensic_framework.query")

router = APIRouter(prefix="/query", tags=["Query"])


class NLQueryRequest(BaseModel):
    """Natural language query request."""

    question: str = Field(..., description="Natural language question")
    execute: bool = Field(False, description="Whether to execute the generated SQL")
    require_approval: bool = Field(True, description="Require approval for suspicious queries")


class NLQueryResponse(BaseModel):
    """Natural language query response."""

    success: bool
    sql: str | None
    results: list[dict[str, Any]] | None = None
    error: str | None = None
    requires_approval: bool = False
    approval_reason: str | None = None


class SQLQueryRequest(BaseModel):
    """Direct SQL query request."""

    sql: str = Field(..., description="SQL query to execute")


class QuerySuggestionRequest(BaseModel):
    """Request for query suggestions."""

    context: str = Field(..., description="Investigation context")


# Agent instance (lazy loaded)
_agent: OllamaAgent | None = None


def get_agent() -> OllamaAgent:
    """Get or create shared Ollama agent."""
    global _agent
    if _agent is None:
        logger.info("🤖 Initializing Ollama agent")
        db = get_db()
        _agent = OllamaAgent(execute_fn=lambda sql: _execute_sql_sync(sql))
    return _agent


def _execute_sql_sync(sql: str) -> list[dict[str, Any]]:
    """Execute SQL synchronously (for agent callback)."""
    import asyncio
    db = get_db()
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(db.execute_raw(sql))


@router.post("/natural", response_model=NLQueryResponse)
async def natural_language_query(request: NLQueryRequest) -> NLQueryResponse:
    """
    Convert natural language to SQL and optionally execute.

    Uses Ollama to translate questions into safe SQL queries.
    """
    logger.info(f"🔍 Natural language query: {request.question[:50]}...")
    
    try:
        agent = get_agent()

        # Check if Ollama is available
        if not agent.is_available():
            logger.warning("⚠️ Ollama not available")
            raise HTTPException(
                status_code=503,
                detail=f"Ollama not available. Ensure it's running and model '{agent.model}' is loaded.",
            )

        result = agent.query(
            request.question,
            execute=request.execute,
            require_approval=request.require_approval,
        )
        
        logger.info(f"✅ Query generated SQL: {result.sql[:50] if result.sql else 'None'}...")
        if result.requires_approval:
            logger.warning(f"⚠️ Query requires approval: {result.approval_reason}")

        return NLQueryResponse(
            success=result.success,
            sql=result.sql,
            results=result.results,
            error=result.error,
            requires_approval=result.requires_approval,
            approval_reason=result.approval_reason,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in natural language query: {e}", exc_info=True)
        raise


@router.post("/sql")
async def execute_sql(request: SQLQueryRequest) -> dict[str, Any]:
    """
    Execute a raw SQL query (SELECT only).

    Direct SQL execution for advanced users.
    """
    logger.info(f"📊 Executing SQL: {request.sql[:50]}...")
    
    db = get_db()

    try:
        results = await db.execute_raw(request.sql)
        logger.info(f"✅ SQL executed successfully: {len(results)} rows returned")
        return {
            "success": True,
            "row_count": len(results),
            "results": results,
        }
    except ValueError as e:
        logger.warning(f"⚠️ Invalid SQL: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"❌ SQL execution failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


@router.post("/suggestions")
async def get_query_suggestions(request: QuerySuggestionRequest) -> dict[str, list[str]]:
    """
    Get suggested queries based on investigation context.

    Uses Ollama to generate relevant forensic queries.
    """
    logger.info(f"💡 Getting query suggestions for context: {request.context[:50]}...")
    
    agent = get_agent()

    if not agent.is_available():
        logger.warning("⚠️ Ollama not available")
        raise HTTPException(
            status_code=503,
            detail="Ollama not available",
        )

    suggestions = agent.suggest_queries(request.context)
    logger.info(f"✅ Generated {len(suggestions)} query suggestions")
    return {"suggestions": suggestions}


@router.post("/explain")
async def explain_sql(request: SQLQueryRequest) -> dict[str, str]:
    """
    Get natural language explanation of a SQL query.

    Useful for understanding complex queries in reports.
    """
    logger.info(f"📖 Explaining SQL: {request.sql[:50]}...")
    
    agent = get_agent()

    if not agent.is_available():
        logger.warning("⚠️ Ollama not available")
        raise HTTPException(
            status_code=503,
            detail="Ollama not available",
        )

    explanation = agent.explain_query(request.sql)
    logger.info("✅ SQL explanation generated")
    return {"explanation": explanation}


@router.get("/status")
async def get_agent_status() -> dict[str, Any]:
    """Get Ollama agent status."""
    logger.debug("Checking Ollama agent status")
    
    agent = get_agent()
    is_available = agent.is_available()
    
    logger.info(f"🤖 Ollama status: {'available' if is_available else 'unavailable'}")

    return {
        "ollama_available": is_available,
        "model": agent.model,
        "host": agent.host,
    }

