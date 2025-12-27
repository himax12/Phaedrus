"""
Integrity verification API routes.
"""

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..integrity import LogChain, IntegrityVerifier

router = APIRouter(prefix="/verify", tags=["Integrity"])


class VerifyLogRequest(BaseModel):
    """Request to verify a specific log."""

    log_id: str = Field(..., description="Log ID to verify")
    content: str = Field(..., description="Log content to verify against chain")


class SealBlockResponse(BaseModel):
    """Response from sealing an evidence block."""

    success: bool
    block_id: int | None = None
    merkle_root: str | None = None
    block_hash: str | None = None
    log_count: int = 0


# Global chain instance
_chain: LogChain | None = None


def get_chain() -> LogChain:
    """Get or create global LogChain."""
    global _chain
    if _chain is None:
        from ..config import get_settings
        settings = get_settings()
        chain_file = settings.data_dir / "logchain.json"
        _chain = LogChain(
            block_interval_seconds=settings.evidence_block_interval_seconds,
            chain_file=chain_file,
        )
    return _chain


@router.get("/chain")
async def get_chain_status() -> dict[str, Any]:
    """Get current chain status and statistics."""
    chain = get_chain()

    return {
        "chain_length": chain.length,
        "pending_logs": chain.pending_count,
        "latest_block": chain.latest_block.to_dict() if chain.latest_block else None,
    }


@router.post("/seal")
async def seal_evidence_block(force: bool = False) -> SealBlockResponse:
    """
    Seal pending logs into an evidence block.

    Creates a new block with Merkle root if logs are pending.
    """
    chain = get_chain()

    block = chain.seal_block(force=force)

    if block is None:
        return SealBlockResponse(success=False)

    return SealBlockResponse(
        success=True,
        block_id=block.block_id,
        merkle_root=block.merkle_root,
        block_hash=block.block_hash,
        log_count=block.log_count,
    )


@router.get("/chain/verify")
async def verify_chain() -> dict[str, Any]:
    """
    Verify the entire chain integrity.

    Returns verification status and any detected issues.
    """
    chain = get_chain()
    verifier = IntegrityVerifier(chain)

    result = verifier.verify_chain()
    return result.to_dict()


@router.get("/block/{block_id}")
async def get_block(block_id: int) -> dict[str, Any]:
    """Get a specific block by ID."""
    chain = get_chain()

    block = chain.get_block(block_id)
    if block is None:
        raise HTTPException(status_code=404, detail=f"Block {block_id} not found")

    return block.to_dict()


@router.get("/block/{block_id}/verify")
async def verify_block(block_id: int) -> dict[str, Any]:
    """Verify a specific block's integrity."""
    chain = get_chain()
    verifier = IntegrityVerifier(chain)

    result = verifier.verify_block(block_id)

    if not result.is_valid and "not found" in result.message:
        raise HTTPException(status_code=404, detail=result.message)

    return result.to_dict()


@router.post("/log")
async def verify_log(request: VerifyLogRequest) -> dict[str, Any]:
    """
    Verify a log exists in the chain.

    Checks if the log content matches what's recorded.
    """
    chain = get_chain()
    verifier = IntegrityVerifier(chain)

    result = verifier.verify_log_exists(request.log_id, request.content)
    return result.to_dict()


@router.get("/report")
async def get_verification_report() -> dict[str, Any]:
    """
    Generate comprehensive verification report.

    Verifies all blocks and provides detailed status.
    """
    chain = get_chain()
    verifier = IntegrityVerifier(chain)

    return verifier.generate_verification_report()


@router.get("/export")
async def export_for_anchoring() -> dict[str, Any]:
    """
    Export block hashes for external blockchain anchoring.

    Returns minimal data needed for cross-referencing with
    public blockchain records.
    """
    chain = get_chain()

    return {
        "chain_length": chain.length,
        "blocks": chain.export_for_anchoring(),
    }


@router.post("/add-log")
async def add_log_to_chain(log_id: str, content: str) -> dict[str, str]:
    """
    Add a log to the pending buffer.

    The log will be included in the next evidence block.
    """
    chain = get_chain()
    chain.add_log(log_id, content)

    return {
        "status": "added",
        "pending_count": str(chain.pending_count),
    }
