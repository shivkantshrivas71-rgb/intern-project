"""
modules/agents/routes.py — Agent Module CRUD Routes

Complete CRUD endpoints for business operational agents.
No password hashing — standard fields: name, phone, email, status.
"""
import datetime

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status

from database import agents_collection
from core.helpers import serialize_doc, serialize_list
from modules.auth.auth import get_current_user, get_admin_user
from modules.agents.schemas import AgentCreate, AgentUpdate, AgentResponse, AgentListResponse

router = APIRouter(prefix="/agents", tags=["Agents"])


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPER
# ─────────────────────────────────────────────────────────────────────────────

async def _get_agent_or_404(agent_id: str) -> dict:
    """Validate the agent ID and fetch the document, or raise a 404 error."""
    if not ObjectId.is_valid(agent_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid agent ID format: '{agent_id}'",
        )
    agent = await agents_collection.find_one({"_id": ObjectId(agent_id)})
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with ID '{agent_id}' not found.",
        )
    return agent


# ─────────────────────────────────────────────────────────────────────────────
# CREATE
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/",
    summary="Create a new agent",
    status_code=status.HTTP_201_CREATED,
)
async def create_agent(
    agent_data: AgentCreate,
    current_user: dict = Depends(get_current_user),
):
    """
    Create a new agent record.
    - The phone number must be unique across all agents.
    - Authentication is required (any logged-in user).
    """
    # Check phone number uniqueness
    if await agents_collection.find_one({"phone": agent_data.phone}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Agent with phone '{agent_data.phone}' already exists.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    agent_doc = {
        **agent_data.model_dump(exclude_none=False),
        "created_by": current_user["username"],
        "created_at": now,
        "updated_at": now,
    }
    result = await agents_collection.insert_one(agent_doc)
    agent_doc["_id"] = result.inserted_id
    return serialize_doc(agent_doc)


# ─────────────────────────────────────────────────────────────────────────────
# READ — List (Paginated + Filter)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/",
    summary="Get all agents (paginated)",
)
async def list_agents(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=10, ge=1, le=100, description="Items per page"),
    status_filter: str = Query(default=None, alias="status", description="Filter by status: active/inactive/suspended"),
    search: str = Query(default=None, description="Search by name or phone"),
    current_user: dict = Depends(get_current_user),
):
    """
    Return a paginated list of all agents.
    Supports optional filtering by status and searching by name or phone number.
    """
    query: dict = {}

    if status_filter:
        if status_filter not in ("active", "inactive", "suspended"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status filter. Use: active, inactive, or suspended.",
            )
        query["status"] = status_filter

    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"phone": {"$regex": search, "$options": "i"}},
        ]

    total = await agents_collection.count_documents(query)
    skip = (page - 1) * page_size

    agents = []
    async for agent in agents_collection.find(query).skip(skip).limit(page_size).sort("created_at", -1):
        agents.append(serialize_doc(agent))

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "agents": agents,
    }


# ─────────────────────────────────────────────────────────────────────────────
# READ — Single Agent
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/{agent_id}",
    summary="Get a single agent by ID",
)
async def get_agent(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve the full details of a single agent by its ID."""
    agent = await _get_agent_or_404(agent_id)
    return serialize_doc(agent)


# ─────────────────────────────────────────────────────────────────────────────
# UPDATE
# ─────────────────────────────────────────────────────────────────────────────

@router.put(
    "/{agent_id}",
    summary="Update agent details",
)
async def update_agent(
    agent_id: str,
    agent_data: AgentUpdate,
    current_user: dict = Depends(get_current_user),
):
    """
    Update an agent's data. Only the provided fields will be updated (partial update).
    A uniqueness check is performed if the phone number is being changed.
    """
    await _get_agent_or_404(agent_id)

    update_fields = agent_data.model_dump(exclude_none=True, exclude_unset=True)
    if not update_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields provided to update.",
        )

    # Check phone uniqueness if the phone number is being changed
    if "phone" in update_fields:
        conflict = await agents_collection.find_one(
            {"phone": update_fields["phone"], "_id": {"$ne": ObjectId(agent_id)}}
        )
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Phone '{update_fields['phone']}' already used by another agent.",
            )

    update_fields["updated_at"] = datetime.datetime.now(datetime.timezone.utc)
    await agents_collection.update_one(
        {"_id": ObjectId(agent_id)}, {"$set": update_fields}
    )
    updated = await agents_collection.find_one({"_id": ObjectId(agent_id)})
    return serialize_doc(updated)


# ─────────────────────────────────────────────────────────────────────────────
# DELETE
# ─────────────────────────────────────────────────────────────────────────────

@router.delete(
    "/{agent_id}",
    summary="Delete an agent (Admin only)",
)
async def delete_agent(
    agent_id: str,
    admin: dict = Depends(get_admin_user),
):
    """
    Permanently delete an agent record.
    Only administrators are permitted to delete agents.
    """
    await _get_agent_or_404(agent_id)
    await agents_collection.delete_one({"_id": ObjectId(agent_id)})
    return {"message": f"Agent '{agent_id}' deleted successfully."}


# ─────────────────────────────────────────────────────────────────────────────
# BULK STATUS UPDATE (Admin only)
# ─────────────────────────────────────────────────────────────────────────────

@router.patch(
    "/bulk/status",
    summary="Bulk update agent status (Admin only)",
)
async def bulk_update_status(
    agent_ids: list[str],
    new_status: str = Query(..., description="New status: active/inactive/suspended"),
    admin: dict = Depends(get_admin_user),
):
    """
    Update the status of multiple agents in a single request.
    Admin-only endpoint.
    """
    if new_status not in ("active", "inactive", "suspended"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid status. Use: active, inactive, or suspended.",
        )

    valid_ids = []
    for aid in agent_ids:
        if not ObjectId.is_valid(aid):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid agent ID format: '{aid}'",
            )
        valid_ids.append(ObjectId(aid))

    now = datetime.datetime.now(datetime.timezone.utc)
    result = await agents_collection.update_many(
        {"_id": {"$in": valid_ids}},
        {"$set": {"status": new_status, "updated_at": now}},
    )
    return {
        "message": f"{result.modified_count} agents updated to '{new_status}' status.",
        "modified_count": result.modified_count,
    }
