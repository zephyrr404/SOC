import secrets
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from app.database import get_db, get_next_id
from app.auth import get_current_user
from app.dependencies import get_owned_project, get_owned_api_key
from app.models.api_key import ApiKeyCreate, ApiKeyCreated
from app.services.reachable import reachable_backend_url
from app.services.prompt_templates import build_ai_agent_prompt

router = APIRouter(dependencies=[Depends(get_current_user)])


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@router.post("/projects/{project_id}/api-keys", summary="Create a website API key (one-time key reveal)")
def create_api_key(body: ApiKeyCreate, project=Depends(get_owned_project), db=Depends(get_db)):
    """Create a key for the website snippet; the plaintext key is returned only once."""
    project_id = project["id"]
    raw_key = f"soc_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)
    api_key = {
        "id": get_next_id("api_keys"),
        "project_id": project_id,
        "key_hash": key_hash,
        "label": body.label,
        "created_at": datetime.now(timezone.utc),
        "last_used_at": None,
        "revoked": False,
    }
    db.api_keys.insert_one(api_key)
    # The plaintext key exists only in this response (stored as a hash), so the
    # reveal step gets the fully-filled script tag + AI-agent prompt right here.
    base_url = reachable_backend_url()
    script_tag = (
        f'<script src="{base_url}/agents/usp.js" '
        f'data-soc-key="{raw_key}" data-soc-host="{base_url}"></script>'
    )
    created = ApiKeyCreated(id=api_key["id"], label=api_key["label"], key=raw_key, created_at=api_key["created_at"])
    return {
        **created.model_dump(),
        "script_tag": script_tag,
        "ai_agent_prompt": build_ai_agent_prompt(base_url, raw_key),
        "backend_url": base_url,
    }


@router.get("/projects/{project_id}/api-keys", summary="List a project's website API keys")
def list_api_keys(project=Depends(get_owned_project), db=Depends(get_db)):
    project_id = project["id"]
    keys = list(db.api_keys.find({"project_id": project_id}, {"_id": 0, "key_hash": 0}).sort("created_at", -1))
    return keys


@router.delete("/api-keys/{key_id}", summary="Revoke a website API key")
def revoke_api_key(key=Depends(get_owned_api_key), db=Depends(get_db)):
    db.api_keys.update_one({"id": key["id"]}, {"$set": {"revoked": True}})
    return {"message": "Key revoked"}
