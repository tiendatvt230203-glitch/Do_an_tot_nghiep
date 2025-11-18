#!/usr/bin/env python3
"""
API Key Management Endpoints
Add these endpoints to your existing api_updated.py
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from api_auth import (
    get_api_key_from_header,
    create_api_key,
    revoke_api_key,
    list_api_keys,
    require_permission
)

# Create router
router = APIRouter(prefix="/api/admin", tags=["API Key Management"])

# Request/Response models
class CreateAPIKeyRequest(BaseModel):
    key_name: str
    created_by: str
    permissions: Optional[dict] = {"read": True, "write": False, "delete": False}
    expires_in_days: Optional[int] = None
    rate_limit: Optional[int] = 1000

class RevokeAPIKeyRequest(BaseModel):
    api_key: str

# ============================================================================
# API Key Management Endpoints (Admin Only)
# ============================================================================

@router.post("/api-keys")
async def create_new_api_key(
    request: CreateAPIKeyRequest,
    api_key_info: dict = Depends(get_api_key_from_header)
):
    """
    Create a new API key (Admin only)

    **Permissions Required:** admin

    **Request Body:**
    ```json
    {
        "key_name": "Mobile App Key",
        "created_by": "admin@example.com",
        "permissions": {
            "read": true,
            "write": true,
            "delete": false
        },
        "expires_in_days": 365,
        "rate_limit": 10000
    }
    ```

    **Response:**
    ```json
    {
        "api_key": "1a2b3c4d5e6f...",
        "key_name": "Mobile App Key",
        "permissions": {...},
        "expires_at": "2025-11-18T00:00:00",
        "rate_limit": 10000
    }
    ```

    ⚠️ **IMPORTANT:** Save the API key immediately! It will NOT be shown again.
    """
    # Check admin permission
    permissions = api_key_info.get('permissions', {})
    if not permissions.get('admin', False):
        raise HTTPException(
            status_code=403,
            detail="Only admins can create API keys"
        )

    try:
        result = create_api_key(
            key_name=request.key_name,
            created_by=request.created_by,
            permissions=request.permissions,
            expires_in_days=request.expires_in_days,
            rate_limit=request.rate_limit
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api-keys")
async def get_api_keys(
    api_key_info: dict = Depends(get_api_key_from_header)
):
    """
    List all API keys (Admin only)

    **Permissions Required:** admin

    **Response:**
    ```json
    [
        {
            "id": 1,
            "key_name": "Mobile App Key",
            "is_active": true,
            "created_by": "admin@example.com",
            "created_at": "2024-11-18T00:00:00",
            "last_used_at": "2024-11-18T10:30:00",
            "expires_at": "2025-11-18T00:00:00",
            "permissions": {"read": true, "write": true},
            "rate_limit": 1000,
            "key_preview": "1a2b3c4d...xyz9"
        }
    ]
    ```
    """
    # Check admin permission
    permissions = api_key_info.get('permissions', {})
    if not permissions.get('admin', False):
        raise HTTPException(
            status_code=403,
            detail="Only admins can list API keys"
        )

    try:
        return list_api_keys()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api-keys/revoke")
async def revoke_key(
    request: RevokeAPIKeyRequest,
    api_key_info: dict = Depends(get_api_key_from_header)
):
    """
    Revoke (deactivate) an API key (Admin only)

    **Permissions Required:** admin

    **Request Body:**
    ```json
    {
        "api_key": "1a2b3c4d5e6f..."
    }
    ```

    **Response:**
    ```json
    {
        "success": true,
        "message": "API key revoked successfully"
    }
    ```
    """
    # Check admin permission
    permissions = api_key_info.get('permissions', {})
    if not permissions.get('admin', False):
        raise HTTPException(
            status_code=403,
            detail="Only admins can revoke API keys"
        )

    try:
        success = revoke_api_key(request.api_key)

        if success:
            return {
                "success": True,
                "message": "API key revoked successfully"
            }
        else:
            raise HTTPException(status_code=404, detail="API key not found")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api-keys/test")
async def test_api_key(
    api_key_info: dict = Depends(get_api_key_from_header)
):
    """
    Test your API key and see your permissions

    **Response:**
    ```json
    {
        "valid": true,
        "key_name": "Your API Key",
        "permissions": {
            "read": true,
            "write": true,
            "delete": false,
            "admin": false
        }
    }
    ```
    """
    return {
        "valid": True,
        "key_name": api_key_info.get('key_name'),
        "permissions": api_key_info.get('permissions'),
        "message": "API key is valid and active"
    }
