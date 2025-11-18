#!/usr/bin/env python3
"""
API Key Authentication System
Middleware and utilities for API key validation
"""

import hashlib
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps
from fastapi import HTTPException, Header, Request
from sqlalchemy import text
from typing import Optional

# Database connection (import from your main app)
def get_db_connection():
    """Get database connection - reuse your existing connection"""
    from sqlalchemy import create_engine
    DATABASE_URL = "postgresql://postgres:postgres@localhost/email_gateway"
    engine = create_engine(DATABASE_URL)
    return engine.connect()

def generate_api_key() -> str:
    """
    Generate a secure random API key
    Returns: 64-character hexadecimal string
    """
    return secrets.token_hex(32)

def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for storage (not actually hashing for simplicity)
    In production, you might want to hash it for extra security
    """
    return api_key

def verify_api_key(api_key: str) -> dict:
    """
    Verify API key and return key information

    Args:
        api_key: The API key to verify

    Returns:
        dict with key info if valid, None if invalid
    """
    conn = get_db_connection()

    try:
        # Check if key exists and is active
        result = conn.execute(text("""
            SELECT id, key_name, is_active, permissions, expires_at,
                   rate_limit_requests, rate_limit_window, last_used_at
            FROM api_keys
            WHERE api_key = :key AND is_active = TRUE
        """), {"key": api_key}).fetchone()

        if not result:
            return None

        key_id, key_name, is_active, permissions, expires_at, rate_limit_requests, rate_limit_window, last_used_at = result

        # Check if key has expired
        if expires_at and datetime.now() > expires_at:
            return None

        # Check rate limiting
        if rate_limit_requests and rate_limit_window:
            # Count requests in the last window
            window_start = datetime.now() - timedelta(seconds=rate_limit_window)
            count = conn.execute(text("""
                SELECT COUNT(*) FROM api_key_logs
                WHERE api_key_id = :key_id AND request_time > :window_start
            """), {"key_id": key_id, "window_start": window_start}).scalar()

            if count >= rate_limit_requests:
                return {
                    "error": "rate_limit_exceeded",
                    "message": f"Rate limit exceeded: {rate_limit_requests} requests per {rate_limit_window} seconds"
                }

        # Update last_used_at
        conn.execute(text("""
            UPDATE api_keys SET last_used_at = NOW() WHERE id = :key_id
        """), {"key_id": key_id})
        conn.commit()

        return {
            "id": key_id,
            "key_name": key_name,
            "permissions": json.loads(permissions) if permissions else {},
            "is_active": is_active
        }

    finally:
        conn.close()

def log_api_request(api_key_id: int, endpoint: str, method: str, ip_address: str,
                    user_agent: str, status_code: int, response_time_ms: int):
    """
    Log API request for monitoring and audit
    """
    conn = get_db_connection()

    try:
        conn.execute(text("""
            INSERT INTO api_key_logs
            (api_key_id, endpoint, method, ip_address, user_agent, status_code, response_time_ms)
            VALUES (:key_id, :endpoint, :method, :ip, :ua, :status, :time)
        """), {
            "key_id": api_key_id,
            "endpoint": endpoint,
            "method": method,
            "ip": ip_address,
            "ua": user_agent,
            "status": status_code,
            "time": response_time_ms
        })
        conn.commit()
    finally:
        conn.close()

async def get_api_key_from_header(
    x_api_key: Optional[str] = Header(None, description="API Key for authentication")
) -> str:
    """
    FastAPI dependency to extract API key from header
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "missing_api_key",
                "message": "API key is required. Please provide X-API-Key header.",
                "example": "X-API-Key: your_api_key_here"
            }
        )

    # Verify the API key
    key_info = verify_api_key(x_api_key)

    if not key_info:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "invalid_api_key",
                "message": "Invalid or expired API key"
            }
        )

    if "error" in key_info:
        raise HTTPException(
            status_code=429,
            detail=key_info
        )

    return key_info

def require_permission(permission: str):
    """
    Decorator to require specific permission

    Usage:
        @require_permission("write")
        async def create_domain(...):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get API key info from kwargs (injected by FastAPI dependency)
            key_info = kwargs.get('api_key_info')

            if not key_info:
                raise HTTPException(status_code=401, detail="Authentication required")

            permissions = key_info.get('permissions', {})

            # Check if key has required permission
            if not permissions.get(permission, False) and not permissions.get('admin', False):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "insufficient_permissions",
                        "message": f"This API key does not have '{permission}' permission",
                        "required_permission": permission,
                        "your_permissions": list(permissions.keys())
                    }
                )

            return await func(*args, **kwargs)

        return wrapper
    return decorator

def create_api_key(key_name: str, created_by: str, permissions: dict = None,
                   expires_in_days: int = None, rate_limit: int = 1000) -> dict:
    """
    Create a new API key

    Args:
        key_name: Description of the key
        created_by: Who is creating this key
        permissions: Dict of permissions {"read": True, "write": True, etc.}
        expires_in_days: Optional expiration in days
        rate_limit: Max requests per hour (default 1000)

    Returns:
        dict with api_key and key info
    """
    conn = get_db_connection()

    try:
        api_key = generate_api_key()

        if permissions is None:
            permissions = {"read": True, "write": False, "delete": False}

        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)

        conn.execute(text("""
            INSERT INTO api_keys
            (key_name, api_key, is_active, created_by, permissions, expires_at, rate_limit_requests)
            VALUES (:name, :key, TRUE, :creator, :perms, :expires, :rate_limit)
        """), {
            "name": key_name,
            "key": api_key,
            "creator": created_by,
            "perms": json.dumps(permissions),
            "expires": expires_at,
            "rate_limit": rate_limit
        })
        conn.commit()

        return {
            "api_key": api_key,
            "key_name": key_name,
            "permissions": permissions,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "rate_limit": rate_limit,
            "created_at": datetime.now().isoformat()
        }

    finally:
        conn.close()

def revoke_api_key(api_key: str) -> bool:
    """
    Revoke (deactivate) an API key

    Args:
        api_key: The key to revoke

    Returns:
        True if revoked, False if not found
    """
    conn = get_db_connection()

    try:
        result = conn.execute(text("""
            UPDATE api_keys SET is_active = FALSE WHERE api_key = :key
        """), {"key": api_key})
        conn.commit()

        return result.rowcount > 0

    finally:
        conn.close()

def list_api_keys() -> list:
    """
    List all API keys (without showing the actual key)

    Returns:
        List of API key info
    """
    conn = get_db_connection()

    try:
        results = conn.execute(text("""
            SELECT id, key_name, is_active, created_by, created_at,
                   last_used_at, expires_at, permissions, rate_limit_requests,
                   CONCAT(LEFT(api_key, 8), '...', RIGHT(api_key, 4)) as key_preview
            FROM api_keys
            ORDER BY created_at DESC
        """)).fetchall()

        keys = []
        for row in results:
            keys.append({
                "id": row[0],
                "key_name": row[1],
                "is_active": row[2],
                "created_by": row[3],
                "created_at": row[4].isoformat() if row[4] else None,
                "last_used_at": row[5].isoformat() if row[5] else None,
                "expires_at": row[6].isoformat() if row[6] else None,
                "permissions": json.loads(row[7]) if row[7] else {},
                "rate_limit": row[8],
                "key_preview": row[9]
            })

        return keys

    finally:
        conn.close()

def Thongbao()
    print("Hello")
