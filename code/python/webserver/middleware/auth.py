"""Authentication middleware for aiohttp server"""

from aiohttp import web
import logging
import base64
from typing import Optional, Set

logger = logging.getLogger(__name__)

# Public endpoints that don't require authentication
PUBLIC_ENDPOINTS: Set[str] = {
    '/',
    '/health',
    '/ready',
    '/oauth/callback',
    '/api/oauth/config',
    '/who',
    '/sites',
    # Static files
    '/static',
    '/html',
    # Allow public access to ask endpoint for now (can be changed)
    '/ask'
}

# Minimum token length (JWT tokens are typically 100+ chars)
MIN_TOKEN_LENGTH = 16


def _validate_token_format(token: str) -> bool:
    """
    Perform basic token format validation.
    
    This catches obviously invalid tokens (empty, too short, whitespace-only)
    and optionally performs JWT structure validation for tokens that look like JWTs.
    
    Args:
        token: The authentication token to validate
        
    Returns:
        True if the token passes basic format checks
    """
    if not token or not token.strip():
        return False
    
    token = token.strip()
    
    if len(token) < MIN_TOKEN_LENGTH:
        logger.warning(f"Token too short ({len(token)} chars), minimum is {MIN_TOKEN_LENGTH}")
        return False
    
    # Check if it looks like a JWT (three base64url-encoded parts separated by dots)
    parts = token.split('.')
    if len(parts) == 3:
        try:
            # Validate header and payload are valid base64url
            for part in parts[:2]:  # Only validate first two parts (header, payload)
                # Add padding back for base64 decoding
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                base64.urlsafe_b64decode(part)
            return True
        except Exception:
            # Not a valid JWT structure, but might still be another token type
            logger.debug("Token does not appear to be a valid JWT, allowing as opaque token")
            return True
    
    # Non-JWT tokens: just pass the length check
    return True


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Handle authentication for protected endpoints"""
    
    # Check if path is public
    path = request.path
    
    # Check exact matches and path prefixes
    is_public = (
        path in PUBLIC_ENDPOINTS or
        path.startswith('/static/') or
        path.startswith('/html/') or
        path == '/favicon.ico'
    )
    
    if is_public:
        # Public endpoint, no auth required
        return await handler(request)
    
    # Check for authentication token
    auth_token = None
    
    # Check Authorization header
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        auth_token = auth_header[7:]
    
    # Check cookie (for web UI)
    if not auth_token:
        auth_cookie = request.cookies.get('auth_token')
        if auth_cookie:
            auth_token = auth_cookie
    
    # Check query parameter (for SSE connections that can't set headers)
    if not auth_token and request.method == 'GET':
        auth_token = request.query.get('auth_token')
    
    # For now, we'll allow requests without tokens in development mode
    config = request.app.get('config', {})
    mode = config.get('mode', 'production')
    
    if not auth_token and mode == 'development':
        logger.debug(f"No auth token for {path}, allowing in development mode")
        request['user'] = {'id': 'dev_user', 'authenticated': False}
        return await handler(request)
    
    if not auth_token:
        logger.warning(f"No auth token provided for protected endpoint: {path}")
        return web.json_response(
            {'error': 'Authentication required', 'type': 'auth_required'},
            status=401,
            headers={'WWW-Authenticate': 'Bearer'}
        )
    
    # Validate token format before accepting it
    if not _validate_token_format(auth_token):
        logger.warning(f"Invalid auth token format for protected endpoint: {path}")
        return web.json_response(
            {'error': 'Invalid authentication token', 'type': 'invalid_token'},
            status=401,
            headers={'WWW-Authenticate': 'Bearer'}
        )
    
    # SECURITY WARNING: Token is accepted but NOT cryptographically verified.
    # In production, this should validate JWT signatures or call OAuth provider.
    # See: https://github.com/Jondhilipsiva/NLWeb/issues for planned token validation.
    request['auth_token'] = auth_token
    request['user'] = {
        'id': 'authenticated_user',
        'authenticated': True,
        'token': auth_token
    }
    
    # Continue to handler
    return await handler(request)
