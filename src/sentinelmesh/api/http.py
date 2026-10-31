"""Backward-compatible imports for the API server."""

from sentinelmesh.api.routes import FRONTEND, ROUTES, resolve_route
from sentinelmesh.api.security import CONTENT_SECURITY_POLICY, LOOPBACK_HOSTS
from sentinelmesh.api.server import create_handler, serve

__all__ = [
    "CONTENT_SECURITY_POLICY",
    "FRONTEND",
    "LOOPBACK_HOSTS",
    "ROUTES",
    "create_handler",
    "resolve_route",
    "serve",
]
