"""The Darkwatch dashboard: a local web app over the same store, scanner and sources."""

from __future__ import annotations

from .server import DEFAULT_HOST, DEFAULT_PORT, WebConfig, build_app, serve

__all__ = ["DEFAULT_HOST", "DEFAULT_PORT", "WebConfig", "build_app", "serve"]
