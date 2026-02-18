"""FastAPI triage service wrapping the ReAct agent as an HTTP endpoint."""

from tw_ai.triage_service.app import app, create_app

__all__ = ["app", "create_app"]
