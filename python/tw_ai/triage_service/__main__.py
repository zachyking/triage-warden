"""Entry point for `python -m tw_ai.triage_service`."""

import uvicorn

from tw_ai.triage_service.config import get_config

if __name__ == "__main__":
    config = get_config()
    uvicorn.run(
        "tw_ai.triage_service.app:app",
        host=config.host,
        port=config.port,
        log_level="info",
    )
