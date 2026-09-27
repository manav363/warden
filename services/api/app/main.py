from fastapi import FastAPI

from app.config import Settings
from app.observability import configure_logging, configure_tracing


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    app = FastAPI(title="Warden API", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    configure_tracing(app, settings)
    return app


app = create_app()
