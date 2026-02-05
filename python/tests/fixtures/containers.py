"""Testcontainers support for Python integration tests.

Provides container management for:
- PostgreSQL for database tests
- Qdrant for vector store tests
- Redis for caching tests (future)

Usage:
    @pytest.fixture(scope="session")
    def postgres(postgres_container):
        # Use the container
        connection_url = postgres_container.get_connection_url()
        ...

    # Or use the URL directly
    def test_database(postgres_connection_url):
        # postgres_connection_url is a string like "postgresql://..."
        ...
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Generator

import pytest

# Type hints for testcontainers - actual imports happen inside functions
# to handle cases where Docker isn't available
try:
    from testcontainers.postgres import PostgresContainer
    from testcontainers.core.container import DockerContainer

    TESTCONTAINERS_AVAILABLE = True
except ImportError:
    TESTCONTAINERS_AVAILABLE = False
    PostgresContainer = Any  # type: ignore
    DockerContainer = Any  # type: ignore


def _skip_if_no_docker() -> None:
    """Skip test if Docker is not available."""
    if not TESTCONTAINERS_AVAILABLE:
        pytest.skip("testcontainers not installed - run: pip install testcontainers[postgres]")


@dataclass
class PostgresTestContainer:
    """Wrapper for PostgreSQL test container."""

    container: PostgresContainer
    host: str
    port: int
    database: str
    username: str
    password: str

    def get_connection_url(self) -> str:
        """Get the PostgreSQL connection URL."""
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"

    def get_async_connection_url(self) -> str:
        """Get the async PostgreSQL connection URL (for asyncpg)."""
        return f"postgresql+asyncpg://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass
class QdrantTestContainer:
    """Wrapper for Qdrant test container."""

    container: DockerContainer
    host: str
    http_port: int
    grpc_port: int

    def get_http_url(self) -> str:
        """Get the Qdrant HTTP URL."""
        return f"http://{self.host}:{self.http_port}"

    def get_grpc_url(self) -> str:
        """Get the Qdrant gRPC URL."""
        return f"http://{self.host}:{self.grpc_port}"


def _create_postgres_container() -> PostgresTestContainer:
    """Create and start a PostgreSQL container."""
    _skip_if_no_docker()

    from testcontainers.postgres import PostgresContainer

    container = PostgresContainer(
        image="postgres:16-alpine",
        user="test",
        password="test",
        dbname="triage_warden_test",
    )
    container.start()

    # Wait for postgres to be ready
    time.sleep(1)

    host = container.get_container_host_ip()
    port = int(container.get_exposed_port(5432))

    return PostgresTestContainer(
        container=container,
        host=host,
        port=port,
        database="triage_warden_test",
        username="test",
        password="test",
    )


def _create_qdrant_container() -> QdrantTestContainer:
    """Create and start a Qdrant container."""
    _skip_if_no_docker()

    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_utils import wait_for_logs

    container = DockerContainer(image="qdrant/qdrant:v1.12.4")
    container.with_exposed_ports(6333, 6334)
    container.start()

    # Wait for Qdrant to be ready
    wait_for_logs(container, "Qdrant gRPC listening on", timeout=30)
    time.sleep(1)

    host = container.get_container_host_ip()
    http_port = int(container.get_exposed_port(6333))
    grpc_port = int(container.get_exposed_port(6334))

    return QdrantTestContainer(
        container=container,
        host=host,
        http_port=http_port,
        grpc_port=grpc_port,
    )


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture(scope="session")
def postgres_container() -> Generator[PostgresTestContainer, None, None]:
    """Session-scoped PostgreSQL container fixture.

    Usage:
        def test_database(postgres_container):
            url = postgres_container.get_connection_url()
            # ... use the database
    """
    pg = _create_postgres_container()
    try:
        yield pg
    finally:
        pg.container.stop()


@pytest.fixture(scope="session")
def postgres_connection_url(postgres_container: PostgresTestContainer) -> str:
    """Get the PostgreSQL connection URL.

    Usage:
        def test_database(postgres_connection_url):
            # postgres_connection_url is "postgresql://test:test@localhost:xxxxx/triage_warden_test"
            ...
    """
    return postgres_container.get_connection_url()


@pytest.fixture(scope="session")
def qdrant_container() -> Generator[QdrantTestContainer, None, None]:
    """Session-scoped Qdrant container fixture.

    Usage:
        def test_vector_store(qdrant_container):
            url = qdrant_container.get_http_url()
            # ... use Qdrant
    """
    qdrant = _create_qdrant_container()
    try:
        yield qdrant
    finally:
        qdrant.container.stop()


@pytest.fixture(scope="session")
def qdrant_http_url(qdrant_container: QdrantTestContainer) -> str:
    """Get the Qdrant HTTP URL.

    Usage:
        def test_vector_store(qdrant_http_url):
            # qdrant_http_url is "http://localhost:xxxxx"
            ...
    """
    return qdrant_container.get_http_url()


@pytest.fixture
def fresh_postgres_container() -> Generator[PostgresTestContainer, None, None]:
    """Function-scoped PostgreSQL container fixture.

    Creates a fresh container for each test. Use when tests need
    complete isolation and don't share state.

    Usage:
        def test_isolated(fresh_postgres_container):
            # Each test gets its own database
            ...
    """
    pg = _create_postgres_container()
    try:
        yield pg
    finally:
        pg.container.stop()


@pytest.fixture
def fresh_qdrant_container() -> Generator[QdrantTestContainer, None, None]:
    """Function-scoped Qdrant container fixture.

    Creates a fresh container for each test. Use when tests need
    complete isolation and don't share state.
    """
    qdrant = _create_qdrant_container()
    try:
        yield qdrant
    finally:
        qdrant.container.stop()
