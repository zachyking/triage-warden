"""Database integration tests using testcontainers.

These tests verify that the Python components work correctly with
a real PostgreSQL database instead of mocks.
"""

from __future__ import annotations

import uuid

import pytest

# Skip all tests if testcontainers is not available
pytest.importorskip("testcontainers")


@pytest.mark.integration
class TestPostgresIntegration:
    """Integration tests with PostgreSQL."""

    @pytest.fixture
    def db_connection(self, postgres_connection_url: str):
        """Create a database connection."""
        import psycopg2

        conn = psycopg2.connect(postgres_connection_url)
        conn.autocommit = True
        yield conn
        conn.close()

    def test_connection_works(self, db_connection):
        """Verify we can connect to PostgreSQL."""
        with db_connection.cursor() as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
            assert result[0] == 1

    def test_can_create_tables(self, db_connection):
        """Verify we can create tables."""
        with db_connection.cursor() as cur:
            # Create a test table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS test_incidents (
                    id UUID PRIMARY KEY,
                    alert_type VARCHAR(100) NOT NULL,
                    alert_data JSONB NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # Insert a test incident
            incident_id = uuid.uuid4()
            cur.execute(
                """
                INSERT INTO test_incidents (id, alert_type, alert_data, status)
                VALUES (%s, %s, %s, %s)
                """,
                (str(incident_id), "email_security", '{"test": true}', "pending"),
            )

            # Verify we can read it back
            cur.execute(
                "SELECT id, alert_type, status FROM test_incidents WHERE id = %s",
                (str(incident_id),),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[1] == "email_security"
            assert row[2] == "pending"

    def test_json_operations(self, db_connection):
        """Verify JSON operations work correctly."""
        with db_connection.cursor() as cur:
            # Create table with JSONB
            cur.execute("""
                CREATE TABLE IF NOT EXISTS test_json (
                    id SERIAL PRIMARY KEY,
                    data JSONB NOT NULL
                )
            """)

            # Insert complex JSON
            test_data = {
                "alert_type": "email_security",
                "indicators": [
                    {"type": "domain", "value": "evil.com"},
                    {"type": "ip", "value": "10.0.0.1"},
                ],
                "nested": {"deep": {"value": 42}},
            }

            import json

            cur.execute(
                "INSERT INTO test_json (data) VALUES (%s) RETURNING id",
                (json.dumps(test_data),),
            )
            row_id = cur.fetchone()[0]

            # Query JSON fields
            cur.execute(
                "SELECT data->'alert_type' FROM test_json WHERE id = %s",
                (row_id,),
            )
            result = cur.fetchone()
            assert result[0] == "email_security"

            # Query nested fields
            cur.execute(
                "SELECT data->'nested'->'deep'->'value' FROM test_json WHERE id = %s",
                (row_id,),
            )
            result = cur.fetchone()
            assert result[0] == 42


@pytest.mark.integration
class TestQdrantIntegration:
    """Integration tests with Qdrant vector database."""

    def test_connection_works(self, qdrant_http_url: str):
        """Verify we can connect to Qdrant."""
        import httpx

        response = httpx.get(f"{qdrant_http_url}/healthz")
        assert response.status_code == 200

    def test_can_create_collection(self, qdrant_http_url: str):
        """Verify we can create collections."""
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, VectorParams

        client = QdrantClient(url=qdrant_http_url)

        # Create a test collection
        collection_name = f"test_collection_{uuid.uuid4().hex[:8]}"

        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE),
        )

        # Verify collection exists
        collections = client.get_collections()
        collection_names = [c.name for c in collections.collections]
        assert collection_name in collection_names

        # Cleanup
        client.delete_collection(collection_name)

    def test_can_store_and_search_vectors(self, qdrant_http_url: str):
        """Verify vector operations work correctly."""
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams

        client = QdrantClient(url=qdrant_http_url)

        collection_name = f"test_vectors_{uuid.uuid4().hex[:8]}"

        # Create collection
        client.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=4, distance=Distance.COSINE),
        )

        # Insert test vectors
        points = [
            PointStruct(
                id=1,
                vector=[0.1, 0.2, 0.3, 0.4],
                payload={"type": "phishing", "severity": "high"},
            ),
            PointStruct(
                id=2,
                vector=[0.5, 0.6, 0.7, 0.8],
                payload={"type": "malware", "severity": "critical"},
            ),
            PointStruct(
                id=3,
                vector=[0.1, 0.2, 0.35, 0.45],  # Similar to point 1
                payload={"type": "phishing", "severity": "medium"},
            ),
        ]

        client.upsert(collection_name=collection_name, points=points)

        # Search for similar vectors
        results = client.search(
            collection_name=collection_name,
            query_vector=[0.1, 0.2, 0.3, 0.4],
            limit=2,
        )

        # Should find the two phishing incidents as most similar
        assert len(results) == 2
        assert results[0].id == 1  # Exact match
        assert results[1].id == 3  # Similar vector

        # Cleanup
        client.delete_collection(collection_name)


@pytest.mark.integration
class TestRAGWithRealVectorStore:
    """Integration tests for RAG with real Qdrant."""

    def test_rag_config_with_qdrant(self, qdrant_http_url: str):
        """Test RAG configuration with real Qdrant."""
        from tw_ai.rag.config import RAGConfig

        config = RAGConfig(
            qdrant_url=qdrant_http_url,
            collection_name="test_rag_collection",
            embedding_model="all-MiniLM-L6-v2",
            embedding_dimension=384,
        )

        assert config.qdrant_url == qdrant_http_url
        assert config.collection_name == "test_rag_collection"
