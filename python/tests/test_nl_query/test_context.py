"""Tests for conversation context management."""

import pytest

from tw_ai.nl_query.context import ConversationContext, ContextEntry
from tw_ai.nl_query.entities import EntityType, ExtractedEntity


def _make_entity(
    entity_type: EntityType, value: str, start: int = 0, end: int = 5
) -> ExtractedEntity:
    return ExtractedEntity(
        entity_type=entity_type,
        value=value,
        original_text=value,
        start=start,
        end=end,
    )


class TestConversationContext:
    def test_initial_state(self):
        ctx = ConversationContext()
        assert ctx.query_count == 0
        assert ctx.incident_id is None
        assert ctx.last_query is None
        assert ctx.recent_entities == {}

    def test_initial_with_incident(self):
        ctx = ConversationContext(incident_id="INC-123")
        assert ctx.incident_id == "INC-123"

    def test_update_adds_entry(self):
        ctx = ConversationContext()
        ctx.update("show incidents", [])
        assert ctx.query_count == 1
        assert ctx.last_query is not None
        assert ctx.last_query.query == "show incidents"

    def test_update_tracks_entities(self):
        ctx = ConversationContext()
        entities = [_make_entity(EntityType.IP_ADDRESS, "10.0.0.1")]
        ctx.update("check 10.0.0.1", entities)
        assert EntityType.IP_ADDRESS in ctx.recent_entities
        assert ctx.recent_entities[EntityType.IP_ADDRESS][0].value == "10.0.0.1"

    def test_resolve_ip_reference(self):
        ctx = ConversationContext()
        entities = [_make_entity(EntityType.IP_ADDRESS, "10.0.0.1")]
        ctx.update("check 10.0.0.1", entities)

        resolved, resolved_entities = ctx.resolve_reference("what about that IP")
        assert "10.0.0.1" in resolved
        assert len(resolved_entities) > 0

    def test_resolve_domain_reference(self):
        ctx = ConversationContext()
        entities = [_make_entity(EntityType.DOMAIN, "evil.com")]
        ctx.update("lookup evil.com", entities)

        resolved, _ = ctx.resolve_reference("block that domain")
        assert "evil.com" in resolved

    def test_resolve_user_reference(self):
        ctx = ConversationContext()
        entities = [_make_entity(EntityType.USERNAME, "jdoe")]
        ctx.update("check user: jdoe", entities)

        resolved, _ = ctx.resolve_reference("disable that user")
        assert "jdoe" in resolved

    def test_resolve_incident_reference(self):
        ctx = ConversationContext(incident_id="INC-999")
        resolved, _ = ctx.resolve_reference("show me this incident")
        assert "INC-999" in resolved

    def test_no_resolution_without_context(self):
        ctx = ConversationContext()
        resolved, resolved_entities = ctx.resolve_reference("block that IP")
        # No entities in context, so reference is not resolved
        assert resolved == "block that IP"
        assert len(resolved_entities) == 0

    def test_most_recent_entity_wins(self):
        ctx = ConversationContext()
        ctx.update("check 10.0.0.1", [_make_entity(EntityType.IP_ADDRESS, "10.0.0.1")])
        ctx.update("check 10.0.0.2", [_make_entity(EntityType.IP_ADDRESS, "10.0.0.2")])

        resolved, _ = ctx.resolve_reference("block that IP")
        assert "10.0.0.2" in resolved

    def test_get_entity_by_type(self):
        ctx = ConversationContext()
        ctx.update("check 10.0.0.1", [_make_entity(EntityType.IP_ADDRESS, "10.0.0.1")])
        entity = ctx.get_entity_by_type(EntityType.IP_ADDRESS)
        assert entity is not None
        assert entity.value == "10.0.0.1"

    def test_get_entity_by_type_missing(self):
        ctx = ConversationContext()
        assert ctx.get_entity_by_type(EntityType.DOMAIN) is None

    def test_clear(self):
        ctx = ConversationContext(incident_id="INC-1")
        ctx.update("test", [_make_entity(EntityType.IP_ADDRESS, "10.0.0.1")])
        ctx.clear()
        assert ctx.query_count == 0
        assert ctx.incident_id is None
        assert ctx.recent_entities == {}

    def test_max_history(self):
        ctx = ConversationContext(max_history=3)
        for i in range(5):
            ctx.update(f"query {i}", [])
        assert ctx.query_count == 3

    def test_query_history(self):
        ctx = ConversationContext()
        ctx.update("first", [])
        ctx.update("second", [])
        history = ctx.query_history
        assert len(history) == 2
        assert history[0].query == "first"
        assert history[1].query == "second"

    def test_to_dict(self):
        ctx = ConversationContext(incident_id="INC-1")
        ctx.update("test", [])
        d = ctx.to_dict()
        assert d["incident_id"] == "INC-1"
        assert d["query_count"] == 1


class TestContextEntry:
    def test_entry_creation(self):
        entry = ContextEntry(
            query="test query",
            entities=[],
            result_count=5,
        )
        assert entry.query == "test query"
        assert entry.result_count == 5
        assert entry.timestamp is not None
