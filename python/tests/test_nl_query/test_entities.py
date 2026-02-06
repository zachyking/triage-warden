"""Tests for entity extraction."""

import pytest
from datetime import datetime, timezone

from tw_ai.nl_query.entities import (
    DateRange,
    EntityExtractor,
    EntityType,
    ExtractedEntity,
)


@pytest.fixture
def extractor() -> EntityExtractor:
    return EntityExtractor()


class TestEntityType:
    def test_all_types_exist(self):
        assert EntityType.IP_ADDRESS == "ip_address"
        assert EntityType.DOMAIN == "domain"
        assert EntityType.HASH_MD5 == "hash_md5"
        assert EntityType.HASH_SHA256 == "hash_sha256"
        assert EntityType.USERNAME == "username"
        assert EntityType.CVE == "cve"
        assert EntityType.PORT == "port"


class TestEntityExtractor:
    def test_empty_query(self, extractor: EntityExtractor):
        assert extractor.extract("") == []

    def test_extract_ipv4(self, extractor: EntityExtractor):
        entities = extractor.extract("traffic from 10.0.0.1 to 192.168.1.100")
        ips = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ips) == 2
        values = {e.value for e in ips}
        assert "10.0.0.1" in values
        assert "192.168.1.100" in values

    def test_invalid_ip_rejected(self, extractor: EntityExtractor):
        entities = extractor.extract("address 999.999.999.999")
        ips = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ips) == 0

    def test_extract_md5_hash(self, extractor: EntityExtractor):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        entities = extractor.extract(f"check hash {md5}")
        hashes = [e for e in entities if e.entity_type == EntityType.HASH_MD5]
        assert len(hashes) == 1
        assert hashes[0].value == md5

    def test_extract_sha256_hash(self, extractor: EntityExtractor):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        entities = extractor.extract(f"hash: {sha256}")
        hashes = [e for e in entities if e.entity_type == EntityType.HASH_SHA256]
        assert len(hashes) == 1
        assert hashes[0].value == sha256

    def test_extract_sha1_hash(self, extractor: EntityExtractor):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        entities = extractor.extract(f"sha1: {sha1}")
        hashes = [e for e in entities if e.entity_type == EntityType.HASH_SHA1]
        assert len(hashes) == 1
        assert hashes[0].value == sha1

    def test_sha256_not_duplicated_as_sha1_or_md5(self, extractor: EntityExtractor):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        entities = extractor.extract(sha256)
        # Should only match SHA-256, not also SHA-1 or MD5
        assert len(entities) == 1
        assert entities[0].entity_type == EntityType.HASH_SHA256

    def test_extract_email(self, extractor: EntityExtractor):
        entities = extractor.extract("email from attacker@evil.com to user@corp.com")
        emails = [e for e in entities if e.entity_type == EntityType.EMAIL]
        assert len(emails) == 2
        values = {e.value for e in emails}
        assert "attacker@evil.com" in values
        assert "user@corp.com" in values

    def test_extract_domain(self, extractor: EntityExtractor):
        entities = extractor.extract("dns query for malicious-site.com")
        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) == 1
        assert domains[0].value == "malicious-site.com"

    def test_domain_not_extracted_from_email(self, extractor: EntityExtractor):
        entities = extractor.extract("from user@example.com")
        domains = [e for e in entities if e.entity_type == EntityType.DOMAIN]
        assert len(domains) == 0

    def test_extract_mitre_technique(self, extractor: EntityExtractor):
        entities = extractor.extract("technique T1566.001 was observed")
        mitre = [e for e in entities if e.entity_type == EntityType.MITRE_TECHNIQUE]
        assert len(mitre) == 1
        assert mitre[0].value == "T1566.001"

    def test_extract_mitre_parent_technique(self, extractor: EntityExtractor):
        entities = extractor.extract("using T1059")
        mitre = [e for e in entities if e.entity_type == EntityType.MITRE_TECHNIQUE]
        assert len(mitre) == 1
        assert mitre[0].value == "T1059"

    def test_extract_cve(self, extractor: EntityExtractor):
        entities = extractor.extract("exploiting CVE-2024-1234")
        cves = [e for e in entities if e.entity_type == EntityType.CVE]
        assert len(cves) == 1
        assert cves[0].value == "CVE-2024-1234"

    def test_extract_incident_id(self, extractor: EntityExtractor):
        entities = extractor.extract("look at INC-5678 and #1234")
        ids = [e for e in entities if e.entity_type == EntityType.INCIDENT_ID]
        assert len(ids) == 2

    def test_extract_port(self, extractor: EntityExtractor):
        entities = extractor.extract("connection on port 443")
        ports = [e for e in entities if e.entity_type == EntityType.PORT]
        assert len(ports) == 1
        assert ports[0].value == "443"

    def test_invalid_port_rejected(self, extractor: EntityExtractor):
        entities = extractor.extract("port 99999")
        ports = [e for e in entities if e.entity_type == EntityType.PORT]
        assert len(ports) == 0

    def test_extract_username(self, extractor: EntityExtractor):
        entities = extractor.extract("activity by user: jdoe")
        users = [e for e in entities if e.entity_type == EntityType.USERNAME]
        assert len(users) == 1
        assert users[0].value == "jdoe"

    def test_extract_severity(self, extractor: EntityExtractor):
        entities = extractor.extract("incidents with severity: critical")
        sevs = [e for e in entities if e.entity_type == EntityType.SEVERITY]
        assert len(sevs) == 1
        assert sevs[0].value == "critical"

    def test_extract_severity_abbreviated(self, extractor: EntityExtractor):
        entities = extractor.extract("sev crit alerts")
        sevs = [e for e in entities if e.entity_type == EntityType.SEVERITY]
        assert len(sevs) == 1
        assert sevs[0].value == "critical"

    def test_multiple_entity_types(self, extractor: EntityExtractor):
        query = "find logs from 10.0.0.1 for user: admin with T1059"
        entities = extractor.extract(query)
        types = {e.entity_type for e in entities}
        assert EntityType.IP_ADDRESS in types
        assert EntityType.USERNAME in types
        assert EntityType.MITRE_TECHNIQUE in types

    def test_entity_positions(self, extractor: EntityExtractor):
        entities = extractor.extract("IP 10.0.0.1 is bad")
        ip_entities = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) == 1
        assert ip_entities[0].start >= 0
        assert ip_entities[0].end > ip_entities[0].start


class TestDateRange:
    def test_relative_time_hours(self, extractor: EntityExtractor):
        result = extractor.extract_date_range("show events from last 24 hours")
        assert result is not None
        assert result.duration_seconds == pytest.approx(24 * 3600, abs=5)

    def test_relative_time_days(self, extractor: EntityExtractor):
        result = extractor.extract_date_range("incidents in the past 7 days")
        assert result is not None
        assert result.duration_seconds == pytest.approx(7 * 24 * 3600, abs=5)

    def test_relative_time_minutes(self, extractor: EntityExtractor):
        result = extractor.extract_date_range("last 30 minutes")
        assert result is not None
        assert result.duration_seconds == pytest.approx(30 * 60, abs=5)

    def test_absolute_date_range(self, extractor: EntityExtractor):
        result = extractor.extract_date_range(
            "events from 2024-01-01 to 2024-01-31"
        )
        assert result is not None
        assert result.start.year == 2024
        assert result.start.month == 1
        assert result.start.day == 1
        assert result.end.day == 31

    def test_no_date_range(self, extractor: EntityExtractor):
        result = extractor.extract_date_range("show me all incidents")
        assert result is None

    def test_date_range_model(self):
        dr = DateRange(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, tzinfo=timezone.utc),
        )
        assert dr.duration_seconds == 86400.0

    def test_empty_query(self, extractor: EntityExtractor):
        assert extractor.extract_date_range("") is None
        assert extractor.extract_date_range(None) is None  # type: ignore[arg-type]
