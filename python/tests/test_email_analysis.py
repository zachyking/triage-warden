"""Comprehensive unit tests for email analysis functions."""

from __future__ import annotations

import sys
import importlib.util
from datetime import datetime
from pathlib import Path

import pytest


# Direct module loading to avoid Python 3.10+ syntax issues
_base_path = Path(__file__).parent.parent / "tw_ai"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load email analysis module
_email = _load_module("tw_ai.analysis.email", _base_path / "analysis" / "email.py")
EmailAnalysis = _email.EmailAnalysis
ExtractedURL = _email.ExtractedURL
AttachmentInfo = _email.AttachmentInfo
EmailAuthResult = _email.EmailAuthResult
parse_email_alert = _email.parse_email_alert
extract_urls = _email.extract_urls
extract_urls_from_html = _email.extract_urls_from_html
parse_authentication_headers = _email.parse_authentication_headers


# ============================================================================
# Tests for ExtractedURL
# ============================================================================


class TestExtractedURL:
    """Tests for ExtractedURL dataclass."""

    def test_create_basic_url(self):
        """Test creating a basic ExtractedURL."""
        url = ExtractedURL(
            url="https://example.com/page",
            domain="example.com",
        )
        assert url.url == "https://example.com/page"
        assert url.domain == "example.com"
        assert url.display_text is None
        assert url.is_shortened is False
        assert url.is_ip_based is False

    def test_create_url_with_display_text(self):
        """Test creating ExtractedURL with display text."""
        url = ExtractedURL(
            url="https://example.com/page",
            domain="example.com",
            display_text="Click here",
        )
        assert url.display_text == "Click here"

    def test_create_shortened_url(self):
        """Test creating a shortened URL."""
        url = ExtractedURL(
            url="https://bit.ly/abc123",
            domain="bit.ly",
            is_shortened=True,
        )
        assert url.is_shortened is True

    def test_create_ip_based_url(self):
        """Test creating an IP-based URL."""
        url = ExtractedURL(
            url="http://192.168.1.100/malware",
            domain="192.168.1.100",
            is_ip_based=True,
        )
        assert url.is_ip_based is True


# ============================================================================
# Tests for AttachmentInfo
# ============================================================================


class TestAttachmentInfo:
    """Tests for AttachmentInfo dataclass."""

    def test_create_basic_attachment(self):
        """Test creating a basic attachment."""
        att = AttachmentInfo(
            filename="document.pdf",
            content_type="application/pdf",
            size_bytes=1024,
        )
        assert att.filename == "document.pdf"
        assert att.content_type == "application/pdf"
        assert att.size_bytes == 1024
        assert att.md5 is None
        assert att.sha256 is None

    def test_create_attachment_with_hashes(self):
        """Test creating attachment with hashes."""
        att = AttachmentInfo(
            filename="malware.exe",
            content_type="application/x-msdownload",
            size_bytes=65536,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        assert att.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert att.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ============================================================================
# Tests for EmailAuthResult
# ============================================================================


class TestEmailAuthResult:
    """Tests for EmailAuthResult dataclass."""

    def test_create_default_auth_result(self):
        """Test creating default auth result."""
        auth = EmailAuthResult()
        assert auth.spf == "none"
        assert auth.dkim == "none"
        assert auth.dmarc == "none"

    def test_create_passing_auth_result(self):
        """Test creating passing auth result."""
        auth = EmailAuthResult(spf="pass", dkim="pass", dmarc="pass")
        assert auth.spf == "pass"
        assert auth.dkim == "pass"
        assert auth.dmarc == "pass"

    def test_create_failing_auth_result(self):
        """Test creating failing auth result."""
        auth = EmailAuthResult(spf="fail", dkim="fail", dmarc="fail")
        assert auth.spf == "fail"
        assert auth.dkim == "fail"
        assert auth.dmarc == "fail"


# ============================================================================
# Tests for extract_urls
# ============================================================================


class TestExtractUrls:
    """Tests for extract_urls function."""

    def test_extract_http_url(self):
        """Test extracting HTTP URL."""
        text = "Visit http://example.com/page for more info"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "http://example.com/page"
        assert urls[0].domain == "example.com"

    def test_extract_https_url(self):
        """Test extracting HTTPS URL."""
        text = "Secure site: https://secure.example.com/login"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "https://secure.example.com/login"
        assert urls[0].domain == "secure.example.com"

    def test_extract_defanged_hxxp(self):
        """Test extracting hxxp:// defanged URL."""
        text = "C2 server: hxxp://evil.com/beacon"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "http://evil.com/beacon"
        assert urls[0].domain == "evil.com"

    def test_extract_defanged_hxxps(self):
        """Test extracting hxxps:// defanged URL."""
        text = "Payload: hxxps://malware.net/download"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "https://malware.net/download"

    def test_extract_defanged_brackets(self):
        """Test extracting URL with bracket defanging."""
        text = "Download from hxxp[:]//evil[.]com/malware"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "http://evil.com/malware"
        assert urls[0].domain == "evil.com"

    def test_extract_defanged_dot_brackets(self):
        """Test extracting URL with [.] defanging."""
        text = "C2: https://c2[.]attacker[.]org/beacon"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "https://c2.attacker.org/beacon"
        assert urls[0].domain == "c2.attacker.org"

    def test_detect_shortened_url(self):
        """Test detecting shortened URL."""
        text = "Click: https://bit.ly/abc123"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].is_shortened is True
        assert urls[0].domain == "bit.ly"

    def test_detect_tinyurl(self):
        """Test detecting TinyURL."""
        text = "Link: https://tinyurl.com/xyz789"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].is_shortened is True

    def test_detect_t_co(self):
        """Test detecting t.co URL."""
        text = "Tweet link: https://t.co/abc123"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].is_shortened is True

    def test_detect_goo_gl(self):
        """Test detecting goo.gl URL."""
        text = "Short: https://goo.gl/short"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].is_shortened is True

    def test_detect_ip_based_url(self):
        """Test detecting IP-based URL."""
        text = "Suspicious: http://192.168.1.100/payload"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].is_ip_based is True
        assert urls[0].domain == "192.168.1.100"

    def test_detect_defanged_ip_url(self):
        """Test detecting defanged IP-based URL."""
        text = "C2: hxxp://192[.]168[.]1[.]100/beacon"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].is_ip_based is True
        assert urls[0].url == "http://192.168.1.100/beacon"

    def test_extract_multiple_urls(self):
        """Test extracting multiple URLs."""
        text = """
        Primary: https://example.com/1
        Backup: http://backup.org/2
        C2: hxxp://evil[.]net/3
        """
        urls = extract_urls(text)

        assert len(urls) == 3
        url_strings = {u.url for u in urls}
        assert "https://example.com/1" in url_strings
        assert "http://backup.org/2" in url_strings
        assert "http://evil.net/3" in url_strings

    def test_no_duplicate_urls(self):
        """Test that duplicate URLs are not returned."""
        text = "Visit https://example.com twice: https://example.com"
        urls = extract_urls(text)

        assert len(urls) == 1

    def test_extract_url_with_query_params(self):
        """Test extracting URL with query parameters."""
        text = "Link: https://example.com/search?q=test&page=1"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert "q=test" in urls[0].url

    def test_extract_url_with_fragment(self):
        """Test extracting URL with fragment."""
        text = "Section: https://example.com/page#section-2"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert "#section-2" in urls[0].url

    def test_empty_text(self):
        """Test extracting from empty text."""
        urls = extract_urls("")
        assert urls == []

    def test_no_urls(self):
        """Test text with no URLs."""
        text = "This is a normal sentence without any URLs."
        urls = extract_urls(text)
        assert urls == []


# ============================================================================
# Tests for extract_urls_from_html
# ============================================================================


class TestExtractUrlsFromHtml:
    """Tests for extract_urls_from_html function."""

    def test_extract_anchor_tag(self):
        """Test extracting URL from anchor tag."""
        html = '<a href="https://example.com/page">Click here</a>'
        urls = extract_urls_from_html(html)

        assert len(urls) == 1
        assert urls[0].url == "https://example.com/page"
        assert urls[0].display_text == "Click here"

    def test_extract_anchor_without_text(self):
        """Test extracting URL from anchor without display text."""
        html = '<a href="https://example.com/page"></a>'
        urls = extract_urls_from_html(html)

        assert len(urls) == 1
        assert urls[0].display_text is None

    def test_extract_multiple_anchors(self):
        """Test extracting multiple anchor tags."""
        html = """
        <p><a href="https://first.com">First Link</a></p>
        <p><a href="https://second.com">Second Link</a></p>
        """
        urls = extract_urls_from_html(html)

        assert len(urls) == 2
        texts = {u.display_text for u in urls}
        assert "First Link" in texts
        assert "Second Link" in texts

    def test_extract_defanged_in_text(self):
        """Test extracting defanged URL from HTML text content."""
        html = "<p>The C2 server is at hxxp://evil[.]com/beacon</p>"
        urls = extract_urls_from_html(html)

        assert len(urls) == 1
        assert urls[0].url == "http://evil.com/beacon"

    def test_combined_anchor_and_text_urls(self):
        """Test extracting both anchor and text URLs."""
        html = """
        <p>Click <a href="https://legit.com">here</a></p>
        <p>Or visit hxxp://evil[.]com/payload</p>
        """
        urls = extract_urls_from_html(html)

        assert len(urls) == 2
        url_strings = {u.url for u in urls}
        assert "https://legit.com" in url_strings
        assert "http://evil.com/payload" in url_strings

    def test_skip_mailto_links(self):
        """Test that mailto: links are skipped."""
        html = '<a href="mailto:test@example.com">Email us</a>'
        urls = extract_urls_from_html(html)

        assert len(urls) == 0

    def test_skip_javascript_links(self):
        """Test that javascript: links are skipped."""
        html = '<a href="javascript:void(0)">Click</a>'
        urls = extract_urls_from_html(html)

        assert len(urls) == 0

    def test_detect_shortened_in_html(self):
        """Test detecting shortened URL in HTML."""
        html = '<a href="https://bit.ly/abc123">Short link</a>'
        urls = extract_urls_from_html(html)

        assert len(urls) == 1
        assert urls[0].is_shortened is True

    def test_nested_html_display_text(self):
        """Test extracting display text from nested HTML."""
        html = '<a href="https://example.com"><span>Click</span> <b>Here</b></a>'
        urls = extract_urls_from_html(html)

        assert len(urls) == 1
        assert "Click" in urls[0].display_text
        assert "Here" in urls[0].display_text

    def test_empty_html(self):
        """Test extracting from empty HTML."""
        urls = extract_urls_from_html("")
        assert urls == []


# ============================================================================
# Tests for parse_authentication_headers
# ============================================================================


class TestParseAuthenticationHeaders:
    """Tests for parse_authentication_headers function."""

    def test_parse_all_pass(self):
        """Test parsing all passing authentication."""
        headers = {
            "Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "pass"
        assert auth.dkim == "pass"
        assert auth.dmarc == "pass"

    def test_parse_all_fail(self):
        """Test parsing all failing authentication."""
        headers = {
            "Authentication-Results": "mx.example.com; spf=fail; dkim=fail; dmarc=fail"
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "fail"
        assert auth.dkim == "fail"
        assert auth.dmarc == "fail"

    def test_parse_spf_softfail(self):
        """Test parsing SPF softfail."""
        headers = {
            "Authentication-Results": "mx.example.com; spf=softfail"
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "softfail"

    def test_parse_spf_neutral(self):
        """Test parsing SPF neutral (maps to softfail)."""
        headers = {
            "Authentication-Results": "mx.example.com; spf=neutral"
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "softfail"

    def test_parse_received_spf_header(self):
        """Test parsing Received-SPF header."""
        headers = {
            "Received-SPF": "pass (domain of sender@example.com designates 1.2.3.4 as permitted sender)"
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "pass"

    def test_parse_combined_headers(self):
        """Test parsing combined authentication headers."""
        headers = {
            "Authentication-Results": "mx.example.com; dkim=pass; dmarc=pass",
            "Received-SPF": "pass",
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "pass"
        assert auth.dkim == "pass"
        assert auth.dmarc == "pass"

    def test_parse_missing_headers(self):
        """Test parsing missing authentication headers."""
        headers = {}
        auth = parse_authentication_headers(headers)

        assert auth.spf == "none"
        assert auth.dkim == "none"
        assert auth.dmarc == "none"

    def test_parse_case_insensitive_headers(self):
        """Test that header parsing is case insensitive."""
        headers = {
            "authentication-results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
        }
        auth = parse_authentication_headers(headers)

        assert auth.spf == "pass"
        assert auth.dkim == "pass"
        assert auth.dmarc == "pass"

    def test_parse_dmarc_bestguesspass(self):
        """Test parsing DMARC bestguesspass."""
        headers = {
            "Authentication-Results": "mx.example.com; dmarc=bestguesspass"
        }
        auth = parse_authentication_headers(headers)

        assert auth.dmarc == "pass"


# ============================================================================
# Tests for parse_email_alert
# ============================================================================


class TestParseEmailAlert:
    """Tests for parse_email_alert function."""

    def test_parse_basic_email(self):
        """Test parsing a basic email alert."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Important: Security Alert",
            "from": "sender@example.com",
            "to": "recipient@company.com",
        }
        email = parse_email_alert(alert_data)

        assert email.message_id == "<123@example.com>"
        assert email.subject == "Important: Security Alert"
        assert email.sender == "sender@example.com"
        assert "recipient@company.com" in email.recipients

    def test_parse_sender_with_display_name(self):
        """Test parsing sender with display name."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": '"John Doe" <john@example.com>',
            "to": "recipient@company.com",
        }
        email = parse_email_alert(alert_data)

        assert email.sender == "john@example.com"
        assert email.sender_display_name == "John Doe"

    def test_parse_multiple_recipients(self):
        """Test parsing multiple recipients."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "user1@company.com, user2@company.com, user3@company.com",
        }
        email = parse_email_alert(alert_data)

        assert len(email.recipients) == 3
        assert "user1@company.com" in email.recipients
        assert "user2@company.com" in email.recipients
        assert "user3@company.com" in email.recipients

    def test_parse_recipients_as_list(self):
        """Test parsing recipients provided as a list."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "recipients": ["user1@company.com", "user2@company.com"],
        }
        email = parse_email_alert(alert_data)

        assert len(email.recipients) == 2

    def test_parse_cc_recipients(self):
        """Test parsing CC recipients."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "cc": "cc1@company.com, cc2@company.com",
        }
        email = parse_email_alert(alert_data)

        assert len(email.cc) == 2
        assert "cc1@company.com" in email.cc
        assert "cc2@company.com" in email.cc

    def test_parse_reply_to(self):
        """Test parsing Reply-To header."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "reply_to": "different@example.com",
        }
        email = parse_email_alert(alert_data)

        assert email.reply_to == "different@example.com"

    def test_parse_reply_to_same_as_sender(self):
        """Test Reply-To is None when same as sender."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "reply_to": "sender@example.com",
        }
        email = parse_email_alert(alert_data)

        assert email.reply_to is None

    def test_parse_body_text(self):
        """Test parsing text body."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "body_text": "This is the email body with https://example.com link.",
        }
        email = parse_email_alert(alert_data)

        assert email.body_text is not None
        assert "email body" in email.body_text
        assert len(email.urls) == 1
        assert email.urls[0].url == "https://example.com"

    def test_parse_body_html(self):
        """Test parsing HTML body."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "body_html": '<p>Click <a href="https://example.com">here</a></p>',
        }
        email = parse_email_alert(alert_data)

        assert email.body_html is not None
        assert len(email.urls) == 1
        assert email.urls[0].display_text == "here"

    def test_parse_urls_from_both_bodies(self):
        """Test extracting URLs from both text and HTML bodies."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "body_text": "Visit https://text-url.com",
            "body_html": '<a href="https://html-url.com">Link</a>',
        }
        email = parse_email_alert(alert_data)

        url_strings = {u.url for u in email.urls}
        assert "https://text-url.com" in url_strings
        assert "https://html-url.com" in url_strings

    def test_parse_attachments(self):
        """Test parsing attachments."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "attachments": [
                {
                    "filename": "document.pdf",
                    "content_type": "application/pdf",
                    "size_bytes": 1024,
                },
                {
                    "filename": "image.png",
                    "content_type": "image/png",
                    "size_bytes": 2048,
                    "md5": "abc123",
                    "sha256": "def456",
                },
            ],
        }
        email = parse_email_alert(alert_data)

        assert len(email.attachments) == 2
        assert email.attachments[0].filename == "document.pdf"
        assert email.attachments[1].md5 == "abc123"

    def test_parse_attachment_with_content(self):
        """Test parsing attachment with content to calculate hash."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "attachments": [
                {
                    "filename": "test.txt",
                    "content_type": "text/plain",
                    "size_bytes": 0,
                    "content": "Hello, World!",
                },
            ],
        }
        email = parse_email_alert(alert_data)

        assert len(email.attachments) == 1
        assert email.attachments[0].md5 is not None
        assert email.attachments[0].sha256 is not None
        assert email.attachments[0].size_bytes == 13  # len("Hello, World!")

    def test_parse_authentication_from_headers(self):
        """Test parsing authentication from headers."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "sender@example.com",
            "to": "recipient@company.com",
            "headers": {
                "Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
            },
        }
        email = parse_email_alert(alert_data)

        assert email.authentication.spf == "pass"
        assert email.authentication.dkim == "pass"
        assert email.authentication.dmarc == "pass"

    def test_parse_from_header_fallback(self):
        """Test parsing sender from headers when not in top-level."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "to": "recipient@company.com",
            "headers": {
                "From": "header-sender@example.com",
            },
        }
        email = parse_email_alert(alert_data)

        assert email.sender == "header-sender@example.com"

    def test_parse_empty_alert(self):
        """Test parsing empty alert data."""
        email = parse_email_alert({})

        assert email.message_id == ""
        assert email.subject == ""
        assert email.sender == ""
        assert email.recipients == []

    def test_parse_defanged_urls_in_body(self):
        """Test parsing defanged URLs in email body."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Malicious Link Alert",
            "from": "security@example.com",
            "to": "analyst@company.com",
            "body_text": "Detected malicious URL: hxxp://evil[.]com/malware",
        }
        email = parse_email_alert(alert_data)

        assert len(email.urls) == 1
        assert email.urls[0].url == "http://evil.com/malware"


# ============================================================================
# Tests for EmailAnalysis dataclass
# ============================================================================


class TestEmailAnalysis:
    """Tests for EmailAnalysis dataclass."""

    def test_create_email_analysis(self):
        """Test creating EmailAnalysis directly."""
        analysis = EmailAnalysis(
            message_id="<123@example.com>",
            subject="Test Subject",
            sender="sender@example.com",
        )

        assert analysis.message_id == "<123@example.com>"
        assert analysis.subject == "Test Subject"
        assert analysis.sender == "sender@example.com"
        assert analysis.recipients == []
        assert analysis.cc == []
        assert analysis.headers == {}
        assert analysis.urls == []
        assert analysis.attachments == []

    def test_email_analysis_default_auth(self):
        """Test EmailAnalysis has default authentication."""
        analysis = EmailAnalysis(
            message_id="<123@example.com>",
            subject="Test",
            sender="sender@example.com",
        )

        assert analysis.authentication.spf == "none"
        assert analysis.authentication.dkim == "none"
        assert analysis.authentication.dmarc == "none"


# ============================================================================
# Integration Tests with Sample Email Data
# ============================================================================


class TestSampleEmailData:
    """Integration tests with realistic sample email data."""

    def test_phishing_email_sample(self):
        """Test parsing a sample phishing email."""
        alert_data = {
            "message_id": "<phish123@attacker.net>",
            "subject": "URGENT: Your Account Has Been Compromised",
            "from": '"IT Support" <support@company.com.attacker.net>',
            "to": "victim@company.com",
            "reply_to": "hacker@attacker.net",
            "headers": {
                "Authentication-Results": "mx.company.com; spf=fail; dkim=fail; dmarc=fail",
            },
            "body_text": """
            Dear User,

            Your account has been compromised. Click here immediately to reset your password:
            hxxps://company-login[.]attacker[.]net/reset

            If you don't act within 24 hours, your account will be deleted.

            IT Support
            """,
            "body_html": """
            <html>
            <body>
            <p>Dear User,</p>
            <p>Your account has been compromised. <a href="https://company-login.attacker.net/reset">Click here</a> immediately to reset your password.</p>
            <p>If you don't act within 24 hours, your account will be deleted.</p>
            <p>IT Support</p>
            </body>
            </html>
            """,
        }
        email = parse_email_alert(alert_data)

        # Check sender appears legitimate but is actually from attacker domain
        assert "attacker.net" in email.sender

        # Check display name spoofing
        assert email.sender_display_name == "IT Support"

        # Check reply-to is different
        assert email.reply_to == "hacker@attacker.net"

        # Check authentication failed
        assert email.authentication.spf == "fail"
        assert email.authentication.dkim == "fail"
        assert email.authentication.dmarc == "fail"

        # Check malicious URL was extracted
        assert len(email.urls) >= 1
        url_domains = {u.domain for u in email.urls}
        assert "company-login.attacker.net" in url_domains

    def test_malware_attachment_sample(self):
        """Test parsing email with malware attachment."""
        alert_data = {
            "message_id": "<malware456@evil.org>",
            "subject": "Invoice #12345",
            "from": "billing@legitimate-company.com.evil.org",
            "to": "accounts@company.com",
            "body_text": "Please find attached invoice for your review.",
            "attachments": [
                {
                    "filename": "Invoice_12345.exe",
                    "content_type": "application/x-msdownload",
                    "size_bytes": 524288,
                    "md5": "5d41402abc4b2a76b9719d911017c592",
                    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                },
            ],
        }
        email = parse_email_alert(alert_data)

        # Check attachment is suspicious
        assert len(email.attachments) == 1
        att = email.attachments[0]
        assert att.filename.endswith(".exe")
        assert att.content_type == "application/x-msdownload"
        assert att.md5 is not None
        assert att.sha256 is not None

    def test_credential_harvesting_sample(self):
        """Test parsing credential harvesting email with IP-based URL."""
        alert_data = {
            "message_id": "<harvest789@phish.com>",
            "subject": "Verify Your Account",
            "from": "no-reply@paypa1.com",  # Typosquatting with '1' instead of 'l'
            "to": "user@company.com",
            "body_html": """
            <html>
            <body>
            <p>Click to verify: <a href="http://192.168.1.100:8080/login.php">Verify Now</a></p>
            </body>
            </html>
            """,
        }
        email = parse_email_alert(alert_data)

        # Check URL is IP-based
        assert len(email.urls) >= 1
        ip_urls = [u for u in email.urls if u.is_ip_based]
        assert len(ip_urls) >= 1

    def test_url_shortener_phishing_sample(self):
        """Test parsing phishing email using URL shorteners."""
        alert_data = {
            "message_id": "<short123@example.com>",
            "subject": "You won a prize!",
            "from": "winner@sweepstakes-promo.com",
            "to": "lucky@company.com",
            "body_text": """
            Congratulations! You've won $1,000,000!

            Claim your prize: https://bit.ly/claim-prize

            Alternate link: https://t.co/abc123
            """,
        }
        email = parse_email_alert(alert_data)

        # Check shortened URLs were detected
        shortened = [u for u in email.urls if u.is_shortened]
        assert len(shortened) >= 2

    def test_bec_sample(self):
        """Test parsing Business Email Compromise sample."""
        alert_data = {
            "message_id": "<bec@fraudster.net>",
            "subject": "Re: Wire Transfer Request",
            "from": '"CEO John Smith" <ceo@company.co>',  # Lookalike domain
            "to": "finance@company.com",
            "reply_to": "ceo.john.smith@gmail.com",
            "headers": {
                "Authentication-Results": "mx.company.com; spf=none; dkim=none; dmarc=none",
            },
            "body_text": """
            Hi,

            Please wire $50,000 to the following account urgently:
            Bank: XYZ Bank
            Account: 1234567890
            Routing: 987654321

            This is time sensitive. Do not call - I'm in a meeting.

            John
            """,
        }
        email = parse_email_alert(alert_data)

        # Check for BEC indicators
        assert email.sender_display_name == "CEO John Smith"
        assert email.reply_to is not None
        assert "gmail.com" in email.reply_to
        assert email.authentication.spf == "none"
        assert email.authentication.dmarc == "none"


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_malformed_email_address(self):
        """Test handling malformed email addresses."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test",
            "from": "not-an-email",
            "to": "recipient@company.com",
        }
        email = parse_email_alert(alert_data)

        # Should not crash, sender will be the raw value
        assert email.sender == "not-an-email"

    def test_unicode_subject(self):
        """Test handling Unicode in subject."""
        alert_data = {
            "message_id": "<123@example.com>",
            "subject": "Test Subject",
            "from": "sender@example.com",
            "to": "recipient@company.com",
        }
        email = parse_email_alert(alert_data)

        assert email.subject == "Test Subject"

    def test_very_long_url(self):
        """Test handling very long URLs."""
        long_path = "a" * 500
        text = f"http://example.com/{long_path}"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert len(urls[0].url) > 500

    def test_nested_defanging(self):
        """Test handling multiple levels of defanging."""
        text = "hxxps[:]//evil[.]com[.]attacker[.]net/path"
        urls = extract_urls(text)

        assert len(urls) == 1
        assert urls[0].url == "https://evil.com.attacker.net/path"

    def test_url_with_credentials(self):
        """Test extracting URL with embedded credentials."""
        text = "http://user:pass@example.com/path"
        urls = extract_urls(text)

        assert len(urls) == 1
        # Domain should exclude credentials
        assert urls[0].domain == "example.com"

    def test_html_with_invalid_markup(self):
        """Test extracting from malformed HTML."""
        html = '<a href="https://example.com">Unclosed anchor'
        urls = extract_urls_from_html(html)

        # Should still extract the URL
        assert len(urls) >= 1
