"""Email parsing module for extracting security-relevant information from email alerts."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from html.parser import HTMLParser


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class ExtractedURL:
    """Represents a URL extracted from email content.

    Attributes:
        url: The normalized URL (defanged URLs are converted to normal form).
        domain: The domain portion of the URL.
        display_text: For HTML links, the visible text (anchor text).
        is_shortened: Whether this URL uses a known URL shortening service.
        is_ip_based: Whether this URL uses an IP address instead of a domain.
    """

    url: str
    domain: str
    display_text: Optional[str] = None
    is_shortened: bool = False
    is_ip_based: bool = False


@dataclass
class AttachmentInfo:
    """Represents information about an email attachment.

    Attributes:
        filename: The name of the attached file.
        content_type: MIME type of the attachment.
        size_bytes: Size of the attachment in bytes.
        md5: MD5 hash of the attachment content (if available).
        sha256: SHA256 hash of the attachment content (if available).
    """

    filename: str
    content_type: str
    size_bytes: int
    md5: Optional[str] = None
    sha256: Optional[str] = None


@dataclass
class EmailAuthResult:
    """Represents email authentication results.

    Attributes:
        spf: SPF check result ("pass", "fail", "softfail", "none").
        dkim: DKIM check result ("pass", "fail", "none").
        dmarc: DMARC check result ("pass", "fail", "none").
    """

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


@dataclass
class EmailAnalysis:
    """Represents a parsed email with security-relevant information.

    Attributes:
        message_id: Unique message identifier from headers.
        subject: Email subject line.
        sender: Sender email address.
        sender_display_name: Display name of the sender (if available).
        reply_to: Reply-To address (if different from sender).
        recipients: List of To: addresses.
        cc: List of CC: addresses.
        headers: Dictionary of email headers.
        body_text: Plain text body content.
        body_html: HTML body content.
        urls: List of extracted URLs.
        attachments: List of attachment information.
        received_timestamps: List of received timestamps from headers.
        authentication: Email authentication results (SPF, DKIM, DMARC).
    """

    message_id: str
    subject: str
    sender: str
    sender_display_name: Optional[str] = None
    reply_to: Optional[str] = None
    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    urls: list[ExtractedURL] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    received_timestamps: list[datetime] = field(default_factory=list)
    authentication: EmailAuthResult = field(default_factory=EmailAuthResult)


# ============================================================================
# URL Shortener Services
# ============================================================================

# Known URL shortening services
URL_SHORTENERS = frozenset([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "j.mp",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "x.co",
    "su.pr",
    "lnkd.in",
    "fb.me",
    "v.gd",
    "qr.ae",
    "adf.ly",
    "bc.vc",
    "po.st",
    "u.to",
    "s.id",
])


# ============================================================================
# Regex Patterns
# ============================================================================

# URL pattern - handles defanged formats (hxxp, hxxps, [://], [.])
URL_PATTERN = re.compile(
    r"(?P<scheme>hxxps?|https?|ftp)"
    r"(?:\[:\]|:)"
    r"(?://|\[//\])"
    r"(?P<url_body>[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)

# IP address pattern for detecting IP-based URLs
IP_ADDRESS_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Email address pattern for extracting addresses from headers
EMAIL_ADDRESS_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

# Display name and email pattern: "Display Name" <email@example.com>
# This pattern handles:
#   - "Name" <email@domain.com>
#   - Name <email@domain.com>
#   - <email@domain.com>
#   - email@domain.com
DISPLAY_NAME_PATTERN = re.compile(
    r'^(?:"([^"]+)"\s*<|([^<@]+?)\s*<)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?$',
    re.IGNORECASE,
)

# Received header timestamp pattern
RECEIVED_TIMESTAMP_PATTERN = re.compile(
    r";\s*(.+?)(?:\s*\(|$)",
    re.IGNORECASE,
)


# ============================================================================
# URL Extraction Functions
# ============================================================================


def _defang_to_normal(value: str) -> str:
    """Convert defanged indicators back to normal format.

    Examples:
        hxxp[:]// -> http://
        evil[.]com -> evil.com
        192[.]168[.]1[.]1 -> 192.168.1.1
    """
    result = value
    # Handle URL scheme defanging
    result = re.sub(r"hxxp", "http", result, flags=re.IGNORECASE)
    result = result.replace("[:]", ":")
    result = result.replace("[//]", "//")
    # Handle domain/IP defanging
    result = result.replace("[.]", ".")
    result = result.replace("[dot]", ".")
    # Handle at-sign defanging
    result = result.replace("[@]", "@")
    result = result.replace("[at]", "@")
    return result


def _extract_domain_from_url(url: str) -> str:
    """Extract the domain portion from a URL.

    Args:
        url: The URL to extract the domain from.

    Returns:
        The domain portion of the URL.
    """
    # Remove scheme
    url_no_scheme = re.sub(r"^[a-zA-Z]+://", "", url)
    # Get the host part (before path, query, etc.)
    host = url_no_scheme.split("/")[0]
    # Remove credentials if present (user:pass@host)
    if "@" in host:
        host = host.split("@")[-1]
    # Remove port if present (must be after removing credentials)
    host = host.split(":")[0]
    return host.lower()


def _is_url_shortened(domain: str) -> bool:
    """Check if a domain is a known URL shortener.

    Args:
        domain: The domain to check.

    Returns:
        True if the domain is a known URL shortener.
    """
    domain_lower = domain.lower()
    return domain_lower in URL_SHORTENERS


def _is_ip_based_url(domain: str) -> bool:
    """Check if a domain is actually an IP address.

    Args:
        domain: The domain to check.

    Returns:
        True if the domain is an IP address.
    """
    # Normalize defanged notation
    normalized = _defang_to_normal(domain)
    return bool(IP_ADDRESS_PATTERN.match(normalized))


def extract_urls(text: str) -> list[ExtractedURL]:
    """Extract URLs from plain text with defanging support.

    Handles various defanging formats:
    - hxxp:// and hxxps://
    - [.] and [dot] for dots
    - [://] for scheme separator

    Args:
        text: The text to extract URLs from.

    Returns:
        List of ExtractedURL objects with normalized URLs.
    """
    if not text:
        return []

    urls: list[ExtractedURL] = []
    seen_urls: set[str] = set()

    for match in URL_PATTERN.finditer(text):
        full_match = match.group(0)
        # Normalize the URL
        normalized_url = _defang_to_normal(full_match)

        # Skip duplicates
        if normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)

        # Extract domain
        domain = _extract_domain_from_url(normalized_url)

        urls.append(
            ExtractedURL(
                url=normalized_url,
                domain=domain,
                display_text=None,
                is_shortened=_is_url_shortened(domain),
                is_ip_based=_is_ip_based_url(domain),
            )
        )

    return urls


class _HTMLLinkExtractor(HTMLParser):
    """HTML parser to extract links with their display text."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, display_text)
        self._current_link: Optional[str] = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self._current_link = value
                    self._current_text = []
                    break

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_link is not None:
            display_text = "".join(self._current_text).strip()
            self.links.append((self._current_link, display_text))
            self._current_link = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_link is not None:
            self._current_text.append(data)


def extract_urls_from_html(html: str) -> list[ExtractedURL]:
    """Extract URLs from HTML content with display text.

    Extracts both anchor tags with their display text and any URLs
    found in the text content.

    Args:
        html: The HTML content to extract URLs from.

    Returns:
        List of ExtractedURL objects with display text for links.
    """
    if not html:
        return []

    urls: list[ExtractedURL] = []
    seen_urls: set[str] = set()

    # Extract links from anchor tags
    parser = _HTMLLinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        # If HTML parsing fails, fall back to regex extraction
        pass

    for href, display_text in parser.links:
        # Normalize the URL
        normalized_url = _defang_to_normal(href)

        # Skip non-http(s) links (mailto, javascript, etc.)
        if not normalized_url.lower().startswith(("http://", "https://", "ftp://")):
            continue

        if normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)

        domain = _extract_domain_from_url(normalized_url)

        urls.append(
            ExtractedURL(
                url=normalized_url,
                domain=domain,
                display_text=display_text if display_text else None,
                is_shortened=_is_url_shortened(domain),
                is_ip_based=_is_ip_based_url(domain),
            )
        )

    # Also extract any URLs from the text content (may be defanged)
    text_urls = extract_urls(html)
    for url in text_urls:
        if url.url not in seen_urls:
            seen_urls.add(url.url)
            urls.append(url)

    return urls


# ============================================================================
# Authentication Header Parsing
# ============================================================================


def _parse_spf_result(auth_header: str) -> str:
    """Parse SPF result from authentication headers.

    Args:
        auth_header: The authentication header value.

    Returns:
        SPF result: "pass", "fail", "softfail", or "none".
    """
    header_lower = auth_header.lower()

    # Check for SPF result in Authentication-Results header (spf=pass format)
    spf_match = re.search(r"spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", header_lower)
    if spf_match:
        result = spf_match.group(1)
        if result in ("pass",):
            return "pass"
        elif result in ("fail", "permerror"):
            return "fail"
        elif result in ("softfail", "neutral", "temperror"):
            return "softfail"

    # Check for Received-SPF header format (starts with result like "pass (domain...)")
    received_spf_match = re.search(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", header_lower)
    if received_spf_match:
        result = received_spf_match.group(1)
        if result == "pass":
            return "pass"
        elif result in ("fail", "permerror"):
            return "fail"
        elif result in ("softfail", "neutral", "temperror"):
            return "softfail"

    return "none"


def _parse_dkim_result(auth_header: str) -> str:
    """Parse DKIM result from authentication headers.

    Args:
        auth_header: The authentication header value.

    Returns:
        DKIM result: "pass", "fail", or "none".
    """
    header_lower = auth_header.lower()

    # Check for DKIM result in Authentication-Results header
    dkim_match = re.search(r"dkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)", header_lower)
    if dkim_match:
        result = dkim_match.group(1)
        if result == "pass":
            return "pass"
        elif result in ("fail", "permerror"):
            return "fail"
    return "none"


def _parse_dmarc_result(auth_header: str) -> str:
    """Parse DMARC result from authentication headers.

    Args:
        auth_header: The authentication header value.

    Returns:
        DMARC result: "pass", "fail", or "none".
    """
    header_lower = auth_header.lower()

    # Check for DMARC result in Authentication-Results header
    dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail|none|bestguesspass)", header_lower)
    if dmarc_match:
        result = dmarc_match.group(1)
        if result in ("pass", "bestguesspass"):
            return "pass"
        elif result == "fail":
            return "fail"
    return "none"


def parse_authentication_headers(headers: dict) -> EmailAuthResult:
    """Parse email authentication results from headers.

    Parses SPF, DKIM, and DMARC results from Authentication-Results
    and related headers.

    Args:
        headers: Dictionary of email headers.

    Returns:
        EmailAuthResult with parsed authentication status.
    """
    # Normalize header keys to lowercase for lookup
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    # Get Authentication-Results header
    auth_results = normalized_headers.get("authentication-results", "")

    # Also check individual headers
    received_spf = normalized_headers.get("received-spf", "")
    dkim_signature = normalized_headers.get("dkim-signature", "")

    # Parse SPF from Authentication-Results first, then fall back to Received-SPF
    spf_result = _parse_spf_result(auth_results)
    if spf_result == "none" and received_spf:
        spf_result = _parse_spf_result(received_spf)

    dkim_result = _parse_dkim_result(auth_results)
    dmarc_result = _parse_dmarc_result(auth_results)

    # If no DKIM result from Authentication-Results but DKIM-Signature exists,
    # we can't determine pass/fail but know it was attempted
    if dkim_result == "none" and dkim_signature:
        # DKIM signature present but not verified in auth-results
        pass

    return EmailAuthResult(
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
    )


# ============================================================================
# Email Parsing
# ============================================================================


def _parse_email_address(value: str) -> tuple[Optional[str], str]:
    """Parse email address with optional display name.

    Args:
        value: Email address string, possibly with display name.

    Returns:
        Tuple of (display_name, email_address).
    """
    if not value:
        return None, ""

    value = value.strip()

    # Try to match "Display Name" <email@example.com> pattern
    match = DISPLAY_NAME_PATTERN.match(value)
    if match:
        # Group 1: quoted display name, Group 2: unquoted display name, Group 3: email
        quoted_name = match.group(1)
        unquoted_name = match.group(2)
        email = match.group(3)

        display_name = quoted_name if quoted_name else unquoted_name
        if display_name:
            display_name = display_name.strip()
        return display_name if display_name else None, email.lower()

    # Try to extract just an email address
    email_match = EMAIL_ADDRESS_PATTERN.search(value)
    if email_match:
        return None, email_match.group(0).lower()

    return None, value.lower()


def _parse_email_list(value: str) -> list[str]:
    """Parse a comma-separated list of email addresses.

    Args:
        value: Comma-separated email addresses.

    Returns:
        List of email addresses.
    """
    if not value:
        return []

    addresses = []
    for part in value.split(","):
        _, email = _parse_email_address(part.strip())
        if email and "@" in email:
            addresses.append(email)
    return addresses


def _parse_received_timestamps(headers: dict) -> list[datetime]:
    """Parse timestamps from Received headers.

    Args:
        headers: Dictionary of email headers.

    Returns:
        List of datetime objects from Received headers.
    """
    timestamps = []

    # Handle both single Received header and multiple
    received_values = []
    for key, value in headers.items():
        if key.lower() == "received":
            if isinstance(value, list):
                received_values.extend(value)
            else:
                received_values.append(value)

    for received in received_values:
        # Extract timestamp after the semicolon
        match = RECEIVED_TIMESTAMP_PATTERN.search(received)
        if match:
            timestamp_str = match.group(1).strip()
            # Try various date formats
            for fmt in [
                "%a, %d %b %Y %H:%M:%S %z",
                "%d %b %Y %H:%M:%S %z",
                "%a, %d %b %Y %H:%M:%S",
                "%d %b %Y %H:%M:%S",
            ]:
                try:
                    # Handle timezone offset like +0000 (MST)
                    # Strip parenthetical timezone names
                    clean_ts = re.sub(r"\s*\([^)]*\)\s*$", "", timestamp_str)
                    dt = datetime.strptime(clean_ts, fmt)
                    timestamps.append(dt)
                    break
                except ValueError:
                    continue

    return timestamps


def _parse_attachments(attachments_data: list) -> list[AttachmentInfo]:
    """Parse attachment information from alert data.

    Args:
        attachments_data: List of attachment dictionaries.

    Returns:
        List of AttachmentInfo objects.
    """
    attachments = []

    for att in attachments_data:
        if isinstance(att, dict):
            filename = att.get("filename", att.get("name", "unknown"))
            content_type = att.get("content_type", att.get("mime_type", "application/octet-stream"))
            size = att.get("size_bytes", att.get("size", 0))
            md5 = att.get("md5")
            sha256 = att.get("sha256")

            # Calculate hashes if content is provided
            content = att.get("content")
            if content and isinstance(content, (bytes, str)):
                if isinstance(content, str):
                    content = content.encode("utf-8")
                if not md5:
                    md5 = hashlib.md5(content).hexdigest()
                if not sha256:
                    sha256 = hashlib.sha256(content).hexdigest()
                if size == 0:
                    size = len(content)

            attachments.append(
                AttachmentInfo(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=size,
                    md5=md5,
                    sha256=sha256,
                )
            )

    return attachments


def parse_email_alert(alert_data: dict) -> EmailAnalysis:
    """Parse an email alert into an EmailAnalysis object.

    Extracts security-relevant information from email alert JSON data,
    including headers, authentication results, URLs, and attachments.

    Args:
        alert_data: Dictionary containing email alert data with fields like:
            - message_id: Unique message identifier
            - subject: Email subject
            - from/sender: Sender address
            - to/recipients: Recipient addresses
            - cc: CC addresses
            - headers: Raw email headers
            - body_text: Plain text body
            - body_html: HTML body
            - attachments: List of attachment info

    Returns:
        EmailAnalysis object with parsed email data.
    """
    # Extract headers
    headers = alert_data.get("headers", {})
    if isinstance(headers, str):
        # Parse header string into dict if needed
        headers = {}

    # Get message ID
    message_id = (
        alert_data.get("message_id")
        or headers.get("Message-ID", "")
        or headers.get("message-id", "")
        or ""
    )

    # Get subject
    subject = (
        alert_data.get("subject")
        or headers.get("Subject", "")
        or headers.get("subject", "")
        or ""
    )

    # Get sender
    sender_raw = (
        alert_data.get("from")
        or alert_data.get("sender")
        or headers.get("From", "")
        or headers.get("from", "")
        or ""
    )
    sender_display_name, sender = _parse_email_address(sender_raw)

    # Get Reply-To
    reply_to_raw = (
        alert_data.get("reply_to")
        or headers.get("Reply-To", "")
        or headers.get("reply-to", "")
    )
    _, reply_to = _parse_email_address(reply_to_raw) if reply_to_raw else (None, None)
    if reply_to and reply_to == sender:
        reply_to = None  # Only include if different from sender

    # Get recipients
    recipients_raw = (
        alert_data.get("to")
        or alert_data.get("recipients")
        or headers.get("To", "")
        or headers.get("to", "")
        or ""
    )
    if isinstance(recipients_raw, list):
        recipients = [_parse_email_address(r)[1] for r in recipients_raw if r]
    else:
        recipients = _parse_email_list(recipients_raw)

    # Get CC
    cc_raw = (
        alert_data.get("cc")
        or headers.get("Cc", "")
        or headers.get("cc", "")
        or ""
    )
    if isinstance(cc_raw, list):
        cc = [_parse_email_address(c)[1] for c in cc_raw if c]
    else:
        cc = _parse_email_list(cc_raw)

    # Get body content
    body_text = alert_data.get("body_text") or alert_data.get("body") or None
    body_html = alert_data.get("body_html") or None

    # Extract URLs from both text and HTML bodies
    urls: list[ExtractedURL] = []
    seen_url_strings: set[str] = set()

    if body_html:
        for url in extract_urls_from_html(body_html):
            if url.url not in seen_url_strings:
                seen_url_strings.add(url.url)
                urls.append(url)

    if body_text:
        for url in extract_urls(body_text):
            if url.url not in seen_url_strings:
                seen_url_strings.add(url.url)
                urls.append(url)

    # Parse attachments
    attachments_data = alert_data.get("attachments", [])
    attachments = _parse_attachments(attachments_data)

    # Parse received timestamps
    received_timestamps = _parse_received_timestamps(headers)

    # Parse authentication
    authentication = parse_authentication_headers(headers)

    return EmailAnalysis(
        message_id=message_id,
        subject=subject,
        sender=sender,
        sender_display_name=sender_display_name,
        reply_to=reply_to,
        recipients=recipients,
        cc=cc,
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
        received_timestamps=received_timestamps,
        authentication=authentication,
    )
