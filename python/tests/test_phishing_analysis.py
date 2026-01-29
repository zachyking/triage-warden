"""Comprehensive unit tests for phishing analysis functions."""

from __future__ import annotations

import sys
import importlib.util
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


# Load phishing analysis module
_phishing = _load_module("tw_ai.analysis.phishing", _base_path / "analysis" / "phishing.py")
analyze_phishing_indicators = _phishing.analyze_phishing_indicators
check_typosquat = _phishing.check_typosquat
detect_urgency_language = _phishing.detect_urgency_language
detect_credential_request = _phishing.detect_credential_request
calculate_risk_score = _phishing.calculate_risk_score
PhishingIndicators = _phishing.PhishingIndicators
TyposquatMatch = _phishing.TyposquatMatch
LEGITIMATE_DOMAINS = _phishing.LEGITIMATE_DOMAINS


# ============================================================================
# Tests for TyposquatMatch and PhishingIndicators dataclasses
# ============================================================================


class TestTyposquatMatchDataclass:
    """Tests for TyposquatMatch dataclass."""

    def test_create_typosquat_match(self):
        """Test creating a TyposquatMatch instance."""
        match = TyposquatMatch(
            suspicious_domain="paypa1.com",
            similar_to="paypal.com",
            similarity_score=0.9,
            technique="homoglyph",
        )
        assert match.suspicious_domain == "paypa1.com"
        assert match.similar_to == "paypal.com"
        assert match.similarity_score == 0.9
        assert match.technique == "homoglyph"

    def test_typosquat_techniques(self):
        """Test all valid typosquat techniques."""
        techniques = ["homoglyph", "typo", "tld_swap", "subdomain"]
        for tech in techniques:
            match = TyposquatMatch(
                suspicious_domain="test.com",
                similar_to="paypal.com",
                similarity_score=0.8,
                technique=tech,
            )
            assert match.technique == tech


class TestPhishingIndicatorsDataclass:
    """Tests for PhishingIndicators dataclass."""

    def test_default_values(self):
        """Test PhishingIndicators default values."""
        indicators = PhishingIndicators()
        assert indicators.typosquat_domains == []
        assert indicators.urgency_phrases == []
        assert indicators.credential_request_detected is False
        assert indicators.suspicious_urls == []
        assert indicators.url_text_mismatch is False
        assert indicators.sender_domain_mismatch is False
        assert indicators.attachment_risk_level == "none"
        assert indicators.overall_risk_score == 0
        assert indicators.risk_factors == []

    def test_attachment_risk_levels(self):
        """Test all valid attachment risk levels."""
        levels = ["none", "low", "medium", "high", "critical"]
        for level in levels:
            indicators = PhishingIndicators(attachment_risk_level=level)
            assert indicators.attachment_risk_level == level


# ============================================================================
# Tests for check_typosquat function
# ============================================================================


class TestTyposquatHomoglyph:
    """Tests for homoglyph-based typosquatting detection."""

    def test_detect_l_to_1_homoglyph(self):
        """Test detecting l->1 homoglyph substitution."""
        matches = check_typosquat("paypa1.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "homoglyph" and m.similar_to == "paypal.com" for m in matches)

    def test_detect_o_to_0_homoglyph(self):
        """Test detecting o->0 homoglyph substitution."""
        matches = check_typosquat("g00gle.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "homoglyph" and m.similar_to == "google.com" for m in matches)

    def test_detect_rn_to_m_homoglyph(self):
        """Test detecting rn->m homoglyph substitution."""
        matches = check_typosquat("arnazon.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        # Should detect similarity to amazon.com (rn looks like m)
        assert any(m.similar_to == "amazon.com" for m in matches)

    def test_high_similarity_score_for_homoglyph(self):
        """Test that homoglyph detection has high similarity score."""
        matches = check_typosquat("micros0ft.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        for match in matches:
            if match.technique == "homoglyph":
                assert match.similarity_score >= 0.8


class TestTyposquatTypo:
    """Tests for typo-based typosquatting detection."""

    def test_detect_single_char_typo(self):
        """Test detecting single character typo."""
        # Missing a character
        matches = check_typosquat("gogle.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "typo" and m.similar_to == "google.com" for m in matches)

    def test_detect_transposition_typo(self):
        """Test detecting character transposition typo."""
        matches = check_typosquat("gogole.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        # Should be within Levenshtein distance threshold

    def test_detect_adjacent_key_typo(self):
        """Test detecting adjacent key typo."""
        # 'a' is adjacent to 's' on keyboard
        matches = check_typosquat("amason.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.similar_to == "amazon.com" for m in matches)

    def test_no_match_for_different_domain(self):
        """Test that completely different domains don't match."""
        matches = check_typosquat("totallyunrelated.com", LEGITIMATE_DOMAINS)
        assert len(matches) == 0


class TestTyposquatTLDSwap:
    """Tests for TLD swap typosquatting detection."""

    def test_detect_com_to_co_swap(self):
        """Test detecting .com to .co TLD swap."""
        matches = check_typosquat("paypal.co", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "tld_swap" and m.similar_to == "paypal.com" for m in matches)

    def test_detect_com_to_net_swap(self):
        """Test detecting .com to .net TLD swap."""
        matches = check_typosquat("amazon.net", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "tld_swap" for m in matches)

    def test_detect_com_to_org_swap(self):
        """Test detecting .com to .org TLD swap."""
        matches = check_typosquat("microsoft.org", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "tld_swap" for m in matches)

    def test_high_similarity_for_tld_swap(self):
        """Test that TLD swap has very high similarity score."""
        matches = check_typosquat("google.co", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        tld_matches = [m for m in matches if m.technique == "tld_swap"]
        for match in tld_matches:
            assert match.similarity_score >= 0.9


class TestTyposquatSubdomain:
    """Tests for subdomain-based typosquatting detection."""

    def test_detect_legitimate_as_subdomain(self):
        """Test detecting legitimate domain used as subdomain."""
        matches = check_typosquat("paypal.evil.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "subdomain" for m in matches)

    def test_detect_prefix_subdomain(self):
        """Test detecting legitimate domain as prefix."""
        matches = check_typosquat("login-paypal.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1
        assert any(m.technique == "subdomain" for m in matches)

    def test_detect_login_subdomain_trick(self):
        """Test detecting login.legitimate.evil.com pattern."""
        matches = check_typosquat("microsoft.attacker.com", LEGITIMATE_DOMAINS)
        assert len(matches) >= 1

    def test_exact_match_no_subdomain_detection(self):
        """Test that exact legitimate domain doesn't trigger subdomain detection."""
        matches = check_typosquat("paypal.com", LEGITIMATE_DOMAINS)
        assert len(matches) == 0


class TestTyposquatEdgeCases:
    """Edge case tests for typosquatting detection."""

    def test_legitimate_domain_returns_empty(self):
        """Test that legitimate domains return no matches."""
        for domain in LEGITIMATE_DOMAINS[:3]:
            matches = check_typosquat(domain, LEGITIMATE_DOMAINS)
            assert len(matches) == 0

    def test_case_insensitive_matching(self):
        """Test that matching is case insensitive."""
        matches_lower = check_typosquat("paypa1.com", LEGITIMATE_DOMAINS)
        matches_upper = check_typosquat("PAYPA1.COM", LEGITIMATE_DOMAINS)
        assert len(matches_lower) == len(matches_upper)

    def test_empty_domain(self):
        """Test handling empty domain."""
        matches = check_typosquat("", LEGITIMATE_DOMAINS)
        assert len(matches) == 0


# ============================================================================
# Tests for detect_urgency_language function
# ============================================================================


class TestUrgencyLanguageDetection:
    """Tests for urgency language detection."""

    def test_detect_urgent_keyword(self):
        """Test detecting 'urgent' keyword."""
        phrases = detect_urgency_language("URGENT: Your account requires attention")
        assert "urgent" in phrases

    def test_detect_immediate_keyword(self):
        """Test detecting 'immediate' keyword."""
        phrases = detect_urgency_language("Immediate action required")
        assert "immediate" in phrases

    def test_detect_suspended_keyword(self):
        """Test detecting 'suspended' keyword."""
        phrases = detect_urgency_language("Your account has been suspended")
        assert "suspended" in phrases

    def test_detect_verify_keyword(self):
        """Test detecting 'verify' keyword."""
        phrases = detect_urgency_language("Please verify your account")
        assert "verify" in phrases

    def test_detect_expire_keyword(self):
        """Test detecting 'expire' keyword."""
        phrases = detect_urgency_language("Your password will expire soon")
        assert any("expire" in p for p in phrases)

    def test_detect_time_limit_phrase(self):
        """Test detecting 'within 24 hours' phrase."""
        phrases = detect_urgency_language("Complete this within 24 hours")
        assert "within 24 hours" in phrases

    def test_detect_account_locked_phrase(self):
        """Test detecting 'account locked' phrase."""
        phrases = detect_urgency_language("Your account locked due to suspicious activity")
        assert "account locked" in phrases

    def test_detect_security_alert_phrase(self):
        """Test detecting 'security alert' phrase."""
        phrases = detect_urgency_language("Security alert: unauthorized access detected")
        assert "security alert" in phrases

    def test_detect_multiple_urgency_phrases(self):
        """Test detecting multiple urgency phrases in one text."""
        text = """
        URGENT: Security Alert!
        Your account has been suspended due to unauthorized access.
        Please verify your account within 24 hours or it will expire.
        """
        phrases = detect_urgency_language(text)
        assert len(phrases) >= 4

    def test_no_urgency_in_normal_text(self):
        """Test that normal text has no urgency phrases."""
        phrases = detect_urgency_language("Thank you for your order. It will ship tomorrow.")
        assert len(phrases) == 0

    def test_case_insensitive_detection(self):
        """Test that urgency detection is case insensitive."""
        phrases = detect_urgency_language("ACCOUNT LOCKED - VERIFY IMMEDIATELY")
        assert len(phrases) >= 2


# ============================================================================
# Tests for detect_credential_request function
# ============================================================================


class TestCredentialRequestDetection:
    """Tests for credential request detection."""

    def test_detect_enter_password(self):
        """Test detecting 'enter your password' pattern."""
        assert detect_credential_request("Please enter your password to continue") is True

    def test_detect_confirm_credentials(self):
        """Test detecting 'confirm your credentials' pattern."""
        assert detect_credential_request("Confirm your credentials to unlock") is True

    def test_detect_verify_account(self):
        """Test detecting 'verify your account' pattern."""
        assert detect_credential_request("Verify your account by clicking below") is True

    def test_detect_click_to_login(self):
        """Test detecting 'click here to login' pattern."""
        assert detect_credential_request("Click here to login and secure your account") is True

    def test_detect_update_payment(self):
        """Test detecting 'update your payment' pattern."""
        assert detect_credential_request("Update your payment information") is True

    def test_detect_credit_card_request(self):
        """Test detecting credit card request patterns."""
        assert detect_credential_request("Enter your credit card number") is True
        assert detect_credential_request("Please provide your card number") is False  # Different pattern

    def test_detect_password_reset(self):
        """Test detecting password reset patterns."""
        assert detect_credential_request("Click to reset your password") is True

    def test_detect_verify_identity(self):
        """Test detecting 'verify your identity' pattern."""
        assert detect_credential_request("Verify your identity to continue") is True

    def test_no_credential_request_in_normal_email(self):
        """Test that normal email doesn't trigger credential detection."""
        normal_text = """
        Hi John,

        Just wanted to follow up on our meeting yesterday.
        Let me know if you have any questions.

        Best,
        Jane
        """
        assert detect_credential_request(normal_text) is False

    def test_case_insensitive_detection(self):
        """Test case insensitive credential detection."""
        assert detect_credential_request("ENTER YOUR PASSWORD NOW") is True
        assert detect_credential_request("Enter Your Password Now") is True


# ============================================================================
# Tests for calculate_risk_score function
# ============================================================================


class TestCalculateRiskScore:
    """Tests for risk score calculation."""

    def test_zero_score_for_no_indicators(self):
        """Test that no indicators results in zero score."""
        indicators = PhishingIndicators()
        score = calculate_risk_score(indicators)
        assert score == 0

    def test_typosquat_adds_to_score(self):
        """Test that typosquatting detection increases score."""
        indicators = PhishingIndicators(
            typosquat_domains=[
                TyposquatMatch("paypa1.com", "paypal.com", 0.9, "homoglyph")
            ]
        )
        score = calculate_risk_score(indicators)
        assert score > 0
        assert score >= 20  # High similarity should give high points

    def test_urgency_phrases_add_to_score(self):
        """Test that urgency phrases increase score."""
        indicators = PhishingIndicators(
            urgency_phrases=["urgent", "immediate", "suspended"]
        )
        score = calculate_risk_score(indicators)
        assert score >= 10

    def test_credential_request_adds_to_score(self):
        """Test that credential request increases score significantly."""
        indicators = PhishingIndicators(credential_request_detected=True)
        score = calculate_risk_score(indicators)
        assert score == 20  # Credential request adds 20 points

    def test_suspicious_urls_add_to_score(self):
        """Test that suspicious URLs increase score."""
        indicators = PhishingIndicators(suspicious_urls=["http://paypa1.com/login"])
        score = calculate_risk_score(indicators)
        assert score >= 10

    def test_url_text_mismatch_adds_to_score(self):
        """Test that URL/text mismatch increases score."""
        indicators = PhishingIndicators(url_text_mismatch=True)
        score = calculate_risk_score(indicators)
        assert score == 10

    def test_sender_mismatch_adds_to_score(self):
        """Test that sender mismatch increases score."""
        indicators = PhishingIndicators(sender_domain_mismatch=True)
        score = calculate_risk_score(indicators)
        assert score == 10

    def test_high_attachment_risk_adds_to_score(self):
        """Test that high-risk attachments increase score."""
        indicators = PhishingIndicators(attachment_risk_level="high")
        score = calculate_risk_score(indicators)
        assert score >= 15

    def test_medium_attachment_risk_adds_less(self):
        """Test that medium-risk attachments add moderate score."""
        indicators = PhishingIndicators(attachment_risk_level="medium")
        score = calculate_risk_score(indicators)
        assert score == 10

    def test_combined_indicators_accumulate(self):
        """Test that multiple indicators accumulate score."""
        indicators = PhishingIndicators(
            typosquat_domains=[
                TyposquatMatch("paypa1.com", "paypal.com", 0.9, "homoglyph")
            ],
            urgency_phrases=["urgent", "immediately"],
            credential_request_detected=True,
            suspicious_urls=["http://paypa1.com"],
            url_text_mismatch=True,
            attachment_risk_level="high",
        )
        score = calculate_risk_score(indicators)
        # Should have high combined score
        assert score >= 70

    def test_score_capped_at_100(self):
        """Test that score is capped at 100."""
        indicators = PhishingIndicators(
            typosquat_domains=[
                TyposquatMatch("paypa1.com", "paypal.com", 1.0, "homoglyph")
            ],
            urgency_phrases=["urgent", "immediate", "suspended", "verify", "expire"],
            credential_request_detected=True,
            suspicious_urls=["http://a.com", "http://b.com", "http://c.com"],
            url_text_mismatch=True,
            sender_domain_mismatch=True,
            attachment_risk_level="critical",
        )
        score = calculate_risk_score(indicators)
        assert score == 100


# ============================================================================
# Tests for analyze_phishing_indicators function
# ============================================================================


class TestAnalyzePhishingIndicators:
    """Tests for the main analysis function."""

    def test_analyze_empty_email(self):
        """Test analyzing empty email data."""
        indicators = analyze_phishing_indicators({})
        assert isinstance(indicators, PhishingIndicators)
        assert indicators.overall_risk_score == 0

    def test_analyze_clean_email(self):
        """Test analyzing legitimate email."""
        email_data = {
            "subject": "Meeting Tomorrow",
            "body": "Hi, just confirming our meeting for tomorrow at 2pm. Best regards.",
            "sender_email": "colleague@company.com",
            "sender_display_name": "John Colleague",
            "urls": [],
            "attachments": [],
        }
        indicators = analyze_phishing_indicators(email_data)
        assert indicators.overall_risk_score < 20

    def test_analyze_obvious_phishing_email(self):
        """Test analyzing obvious phishing email."""
        email_data = {
            "subject": "URGENT: Your PayPal Account Has Been Suspended",
            "body": """
            Dear Customer,

            We have detected unauthorized access to your account. Your account has been
            temporarily suspended. Please verify your account within 24 hours to avoid
            permanent suspension.

            Click here to login and confirm your credentials.

            Security Alert - Action Required Immediately
            """,
            "sender_email": "security@paypa1.com",
            "sender_display_name": "PayPal Security",
            "urls": ["http://paypa1.com/verify-account"],
            "url_display_texts": [
                {"url": "http://paypa1.com/verify-account", "display_text": "Click here"}
            ],
            "attachments": ["verify-account.exe"],
        }
        indicators = analyze_phishing_indicators(email_data)

        # Check specific indicators
        assert len(indicators.typosquat_domains) >= 1
        assert len(indicators.urgency_phrases) >= 3
        assert indicators.credential_request_detected is True
        assert indicators.attachment_risk_level in ("high", "critical")
        assert indicators.overall_risk_score >= 70

    def test_detect_sender_domain_mismatch(self):
        """Test detecting sender display name vs domain mismatch."""
        email_data = {
            "subject": "Account Update",
            "body": "Please update your account.",
            "sender_email": "support@random-domain.com",
            "sender_display_name": "Microsoft Support",
        }
        indicators = analyze_phishing_indicators(email_data)
        assert indicators.sender_domain_mismatch is True

    def test_detect_reply_to_mismatch(self):
        """Test detecting reply-to domain mismatch."""
        email_data = {
            "subject": "Invoice",
            "body": "Please review the attached invoice.",
            "sender_email": "billing@company.com",
            "reply_to": "billing@attacker.com",
        }
        indicators = analyze_phishing_indicators(email_data)
        assert any("Reply-to" in f for f in indicators.risk_factors)

    def test_detect_url_text_mismatch(self):
        """Test detecting URL display text mismatch."""
        email_data = {
            "subject": "Verify Account",
            "body": "Click the link below",
            "sender_email": "support@legitimate.com",
            "url_display_texts": [
                {"url": "http://evil.com/steal", "display_text": "http://paypal.com/verify"}
            ],
        }
        indicators = analyze_phishing_indicators(email_data)
        assert indicators.url_text_mismatch is True


# ============================================================================
# Tests for Attachment Risk Assessment
# ============================================================================


class TestAttachmentRiskAssessment:
    """Tests for attachment risk assessment."""

    def test_executable_is_high_risk(self):
        """Test that .exe attachments are high risk."""
        email_data = {
            "subject": "Invoice",
            "body": "See attached",
            "sender_email": "billing@company.com",
            "attachments": ["invoice.exe"],
        }
        indicators = analyze_phishing_indicators(email_data)
        assert indicators.attachment_risk_level in ("high", "critical")

    def test_script_files_are_high_risk(self):
        """Test that script files are high risk."""
        high_risk_files = [
            "script.bat", "script.cmd", "script.ps1",
            "script.vbs", "script.js", "app.scr"
        ]
        for filename in high_risk_files:
            email_data = {
                "subject": "Test",
                "body": "Test",
                "sender_email": "test@test.com",
                "attachments": [filename],
            }
            indicators = analyze_phishing_indicators(email_data)
            assert indicators.attachment_risk_level in ("high", "critical"), f"Failed for {filename}"

    def test_macro_documents_are_medium_risk(self):
        """Test that macro-enabled documents are medium risk."""
        medium_risk_files = ["document.docm", "spreadsheet.xlsm", "archive.zip", "archive.rar"]
        for filename in medium_risk_files:
            email_data = {
                "subject": "Test",
                "body": "Test",
                "sender_email": "test@test.com",
                "attachments": [filename],
            }
            indicators = analyze_phishing_indicators(email_data)
            assert indicators.attachment_risk_level == "medium", f"Failed for {filename}"

    def test_office_documents_are_low_risk(self):
        """Test that normal office documents are low risk."""
        low_risk_files = ["document.pdf", "document.docx", "spreadsheet.xlsx"]
        for filename in low_risk_files:
            email_data = {
                "subject": "Test",
                "body": "Test",
                "sender_email": "test@test.com",
                "attachments": [filename],
            }
            indicators = analyze_phishing_indicators(email_data)
            assert indicators.attachment_risk_level == "low", f"Failed for {filename}"

    def test_double_extension_is_critical(self):
        """Test that double extensions are critical risk."""
        email_data = {
            "subject": "Invoice",
            "body": "See attached invoice",
            "sender_email": "billing@company.com",
            "attachments": ["invoice.pdf.exe"],
        }
        indicators = analyze_phishing_indicators(email_data)
        assert indicators.attachment_risk_level == "critical"

    def test_no_attachments_is_none_risk(self):
        """Test that no attachments results in 'none' risk."""
        email_data = {
            "subject": "Hello",
            "body": "Just saying hi",
            "sender_email": "friend@email.com",
            "attachments": [],
        }
        indicators = analyze_phishing_indicators(email_data)
        assert indicators.attachment_risk_level == "none"


# ============================================================================
# Real Phishing Examples Tests
# ============================================================================


class TestRealPhishingExamples:
    """Tests using real-world phishing email patterns."""

    def test_netflix_phishing_example(self):
        """Test detection of Netflix phishing email pattern."""
        email_data = {
            "subject": "Your Netflix membership has been suspended",
            "body": """
            Hi,

            We were unable to validate your payment information for the next billing
            cycle of your subscription. We'll suspend your membership if we do not
            receive a response from you within 24 hours.

            To continue using Netflix services, please update your payment method.

            Click here to update your billing information

            Netflix Support
            """,
            "sender_email": "support@netf1ix-billing.com",
            "sender_display_name": "Netflix",
            "urls": ["http://netf1ix-billing.com/update-payment"],
            "url_display_texts": [
                {"url": "http://netf1ix-billing.com/update-payment",
                 "display_text": "Click here to update your billing information"}
            ],
        }
        indicators = analyze_phishing_indicators(email_data)

        assert indicators.overall_risk_score >= 50
        assert indicators.credential_request_detected is True
        assert len(indicators.urgency_phrases) >= 2

    def test_microsoft_phishing_example(self):
        """Test detection of Microsoft account phishing email pattern."""
        email_data = {
            "subject": "Security Alert: Unusual Sign-in Activity",
            "body": """
            We detected something unusual about a recent sign-in to your Microsoft
            account. To help keep you safe, we required an extra security challenge.

            Sign-in details:
            Country/region: Unknown
            IP address: 185.220.101.1
            Date: Today
            Platform: Unknown

            If this wasn't you, please secure your account immediately by clicking
            the button below to verify your identity and reset your password.

            Verify your account now

            The Microsoft account team
            """,
            "sender_email": "security@micr0soft-account.com",
            "sender_display_name": "Microsoft Account Team",
            "urls": ["http://micr0soft-account.com/verify"],
        }
        indicators = analyze_phishing_indicators(email_data)

        assert indicators.overall_risk_score >= 50
        # Should detect typosquatting in sender domain
        assert len(indicators.typosquat_domains) >= 1

    def test_amazon_phishing_example(self):
        """Test detection of Amazon phishing email pattern."""
        email_data = {
            "subject": "Action Required: Verify Your Amazon Account",
            "body": """
            Dear Amazon Customer,

            We have placed a hold on your Amazon account and all pending orders.

            We took this action because the billing information you provided did not
            match the information on file with the card issuer.

            To resolve this issue, please verify your billing information by clicking
            the link below:

            Verify Now

            If you do not verify your account within 24 hours, your account will be
            permanently suspended.

            Sincerely,
            Amazon Customer Service
            """,
            "sender_email": "no-reply@arnazon-support.com",
            "sender_display_name": "Amazon Customer Service",
            "urls": ["http://arnazon-support.com/verify-billing"],
            "attachments": ["verification-form.docm"],
        }
        indicators = analyze_phishing_indicators(email_data)

        assert indicators.overall_risk_score >= 60
        assert len(indicators.urgency_phrases) >= 3
        assert indicators.attachment_risk_level == "medium"

    def test_bank_phishing_example(self):
        """Test detection of bank phishing email pattern.

        Note: Bank of America is not in our default legitimate domains list,
        so typosquatting detection won't trigger. However, other indicators
        like urgency language, credential requests, and URL mismatch should still work.
        """
        email_data = {
            "subject": "Important: Your Account Has Been Locked",
            "body": """
            Dear Valued Customer,

            Your account has been locked due to security concerns. We have detected
            multiple unauthorized login attempts.

            To restore access to your account, please verify your identity:

            - Enter your online banking username and password
            - Confirm your security questions
            - Update your contact information

            FAILURE TO VERIFY YOUR ACCOUNT WITHIN 48 HOURS WILL RESULT IN
            PERMANENT ACCOUNT CLOSURE.

            Click here to login and verify your account.

            Customer Security Team
            """,
            "sender_email": "security@bank-of-arnerica.com",
            "sender_display_name": "Bank Security",
            "urls": ["http://bank-of-arnerica.com/secure-login"],
            "url_display_texts": [
                {"url": "http://bank-of-arnerica.com/secure-login",
                 "display_text": "https://www.bankofamerica.com/login"}
            ],
        }
        indicators = analyze_phishing_indicators(email_data)

        # Without typosquat detection (bankofamerica not in default list),
        # we still detect credential request, urgency, and URL mismatch
        assert indicators.overall_risk_score >= 40
        assert indicators.credential_request_detected is True
        assert indicators.url_text_mismatch is True
        assert len(indicators.urgency_phrases) >= 3

    def test_apple_phishing_example(self):
        """Test detection of Apple ID phishing email pattern."""
        email_data = {
            "subject": "Your Apple ID was used to sign in to iCloud",
            "body": """
            Your Apple ID (email@example.com) was used to sign in to iCloud via
            a web browser.

            Date and Time: January 15, 2024
            Operating System: Windows
            Browser: Chrome

            If you did not sign in recently, your account may be compromised.
            We strongly recommend that you change your password immediately.

            Change Password Now

            If you made this sign in, you can disregard this email.

            Apple Support
            """,
            "sender_email": "noreply@app1e-id-support.com",
            "sender_display_name": "Apple",
            "urls": ["http://app1e-id-support.com/reset-password"],
            "attachments": ["reset-instructions.pdf.exe"],
        }
        indicators = analyze_phishing_indicators(email_data)

        # Should detect typosquatting (app1e -> apple), critical attachment, urgency
        assert indicators.overall_risk_score >= 60
        assert indicators.attachment_risk_level == "critical"  # Double extension
        assert len(indicators.typosquat_domains) >= 1  # app1e vs apple
        assert indicators.sender_domain_mismatch is True  # Display says "Apple" but domain is different


# ============================================================================
# Integration Tests
# ============================================================================


class TestPhishingAnalysisIntegration:
    """Integration tests for phishing analysis workflow."""

    def test_risk_factors_populated(self):
        """Test that risk factors are properly populated."""
        email_data = {
            "subject": "URGENT: Account Suspended",
            "body": "Please verify your account by entering your password.",
            "sender_email": "support@paypa1.com",
            "urls": ["http://paypa1.com/verify"],
        }
        indicators = analyze_phishing_indicators(email_data)

        # Should have multiple risk factors
        assert len(indicators.risk_factors) >= 2
        # Risk factors should be descriptive strings
        for factor in indicators.risk_factors:
            assert isinstance(factor, str)
            assert len(factor) > 10

    def test_consistency_between_score_and_factors(self):
        """Test that risk score correlates with number of risk factors."""
        # Low risk email
        low_risk_data = {
            "subject": "Meeting notes",
            "body": "Here are the meeting notes from today.",
            "sender_email": "colleague@work.com",
        }
        low_risk_indicators = analyze_phishing_indicators(low_risk_data)

        # High risk email
        high_risk_data = {
            "subject": "URGENT: Verify your PayPal account NOW",
            "body": "Enter your password immediately or your account will be suspended within 24 hours.",
            "sender_email": "security@paypa1.com",
            "sender_display_name": "PayPal Security",
            "urls": ["http://paypa1.com/verify"],
            "attachments": ["verify.exe"],
        }
        high_risk_indicators = analyze_phishing_indicators(high_risk_data)

        # High risk should have higher score and more factors
        assert high_risk_indicators.overall_risk_score > low_risk_indicators.overall_risk_score
        assert len(high_risk_indicators.risk_factors) > len(low_risk_indicators.risk_factors)

    def test_all_indicator_types_can_be_detected(self):
        """Test that all indicator types can be detected in a single email."""
        comprehensive_phishing = {
            "subject": "URGENT: Security Alert - Account Suspended",
            "body": """
            Your account has been suspended due to unauthorized access.

            Please verify your account within 24 hours by clicking the link below
            and entering your password.

            Confirm your credentials now to restore access.

            Action required immediately!
            """,
            "sender_email": "security@paypa1.com",
            "sender_display_name": "PayPal Security Team",
            "reply_to": "support@different-domain.com",
            "urls": ["http://paypa1.com/verify", "http://g00gle.com/track"],
            "url_display_texts": [
                {"url": "http://evil.com", "display_text": "http://paypal.com/secure"}
            ],
            "attachments": ["security-update.exe"],
        }
        indicators = analyze_phishing_indicators(comprehensive_phishing)

        # All types should be detected
        assert len(indicators.typosquat_domains) >= 1
        assert len(indicators.urgency_phrases) >= 3
        assert indicators.credential_request_detected is True
        assert len(indicators.suspicious_urls) >= 1
        assert indicators.url_text_mismatch is True
        assert indicators.sender_domain_mismatch is True
        assert indicators.attachment_risk_level in ("high", "critical")
        assert indicators.overall_risk_score >= 80
        assert len(indicators.risk_factors) >= 5
