"""Sample email fixtures for E2E testing of the phishing pipeline.

This module provides realistic email alert fixtures covering:
- OBVIOUS_PHISHING: Clear phishing with typosquatting, urgency, and credential requests
- SOPHISTICATED_PHISHING: Subtle phishing with lookalike domain, no obvious red flags
- LEGITIMATE_EMAIL: Normal business email that should pass triage
- FALSE_POSITIVE: Security notification that looks suspicious but is legitimate
"""

from __future__ import annotations


# =============================================================================
# OBVIOUS_PHISHING
# Classic phishing email with multiple red flags:
# - Typosquat domain (paypa1.com instead of paypal.com)
# - Urgency language ("immediately", "suspended")
# - Credential request ("verify your account")
# - Failed authentication (SPF/DKIM/DMARC fail)
# =============================================================================

OBVIOUS_PHISHING = {
    "message_id": "<phish-001@paypa1.com>",
    "subject": "URGENT: Your PayPal account has been suspended - Verify immediately",
    "sender": "security@paypa1.com",
    "from": "PayPal Security <security@paypa1.com>",
    "recipients": ["victim@company.com"],
    "to": "victim@company.com",
    "received_time": "2024-01-15T09:30:00Z",
    "body_text": """Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account has been suspended until you verify your identity.

IMPORTANT: You must verify your account immediately to avoid permanent suspension.

Click here to verify your account: http://paypa1-secure.com/verify/login

If you don't verify within 24 hours, your account will be permanently closed.

Thank you for your cooperation.

PayPal Security Team
""",
    "body_html": """
<html>
<body>
<p>Dear Valued Customer,</p>

<p>We have detected unusual activity on your PayPal account. Your account has been <b>suspended</b> until you verify your identity.</p>

<p style="color: red;"><b>IMPORTANT:</b> You must verify your account immediately to avoid permanent suspension.</p>

<p><a href="http://paypa1-secure.com/verify/login">Click here to verify your account</a></p>

<p>If you don't verify within 24 hours, your account will be permanently closed.</p>

<p>Thank you for your cooperation.</p>
<p>PayPal Security Team</p>
</body>
</html>
""",
    "headers": {
        "From": "PayPal Security <security@paypa1.com>",
        "To": "victim@company.com",
        "Subject": "URGENT: Your PayPal account has been suspended - Verify immediately",
        "Message-ID": "<phish-001@paypa1.com>",
        "Date": "Mon, 15 Jan 2024 09:30:00 +0000",
        "Authentication-Results": "mx.company.com; spf=fail smtp.mailfrom=paypa1.com; dkim=fail; dmarc=fail",
        "Received-SPF": "fail (domain paypa1.com does not designate sending IP as permitted sender)",
    },
    "urls": ["http://paypa1-secure.com/verify/login"],
    "attachments": [],
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
    "type": "email_security",
}


# =============================================================================
# SOPHISTICATED_PHISHING
# Subtle phishing that's harder to detect:
# - Lookalike domain (micros0ft-security.com with '0' instead of 'o')
# - No obvious urgency language (professional tone)
# - Passes some authentication checks (SPF pass but DMARC fail)
# - Legitimate-looking security notification format
# =============================================================================

SOPHISTICATED_PHISHING = {
    "message_id": "<sec-notice-7382@micros0ft-security.com>",
    "subject": "Security Review Required for Your Microsoft 365 Account",
    "sender": "no-reply@micros0ft-security.com",
    "from": "Microsoft Security <no-reply@micros0ft-security.com>",
    "recipients": ["employee@company.com"],
    "to": "employee@company.com",
    "received_time": "2024-01-15T14:22:00Z",
    "body_text": """Microsoft Security Notification

As part of our ongoing security measures, we periodically review account activity to ensure the protection of your data.

We noticed your account was accessed from a new location. If this was you, no action is needed.

If you do not recognize this activity, please review your account security settings:

https://micros0ft-security.com/account/review

Recent Activity Summary:
- Location: San Jose, California
- Device: Windows 11 PC
- Time: January 14, 2024 at 3:45 PM PST

This is an automated message from Microsoft Security.
For questions, visit our Help Center.

Microsoft Corporation
One Microsoft Way
Redmond, WA 98052
""",
    "body_html": """
<!DOCTYPE html>
<html>
<head><style>body{font-family:Segoe UI,Arial,sans-serif;}</style></head>
<body>
<table width="600" style="margin:auto;">
<tr><td style="background:#0078d4;padding:20px;text-align:center;">
<img src="https://micros0ft-security.com/logo.png" alt="Microsoft" width="120">
</td></tr>
<tr><td style="padding:30px;">
<h2 style="color:#1a1a1a;">Security Review Required</h2>

<p>As part of our ongoing security measures, we periodically review account activity to ensure the protection of your data.</p>

<p>We noticed your account was accessed from a new location. If this was you, no action is needed.</p>

<p>If you do not recognize this activity, please review your account security settings:</p>

<p style="text-align:center;margin:30px 0;">
<a href="https://micros0ft-security.com/account/review" style="background:#0078d4;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;">Review Security Settings</a>
</p>

<table style="background:#f5f5f5;padding:15px;width:100%;">
<tr><td><b>Recent Activity Summary:</b></td></tr>
<tr><td>Location: San Jose, California</td></tr>
<tr><td>Device: Windows 11 PC</td></tr>
<tr><td>Time: January 14, 2024 at 3:45 PM PST</td></tr>
</table>

<p style="color:#666;font-size:12px;margin-top:30px;">This is an automated message from Microsoft Security.<br>For questions, visit our Help Center.</p>
</td></tr>
<tr><td style="background:#f5f5f5;padding:15px;text-align:center;font-size:11px;color:#666;">
Microsoft Corporation<br>One Microsoft Way<br>Redmond, WA 98052
</td></tr>
</table>
</body>
</html>
""",
    "headers": {
        "From": "Microsoft Security <no-reply@micros0ft-security.com>",
        "To": "employee@company.com",
        "Subject": "Security Review Required for Your Microsoft 365 Account",
        "Message-ID": "<sec-notice-7382@micros0ft-security.com>",
        "Date": "Mon, 15 Jan 2024 14:22:00 +0000",
        "Authentication-Results": "mx.company.com; spf=pass smtp.mailfrom=micros0ft-security.com; dkim=none; dmarc=fail",
        "Received-SPF": "pass",
    },
    "urls": ["https://micros0ft-security.com/account/review"],
    "attachments": [],
    "spf_result": "pass",
    "dkim_result": "none",
    "dmarc_result": "fail",
    "type": "email_security",
}


# =============================================================================
# LEGITIMATE_EMAIL
# Normal business email that should NOT trigger phishing alerts:
# - Known sender domain (company.com internal)
# - All authentication passes
# - Normal business content
# - Internal SharePoint links
# =============================================================================

LEGITIMATE_EMAIL = {
    "message_id": "<report-2024-Q4@company.com>",
    "subject": "Q4 2024 Financial Report - Review Required",
    "sender": "finance@company.com",
    "from": "Finance Team <finance@company.com>",
    "recipients": ["manager@company.com"],
    "to": "manager@company.com",
    "received_time": "2024-01-15T10:00:00Z",
    "body_text": """Hi Team,

Please find the Q4 2024 Financial Report attached and available on SharePoint.

Key highlights:
- Revenue increased 12% year-over-year
- Operating expenses within budget
- Strong cash position entering 2024

Please review by end of week and let me know if you have questions.

SharePoint link: https://company.sharepoint.com/sites/finance/reports/Q4-2024

Best regards,
Finance Team
""",
    "body_html": """
<html>
<body>
<p>Hi Team,</p>

<p>Please find the Q4 2024 Financial Report attached and available on SharePoint.</p>

<p><b>Key highlights:</b></p>
<ul>
<li>Revenue increased 12% year-over-year</li>
<li>Operating expenses within budget</li>
<li>Strong cash position entering 2024</li>
</ul>

<p>Please review by end of week and let me know if you have questions.</p>

<p>SharePoint link: <a href="https://company.sharepoint.com/sites/finance/reports/Q4-2024">Q4 2024 Report</a></p>

<p>Best regards,<br>Finance Team</p>
</body>
</html>
""",
    "headers": {
        "From": "Finance Team <finance@company.com>",
        "To": "manager@company.com",
        "Subject": "Q4 2024 Financial Report - Review Required",
        "Message-ID": "<report-2024-Q4@company.com>",
        "Date": "Mon, 15 Jan 2024 10:00:00 +0000",
        "Authentication-Results": "mx.company.com; spf=pass smtp.mailfrom=company.com; dkim=pass; dmarc=pass",
        "Received-SPF": "pass",
        "DKIM-Signature": "v=1; a=rsa-sha256; d=company.com; s=selector1; ...",
    },
    "urls": ["https://company.sharepoint.com/sites/finance/reports/Q4-2024"],
    "attachments": [
        {
            "filename": "Q4-2024-Financial-Report.pdf",
            "content_type": "application/pdf",
            "size_bytes": 1548792,
        }
    ],
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
    "type": "email_security",
}


# =============================================================================
# FALSE_POSITIVE
# Legitimate security notification that looks suspicious:
# - Real security notification from known security vendor
# - Contains "suspicious" language (it's reporting a security event)
# - Contains links to password reset (legitimate)
# - Authentication passes
# =============================================================================

FALSE_POSITIVE = {
    "message_id": "<alert-89721@okta.com>",
    "subject": "Security Alert: Suspicious login detected for your account",
    "sender": "noreply@okta.com",
    "from": "Okta Security <noreply@okta.com>",
    "recipients": ["user@company.com"],
    "to": "user@company.com",
    "received_time": "2024-01-15T08:15:00Z",
    "body_text": """Okta Security Alert

A suspicious sign-in attempt was detected for your account.

Details:
- Time: January 15, 2024 at 8:10 AM PST
- Location: Unknown
- IP Address: 203.0.113.50
- Status: Blocked

If this was you, you can safely ignore this message.

If this wasn't you, we recommend you:
1. Review your recent account activity
2. Reset your password: https://company.okta.com/password/reset
3. Enable or verify MFA settings

For help, contact your IT administrator or visit Okta Support.

This is an automated security notification. Do not reply to this email.

Okta, Inc.
100 First Street
San Francisco, CA 94105
""",
    "body_html": """
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
<div style="background: #00297a; padding: 20px; text-align: center;">
<img src="https://www.okta.com/logo.png" alt="Okta" height="40">
</div>

<div style="padding: 30px;">
<h2 style="color: #00297a;">Security Alert</h2>

<p style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107;">
A suspicious sign-in attempt was detected for your account.
</p>

<table style="width: 100%; margin: 20px 0;">
<tr><td><b>Time:</b></td><td>January 15, 2024 at 8:10 AM PST</td></tr>
<tr><td><b>Location:</b></td><td>Unknown</td></tr>
<tr><td><b>IP Address:</b></td><td>203.0.113.50</td></tr>
<tr><td><b>Status:</b></td><td style="color: green;">Blocked</td></tr>
</table>

<p>If this was you, you can safely ignore this message.</p>

<p>If this wasn't you, we recommend you:</p>
<ol>
<li>Review your recent account activity</li>
<li><a href="https://company.okta.com/password/reset">Reset your password</a></li>
<li>Enable or verify MFA settings</li>
</ol>

<p>For help, contact your IT administrator or visit <a href="https://support.okta.com">Okta Support</a>.</p>

<p style="color: #666; font-size: 12px; margin-top: 30px;">
This is an automated security notification. Do not reply to this email.
</p>
</div>

<div style="background: #f5f5f5; padding: 15px; text-align: center; font-size: 11px; color: #666;">
Okta, Inc.<br>100 First Street<br>San Francisco, CA 94105
</div>
</body>
</html>
""",
    "headers": {
        "From": "Okta Security <noreply@okta.com>",
        "To": "user@company.com",
        "Subject": "Security Alert: Suspicious login detected for your account",
        "Message-ID": "<alert-89721@okta.com>",
        "Date": "Mon, 15 Jan 2024 08:15:00 +0000",
        "Authentication-Results": "mx.company.com; spf=pass smtp.mailfrom=okta.com; dkim=pass header.d=okta.com; dmarc=pass",
        "Received-SPF": "pass",
        "DKIM-Signature": "v=1; a=rsa-sha256; d=okta.com; s=selector1; ...",
        "List-Unsubscribe": "<https://okta.com/unsubscribe>",
    },
    "urls": [
        "https://company.okta.com/password/reset",
        "https://support.okta.com",
    ],
    "attachments": [],
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
    "type": "email_security",
}
