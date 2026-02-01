# Confidence Scoring

How the AI agent determines confidence in its verdicts.

## Confidence Factors

The agent considers multiple factors when calculating confidence:

### Evidence Quality

| Factor | Impact |
|--------|--------|
| Threat intel match (high confidence) | +0.3 |
| Threat intel match (low confidence) | +0.1 |
| Authentication failure | +0.2 |
| Known malicious indicator | +0.3 |
| Suspicious pattern | +0.1 |

### Evidence Quantity

| Indicators | Confidence Boost |
|------------|------------------|
| 1 indicator | Base |
| 2-3 indicators | +0.1 |
| 4-5 indicators | +0.2 |
| 6+ indicators | +0.3 |

### Data Completeness

| Missing Data | Confidence Penalty |
|--------------|-------------------|
| None | 0 |
| Minor (sender reputation) | -0.1 |
| Moderate (attachment analysis) | -0.2 |
| Major (multiple tools failed) | -0.3 |

## Calculation Example

**Phishing Email Analysis:**

```
Base confidence: 0.5

Evidence found:
+ SPF failed: +0.15
+ DKIM failed: +0.15
+ Sender domain < 7 days old: +0.2
+ URL matches phishing pattern: +0.25
+ VirusTotal flags URL as phishing: +0.2

Evidence count (5): +0.2

Data completeness: All tools succeeded: +0

Final confidence: 0.5 + 0.15 + 0.15 + 0.2 + 0.25 + 0.2 + 0.2 = 1.0 (capped at 0.99)

Verdict: malicious, confidence: 0.99
```

## Confidence Thresholds

Policy decisions use confidence thresholds:

```toml
# Auto-quarantine high confidence malicious
[[policy.rules]]
name = "auto_quarantine_confident"
classification = "malicious"
confidence_min = 0.9
action = "quarantine_email"
decision = "allowed"

# Require review for lower confidence
[[policy.rules]]
name = "review_uncertain"
confidence_max = 0.7
decision = "requires_approval"
approval_level = "analyst"
```

## Confidence Calibration

The agent is calibrated so confidence correlates with accuracy:

| Stated Confidence | Expected Accuracy |
|-------------------|-------------------|
| 0.9 | ~90% of verdicts correct |
| 0.8 | ~80% of verdicts correct |
| 0.7 | ~70% of verdicts correct |

### Monitoring Calibration

Track calibration with metrics:

```promql
# Accuracy at confidence level
triage_accuracy_by_confidence{confidence_bucket="0.9-1.0"}
```

### Improving Calibration

1. **Feedback loop** - Log false positives to improve
2. **Periodic review** - Sample low-confidence verdicts
3. **Model updates** - Retrain with corrected examples

## Handling Low Confidence

When confidence is low:

### Option 1: Escalate

```yaml
- condition: confidence < 0.6
  action: escalate
  parameters:
    level: analyst
    reason: "Low confidence verdict requires human review"
```

### Option 2: Gather More Data

```yaml
- condition: confidence < 0.6
  action: request_additional_data
  parameters:
    - "sender_history"
    - "recipient_context"
```

### Option 3: Conservative Default

```yaml
- condition: confidence < 0.6
  action: quarantine_email
  parameters:
    reason: "Quarantined pending review due to uncertainty"
```

## Confidence in UI

Dashboard displays confidence visually:

| Confidence | Display |
|------------|---------|
| 0.9+ | Green badge, "High Confidence" |
| 0.7-0.9 | Yellow badge, "Moderate Confidence" |
| 0.5-0.7 | Orange badge, "Low Confidence" |
| <0.5 | Red badge, "Very Low Confidence" |

## Improving Confidence

Actions that help the agent be more confident:

1. **Complete data** - Ensure all tools succeed
2. **Rich context** - Provide incident metadata
3. **Historical data** - Include past incidents with similar patterns
4. **Clear playbooks** - Well-defined analysis steps
