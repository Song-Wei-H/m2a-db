# Risk Engine V3 Specification

## Purpose

Risk Engine V3 根據服務、漏洞證據、CVE 情報與 Learning Feedback 計算風險分數。

---

## Inputs

### Open Ports

來源：

```text
open_ports
```

---

### Tool Results

來源：

```text
tool_results
```

---

### Evidence Confidence

來源：

```text
evidence_confidence
```

---

### CVE Intelligence

來源：

```text
cve_enrichment
```

包含：

```text
CVSS
EPSS
KEV
```

---

### Learning Feedback

來源：

```text
learning_feedback
```

---

## Risk Formula

```text
risk_score =
service_score +
vulnerability_score +
confidence_score +
threat_intel_score +
learning_score
```

---

## Severity Mapping

### Critical

```text
risk_score >= 9
```

### High

```text
risk_score >= 7
```

### Medium

```text
risk_score >= 4
```

### Low

```text
risk_score < 4
```

---

## Threat Intelligence Bonus

### KEV

```text
+3
```

### CVSS >= 9

```text
+2
```

### EPSS > 0.8

```text
+2
```

---

## Output

```json
{
  "risk_score": 8.6,
  "severity": "high",
  "kev": true,
  "epss": 0.91,
  "confidence": 0.89
}
```
