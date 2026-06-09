# Decision Engine Specification

## Purpose

Decision Engine 負責根據 Risk Engine V3 的結果，決定：

* next_tool
* next_action
* approval_required
* termination_reason

---

## Inputs

### Open Ports

來源：

* open_ports

### Tool Results

來源：

* tool_results

### Normalized Results

來源：

* normalized_result

### Risk Assessment

來源：

* decision_scores
* evidence_confidence

---

## Supported Actions

### continue

條件：

```text
next_tool != null
```

代表：

```text
繼續下一輪工具驗證
```

---

### verify

條件：

```text
需要額外證據確認
```

例如：

```text
疑似漏洞
版本匹配
低信心結果
```

---

### remediate

條件：

```text
KEV = true
OR
CVSS >= 9.0
```

代表：

```text
停止後續驗證
產出修補建議
```

---

### stop

條件：

```text
next_tool == null
```

或：

```text
已達 max_round
```

---

## Tool Selection

### HTTP

```text
80
443
8080
8443
```

流程：

```text
httpx_basic
↓
nuclei_safe
↓
dirb_safe
```

---

### SSH

```text
22
```

流程：

```text
ssh-enum
```

---

### MySQL

```text
3306
```

流程：

```text
mysql-info
```

---

## Consistency Rule

禁止：

```text
next_tool != null
next_action = stop
```

必須：

```text
next_tool != null
→ continue
```

---

## Output Schema

```json
{
  "risk_score": 7.2,
  "next_tool": "nuclei_safe",
  "next_action": "continue",
  "confidence": 0.83,
  "reason": "HTTP service detected"
}
```
