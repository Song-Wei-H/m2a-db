# Learning Feedback Specification

## Purpose

Learning Feedback 用於紀錄工具歷史效果，並提供 Risk Engine V3 作為評分依據。

---

## Data Sources

### Tool Results

```text
tool_results
```

### Normalized Results

```text
normalized_result
```

### Evidence Confidence

```text
evidence_confidence
```

### Decision Scores

```text
decision_scores
```

---

## Required Fields

```text
tool_name
success
service
evidence_type
learning_score
reason
created_at
```

---

## Scoring Rules

### Strong Positive

條件：

```text
工具成功
找到有效證據
```

分數：

```text
+1.0
```

---

### Positive

條件：

```text
工具成功
但證據有限
```

分數：

```text
+0.5
```

---

### Neutral

條件：

```text
無結果
```

分數：

```text
0
```

---

### Negative

條件：

```text
工具失敗
timeout
解析錯誤
```

分數：

```text
-0.5
```

---

## Example Record

```json
{
  "tool_name": "httpx_basic",
  "success": true,
  "service": "http",
  "evidence_type": "web_service",
  "learning_score": 0.8,
  "reason": "service identified successfully"
}
```

---

## Future Usage

Learning Feedback 將提供：

```text
Risk Engine V3
Decision Engine
Long-Term Learning
Tool Success Statistics
Adaptive Tool Ranking
```
