# SIGMASimTest

# Detection Rule Event-Set Similarity

Compare two detection rules and determine whether they match the **same underlying events**.

---

## Purpose

Answer one question only:

**Would the exact same EDR / SIEM events match both rules?**

---

## Scope

✔ Deterministic  
✔ Event-set based  
✔ Detection-as-code friendly  

✘ Behavioral similarity  
✘ MITRE / intent comparison  
✘ Alert volume estimation  
✘ Embeddings / cosine / RAG  

---

## Model

Each rule defines a **set of events**.

Possible relationships:

- **Identical** – same event set  
- **Overlapping** – some shared events  
- **Disjoint** – no shared events  

---

## How It Works

**Canonicalization**  
Ignores non-executing metadata. Keeps only logsource and detection logic.

**Atom Extraction**  
Rules are decomposed into atomic predicates:

`(field, operator, value, polarity)`

Atoms represent executable constraints.

**Logic Normalization**  
Detection conditions parsed into a simplified AST (AND / OR / NOT).  
Equivalent logic structures are normalized.

**Predicate Comparison**  
Positive atoms compared using set operations (Jaccard).  
Used only to determine identity or overlap, not frequency.

**Event-Equivalence Short-Circuit**  
If atoms, filters, and logsource match → **identical event set**.

---

## Usage

`python3 compare_sigma_rules.py rule1.yaml rule2.yaml`

---

## Expected Output

### Example 1: Identical Event Sets (Similarity = 1.0)

When two rules detect the exact same events:

```json
{
  "rule1": {
    "file": "examples/rule1.yaml",
    "id": "12345678-1234-1234-1234-123456789abc",
    "title": "Suspicious PowerShell Download"
  },
  "rule2": {
    "file": "examples/rule3.yaml",
    "id": "abcdef12-3456-7890-abcd-ef1234567890",
    "title": "Suspicious PowerShell Download Copy"
  },
  "similarity_metrics": {
    "atom_jaccard": 1.0,
    "logic_shape_similarity": 1.0,
    "service_penalty": 0.0,
    "filter_penalty": 0.0
  },
  "weighted_similarity": 1.0,
  "algorithm": {
    "name": "behavioral_novelty",
    "version": "1.2",
    "formula": "0.70 * atom_jaccard + 0.30 * logic_similarity - service_penalty - filter_penalty"
  }
}
```

**Interpretation**: These rules are functionally identical despite different titles and IDs.

### Example 2: Overlapping Event Sets (Similarity = 0.4333)

When rules share some detection logic but have important differences:

```json
{
  "rule1": {
    "file": "examples/rule1.yaml",
    "id": "12345678-1234-1234-1234-123456789abc",
    "title": "Suspicious PowerShell Download"
  },
  "rule2": {
    "file": "examples/rule2.yaml",
    "id": "87654321-4321-4321-4321-cba987654321",
    "title": "Malicious PowerShell Network Activity"
  },
  "similarity_metrics": {
    "atom_jaccard": 0.3333,
    "logic_shape_similarity": 1.0,
    "service_penalty": 0.0,
    "filter_penalty": 0.1
  },
  "weighted_similarity": 0.4333,
  "algorithm": {
    "name": "behavioral_novelty",
    "version": "1.2",
    "formula": "0.70 * atom_jaccard + 0.30 * logic_similarity - service_penalty - filter_penalty"
  }
}
```

**Interpretation**: These rules have overlapping detection patterns but different filter logic. The 0.3333 atom Jaccard indicates partial overlap in field constraints, while the 0.1 filter penalty reflects divergent exclusion logic.

### Output Schema

| Field | Description |
|-------|-------------|
| `rule1`, `rule2` | Metadata from each rule file |
| `similarity_metrics.atom_jaccard` | Jaccard similarity of positive atomic predicates (0-1) |
| `similarity_metrics.logic_shape_similarity` | Structural similarity of detection logic AST (0-1) |
| `similarity_metrics.service_penalty` | Penalty for log source service mismatch (0 or 0.05) |
| `similarity_metrics.filter_penalty` | Penalty for filter divergence (0-0.10) |
| `weighted_similarity` | Final composite similarity score (0-1) |
| `algorithm` | Algorithm metadata and formula |

---

## Supported Formats

- SIGMA (native)
- Any rule format expressible as fields, operators, values, and logic

---

## Design Principles

- Rules are executable logic  
- Similarity must be provable  
- Fail conservatively  
- No inference without telemetry  

---

## License

MIT
