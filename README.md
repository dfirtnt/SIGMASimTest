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
