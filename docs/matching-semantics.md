# Matching semantics: what is normalized, what is preserved, and why

The single most common objection to this engine, from detection engineers, is some form of:

> You lowercase my values. Attackers use weird casing and misspell things deliberately.
> Isn't that exactly the signal I'm hunting? Aren't you throwing it away?

Short answer: **no.** Attacker misspellings, homoglyphs, and case-anomaly hunts are all
preserved as distinct atoms. This page shows the worked cases and names the one deployment
assumption that would change the answer.

---

## The distinction that resolves it

Two different questions are easy to merge, and everything here depends on keeping them
apart:

| | Question | Decided by |
|---|---|---|
| **1. Detection** | Does this rule fire on this event? | Sigma semantics + your SIEM/EDR backend |
| **2. Comparison** | Do these *two rules* fire on the same events? | This engine |

**SIGMASimTest only ever answers (2).** It never executes a rule against telemetry, and
nothing it does changes what any rule detects. Normalization here adjusts whether two
*rules* are judged equivalent — not whether a rule matches an event.

That matters because the intuition "normalization loses signal" is correct at layer (1)
and does not transfer to layer (2). The test this engine applies is:

> Would these two rules alert on different events?

If the answer is no, they are duplicates, however differently they happen to be typed.

---

## Nothing is fuzzy

There is no spelling correction, no edit distance, no synonym inference, no stemming, no
embeddings, and no similarity heuristic of any kind operating on values. Every comparison
is exact set membership over canonical strings.

Concretely, all of these stay **distinct** atoms:

| Rule fragment | Atom identity |
|---|---|
| `CommandLine\|contains: 'Invoke-WebRequst'` | `process.command_line\|contains\|invoke-webrequst` |
| `CommandLine\|contains: 'Invoke-WebRequest'` | `process.command_line\|contains\|invoke-webrequest` |
| `Image\|endswith: '\rundll32.exe'` | `process.image\|endswith\|/rundll32.exe` |
| `Image\|endswith: '\rund1l32.exe'` | `process.image\|endswith\|/rund1l32.exe` |

A rule hunting an attacker's typo, a homoglyph binary name, or a lookalike LOLBin is never
collapsed into a rule hunting the legitimate string. Those are different hunts and the
engine reports them as different hunts.

---

## Case: folded only where the matcher already ignores it

Sigma string comparison is **case-insensitive by default**. That is a property of the
Sigma specification and of the backends rules compile to — not a choice this engine makes.
It is precisely why the `|cased` modifier exists as an explicit opt-in.

So for a default-modifier rule:

```yaml
CommandLine|contains: 'Mimikatz'
```

…the deployed rule already fires on `mimikatz`, `MIMIKATZ`, and `MiMiKaTz`. Case carries
no discriminating power *for that rule*, because the matcher was never going to honor it.

Which means two analysts writing the same hunt in different casing have authored rules
that alert on **byte-identical event sets**:

| Rule fragment | Atom identity |
|---|---|
| `CommandLine\|contains: 'Mimikatz'` | `process.command_line\|contains\|mimikatz` |
| `CommandLine\|contains: 'mimikatz'` | `process.command_line\|contains\|mimikatz` |

Folding these together is the engine reporting the truth: they are duplicates. Refusing to
fold would make the deduplicator blind to a real duplicate and let the corpus accumulate
two rules that do the same thing — the exact failure this tool exists to prevent.

### Hunting case as tradecraft: use `|cased`

When the casing itself *is* the signal — a packer that emits `PoWeRsHeLl`, an actor whose
tooling has a consistent capitalization tell — express it with `|cased`, and the engine
preserves it:

| Rule fragment | Atom identity |
|---|---|
| `CommandLine\|contains\|cased: 'MiMiKaTz'` | `process.command_line\|contains\|cased\|MiMiKaTz` |
| `CommandLine\|contains\|cased: 'mimikatz'` | `process.command_line\|contains\|cased\|mimikatz` |
| `CommandLine\|contains: 'Mimikatz'` | `process.command_line\|contains\|mimikatz` |

All three are distinct. Note the third line especially: **a `|cased` atom never collapses
into its case-insensitive sibling**, even for the same literal. A rule hunting one specific
capitalization is a materially narrower hunt than one accepting any capitalization, and the
engine keeps them apart.

`re` (regex) values also always preserve case — `CommandLine|re: 'Invoke-[Ww]eb'` keeps its
pattern verbatim as `process.command_line|re|Invoke-[Ww]eb`.

### Authoring implication

If case-anomaly detection matters to your program, `|cased` should be a deliberate
authoring convention. An author who *intends* case-sensitivity but omits the modifier gets
case-insensitive matching **in production** — the engine is faithfully reporting what the
rule does, not what the author meant. That gap is fixed in the rule, not in the comparator.

---

## Full normalization inventory

Every transformation applied to an atom before comparison. None is fuzzy; each either
mirrors matcher behavior or resolves a curated synonym table.

| Normalization | Scope | Rationale |
|---|---|---|
| Case folding for `contains` / `endswith` / `startswith` / `eq`; `\|cased` and `re` exempt | value | Sigma matches case-insensitively by default, so both forms hit the same events |
| `\` → `/`; doubled `\\` preserved | value | Path-separator canonicalization so `\powershell.exe` and `/powershell.exe` don't split |
| Edge wildcard folding: `"*foo*"` as `eq` ≡ `\|contains: "foo"` | operator + value | Identical matcher semantics expressed two ways. Only *edge* wildcards; internal `foo*bar` untouched, `re` and numeric ops never folded |
| Field aliasing: `CommandLine` / `ProcessCommandLine` / `command_line` → `process.command_line` | field name | Curated static table plus a snake_case overlay. A lookup, not an inference |
| `strip()` whitespace; bool → `"true"`/`"false"`; numbers → string | value | Deterministic serialization |

What is **not** normalized, ever: spelling, homoglyphs, character substitution, word order,
synonyms, semantic field equivalence (a basename is not a path), or values under `re`.

---

## Measured impact

Removing case folding, measured against 3,134 real SigmaHQ rules (2,235 successfully
extracted):

| | Folded (current) | Literal case-sensitive |
|---|---|---|
| Rules whose atom set changes | — | **1,508 of 2,235 (67.5%)** |
| Distinct atoms | 9,303 | 9,511 (+208) |
| Exact-hash duplicate groups found | 1 | 1 |

Folding only ever *merges* atoms that the matcher treats identically; removing it only ever
*splits*. The effect is therefore uniformly lower similarity across the corpus — more false
`NOVEL`, weaker deduplication — without any corresponding gain in detection fidelity, since
no rule's matching behavior changes either way.

---

## The assumption that would change this

Everything above rests on one deployment fact: **Sigma's default string matching is
case-insensitive, and your backend honors that.**

If your telemetry pipeline executes case-sensitively — some do — then folding models the
wrong matcher and should be removed. In that world, `contains: 'Mimikatz'` and
`contains: 'mimikatz'` genuinely are different hunts, and merging them is wrong.

That is a deployment question, not a spec question, and it is the one input that would
reverse this design. If it applies to you, the change is confined to
`_CASE_INSENSITIVE_OPS` in [`atom_extractor.py`](../sigma_similarity/atom_extractor.py) —
but expect the 67.5% shift above.

---

## See also

- [README — Atom identity](../README.md#atom-identity) — the 3-slot identity and the
  normalization summary
- [README — Scoring](../README.md#scoring) — how atoms become a similarity score
- `tests/test_regression_case_sensitive_atoms.py` and `tests/test_wildcard_fold.py` — the
  regression contracts locking in every behavior on this page
