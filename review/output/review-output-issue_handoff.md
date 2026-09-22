# Review Finding Handoff

Use this format when confirmed review findings will be posted to an Issue, PR comment, or other persistent handoff location for a later remediation agent.

Only confirmed findings that passed the normal evidence and finding gates may be handed off.

## Finding format

### RV-001 — [P1] <Concise defect title>

**Status:** Open

**Confidence:** 0.95

**Location:** `<path:line-range>`

**Trigger**

Describe the concrete runtime, build, configuration, state, or failure condition required to expose the defect.

**Evidence**

State the minimum repository-backed evidence proving the finding.

Do not include hidden reasoning or speculative possibilities.

**Impact**

Describe the externally observable engineering consequence.

**Suggested direction**

Describe the preferred remediation direction based on the repository's existing architecture, canonical implementation, or ownership model.

Do not prescribe an exact patch or implementation code. If more than one repair is plausible, state the decision criteria.

**Constraints / Non-goals**

Record important boundaries the remediation must preserve, for example:

- do not create a second implementation;
- preserve the canonical owner;
- do not change the public API;
- do not weaken tests;
- do not expand the original Issue scope.

**Acceptance check**

State observable conditions that would demonstrate that this finding is resolved.

**Suggested validation**

List the smallest useful tests, build commands, or runtime checks that should validate the fix.

**Residual uncertainty**

Include only material information that the reviewer could not verify. Otherwise write `None`.

---

## Handoff rules

A remediation agent must treat every finding as a review claim that must be revalidated against the current repository state before code is changed.

The remediation agent may reject a finding if repository evidence proves that it no longer applies or was incorrect.

Do not resolve or delete a finding merely because code was changed. Resolution requires validation evidence.

If fixing the finding would exceed the original Issue scope or require an independent architecture decision, do not silently expand the patch. Record it as a follow-up instead.

Use stable finding IDs (`RV-001`, `RV-002`, ...) so later comments, commits, and re-reviews can refer to the same defect unambiguously.
