"""Result model shared by every rule.

The central invariant: **an unreadable input is a failure, never a skip.**
There is no status meaning "I could not check this, so assume fine". PENDING,
EXCEPTION, UNCHECKABLE and ERROR are all non-green, so a rule that cannot do
its job can never be mistaken for a rule that did its job and found nothing.
"""
from __future__ import annotations

import dataclasses
import enum


class Status(enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # Violated, with an explicit recorded exception. Deliberately NOT PASS: an
    # exception you cannot see is indistinguishable from a rule that does not
    # work.
    EXCEPTION = "EXCEPTION"
    # Written and implemented, but gated pending an external verification.
    PENDING = "PENDING"
    # The rule's inputs are absent from this repo (no Xcode project, no
    # manifests). Not a violation -- but also not a pass.
    NOT_APPLICABLE = "N/A"
    # The inputs exist but could not be READ: API denied, git failed, file
    # malformed. The rule did not run. Loud on purpose.
    UNCHECKABLE = "UNCHECKABLE"
    # The rule itself raised. This is a bug in the checker, and it is kept
    # distinct from UNCHECKABLE because an unavailable input can be tolerated
    # deliberately (--allow-unchecked) while a crashing rule never can. If a
    # crashing rule could be tolerated, every rule would be a check that cannot
    # fail and none of the others would mean anything.
    ERROR = "ERROR"


# Statuses that mean "this rule did not produce a clean verdict".
NON_GREEN = (Status.FAIL, Status.UNCHECKABLE, Status.ERROR)


@dataclasses.dataclass
class Finding:
    rule_id: str
    status: Status
    detail: str
    evidence: str = ""

    @property
    def is_violation(self) -> bool:
        return self.status in NON_GREEN


@dataclasses.dataclass
class Rule:
    rule_id: str
    title: str
    # "evidence"    = derived from a violation observed in these repos.
    # "speculative" = good practice, no observed violation behind it.
    basis: str
    check: object
    pending_reason: str = ""
