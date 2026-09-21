"""Result model shared by every rule.

A rule reports exactly one Status. There is deliberately no status that means
"I could not check this, so assume fine": UNCHECKABLE and PENDING are both
non-green, so a rule that cannot do its job can never be mistaken for a rule
that did its job and found nothing.
"""
from __future__ import annotations

import dataclasses
import enum


class Status(enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # The rule is written and implemented but is gated off pending an external
    # verification. Never green, never red -- it is not being applied.
    PENDING = "PENDING"
    # The rule could not run here because the repo lacks the inputs it reads
    # (e.g. no Xcode project). Not a violation, but not a pass either.
    NOT_APPLICABLE = "N/A"
    # The rule is violated, and the violation has been granted an explicit,
    # recorded exception. Deliberately NOT PASS: an exception you cannot see is
    # indistinguishable from a rule that does not work.
    EXCEPTION = "EXCEPTION"
    # The inputs exist but could not be read (API denied, malformed file).
    # This is loud on purpose: silence here is how checkers start lying.
    UNCHECKABLE = "UNCHECKABLE"


@dataclasses.dataclass
class Finding:
    rule_id: str
    status: Status
    detail: str
    evidence: str = ""

    @property
    def is_violation(self) -> bool:
        return self.status in (Status.FAIL, Status.UNCHECKABLE)


@dataclasses.dataclass
class Rule:
    rule_id: str
    title: str
    # "evidence" = derived from an observed violation in this ecosystem.
    # "speculative" = good practice, but no observed violation behind it.
    basis: str
    check: object
    pending_reason: str = ""
