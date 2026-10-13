"""Detection settings shared by the detectors, the CLI and the dashboard."""

from __future__ import annotations

from dataclasses import dataclass

# Count failed logins per (source IP, account) pair: targeted password guessing.
GROUP_BY_ACCOUNT_AND_SOURCE = "account_and_source"
# Count failed logins per source IP only: also catches one source trying many accounts.
GROUP_BY_SOURCE = "source"
VALID_GROUP_BY = (GROUP_BY_ACCOUNT_AND_SOURCE, GROUP_BY_SOURCE)


@dataclass(frozen=True)
class DetectionConfig:
    """Tunable thresholds for the detection rules (see docs/detection_rules.md)."""

    failure_threshold: int = 5
    failure_window_minutes: int = 10
    group_by: str = GROUP_BY_ACCOUNT_AND_SOURCE
    success_min_failures: int = 3
    success_lookback_minutes: int = 30

    def __post_init__(self) -> None:
        for name in (
            "failure_threshold",
            "failure_window_minutes",
            "success_min_failures",
            "success_lookback_minutes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a whole number of at least 1, got {value!r}.")
        if self.group_by not in VALID_GROUP_BY:
            raise ValueError(
                f"group_by must be one of {', '.join(VALID_GROUP_BY)}, got {self.group_by!r}."
            )
