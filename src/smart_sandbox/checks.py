"""Helper for recording conformance check results on a step."""

from smart_sandbox.models import CheckResult, CheckSeverity, Step


class Checker:
    """Records pass/fail checks on a step; check ids and doc refs stay with
    the result so the report can link back to the integration guide."""

    def __init__(self, step: Step) -> None:
        self._step = step

    def check(
        self,
        check_id: str,
        description: str,
        doc_ref: str,
        passed: bool,  # noqa: FBT001
        *,
        severity: CheckSeverity = CheckSeverity.FAIL,
        detail: str = "",
    ) -> bool:
        self._step.checks.append(
            CheckResult(
                check_id=check_id,
                description=description,
                doc_ref=doc_ref,
                severity=severity,
                passed=passed,
                detail=detail,
            )
        )
        return passed

    def info(self, check_id: str, description: str, doc_ref: str, detail: str) -> None:
        self.check(
            check_id,
            description,
            doc_ref,
            True,
            severity=CheckSeverity.INFO,
            detail=detail,
        )
