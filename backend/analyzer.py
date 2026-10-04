from backend.scanner import (
    scan_directory,
    count_scannable_files,
)
from backend.rules import get_rule


SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}


SUPPORTING_RULES = {
    "CRYPTO-HASHLIB",
    "CRYPTO-CIPHER",
    "CRYPTO-CRYPTO-CIPHER",
}


def analyze_directory(directory: str) -> list[dict]:
    """Scan, enrich, contextualize, and consolidate findings."""

    raw_findings = scan_directory(directory)

    enriched = []

    for finding in raw_findings:

        rule = get_rule(
            finding["rule_id"]
        )

        severity = rule["severity"]

        title = rule["title"]

        description = rule["description"]

        recommendation = rule["recommendation"]

        risk_score = rule["risk_score"]


        # --------------------------------------------------
        # Context-aware TLS analysis
        # --------------------------------------------------

        if finding["rule_id"] == "CRYPTO-TLS":

            matched_text = (
                finding["matched_text"]
                .upper()
            )

            if matched_text in {
                "TLS1.0",
                "TLS1.1",
                "TLSV1",
                "TLSV1.0",
                "TLSV1.1",
            }:

                severity = "High"

                title = (
                    "Deprecated TLS protocol"
                )

                description = (
                    "An outdated TLS protocol "
                    "version was detected."
                )

                recommendation = (
                    "Migrate to a currently "
                    "supported TLS version "
                    "and review cipher-suite "
                    "configuration."
                )

                risk_score = 80


        enriched.append(
            {
                **finding,

                "title": title,

                "severity": severity,

                "description": description,

                "recommendation":
                    recommendation,

                "confidence":
                    finding.get(
                        "confidence",
                        rule["confidence"],
                    ),

                "risk_score":
                    risk_score,
            }
        )


    return consolidate_findings(
        enriched
    )


def consolidate_findings(
    findings: list[dict],
) -> list[dict]:
    """
    Consolidate findings on the same file and line.

    Primary security findings take priority over
    supporting API/library detections.
    """

    grouped: dict[
        tuple[str, int],
        list[dict]
    ] = {}


    for finding in findings:

        key = (
            finding["file"],
            finding["line"],
        )

        grouped.setdefault(
            key,
            []
        ).append(finding)


    consolidated = []


    for group in grouped.values():

        primary = [
            finding
            for finding in group
            if finding["rule_id"]
            not in SUPPORTING_RULES
        ]


        supporting = [
            finding
            for finding in group
            if finding["rule_id"]
            in SUPPORTING_RULES
        ]


        if primary:

            best = max(
                primary,
                key=lambda finding: (
                    SEVERITY_ORDER.get(
                        finding["severity"],
                        0,
                    ),
                    finding["risk_score"],
                ),
            )

            consolidated.append(
                best
            )


        elif supporting:

            best = max(
                supporting,
                key=lambda finding: (
                    SEVERITY_ORDER.get(
                        finding["severity"],
                        0,
                    ),
                    finding["risk_score"],
                ),
            )

            consolidated.append(
                best
            )


    return sorted(
        consolidated,
        key=lambda finding: (
            finding["file"],
            finding["line"],
            -SEVERITY_ORDER.get(
                finding["severity"],
                0,
            ),
        ),
    )


def get_summary(
    findings: list[dict],
    directory: str | None = None,
) -> dict:
    """Create the overall ECDAT scan summary."""

    summary = {
        "total_findings": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total_risk_score": 0,
        "files_with_findings": 0,
        "files_scanned": 0,
    }


    files = set()


    for finding in findings:

        severity = finding.get(
            "severity",
            "Info",
        ).lower()


        if severity in summary:

            summary[severity] += 1


        summary[
            "total_risk_score"
        ] += finding.get(
            "risk_score",
            0,
        )


        files.add(
            finding["file"]
        )


    summary[
        "files_with_findings"
    ] = len(files)


    if directory:

        summary[
            "files_scanned"
        ] = count_scannable_files(
            directory
        )


    return summary
