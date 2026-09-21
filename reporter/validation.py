"""
Schema validation for /ingest.

Before this existed the endpoint trusted whatever JSON arrived. Half of a
22-payload fuzz corpus crashed it with HTTP 500 (a string where a list was
expected, NaN durations, a non-numeric bucket count), and the other half was
stored as-is: unknown severities, 5,000-character names and
`"vulnerabilitiesFound": "no"`, which Python reads as true. Everything is
checked here, and every problem is reported at once so a caller can fix a
payload in one round trip.
"""

import math
from datetime import datetime

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
PROVIDERS = ("aws", "azure", "gcp")

MAX_FINDINGS = 100_000
MAX_NAME_LENGTH = 1024
MAX_RISK_FACTORS = 32
MAX_RISK_FACTOR_LENGTH = 128
MAX_RESOURCES_SCANNED = 10_000_000


class ValidationError(Exception):
    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _pick(obj, *keys):
    """First present key; the auditor sends camelCase, older callers PascalCase."""
    for key in keys:
        if key in obj:
            return obj[key]
    return None


def _timestamp(value):
    text = value.strip().replace("Z", "+00:00")
    # .NET emits 7 fractional digits; Python accepts at most 6.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = len(tail) - len(tail.lstrip("0123456789"))
        text = head + "." + tail[: min(digits, 6)] + tail[digits:]
    datetime.fromisoformat(text)


def _bucket(index, raw, errors):
    where = f"atRiskBuckets[{index}]"
    if not isinstance(raw, dict):
        errors.append(f"{where} must be an object")
        return None

    name = _pick(raw, "bucketName", "BucketName")
    if not isinstance(name, str) or not name.strip():
        errors.append(f"{where}.bucketName must be a non-empty string")
    elif len(name) > MAX_NAME_LENGTH:
        errors.append(f"{where}.bucketName is longer than {MAX_NAME_LENGTH} characters")

    severity = _pick(raw, "severity", "Severity")
    if not isinstance(severity, str) or severity.upper() not in SEVERITIES:
        errors.append(f"{where}.severity must be one of {', '.join(SEVERITIES)}")

    factors = _pick(raw, "riskFactors", "RiskFactors")
    if factors is None:
        factors = []
    if not isinstance(factors, list) or not all(
        isinstance(f, str) and 0 < len(f) <= MAX_RISK_FACTOR_LENGTH for f in factors
    ):
        errors.append(
            f"{where}.riskFactors must be a list of strings of at most"
            f" {MAX_RISK_FACTOR_LENGTH} characters"
        )
    elif len(factors) > MAX_RISK_FACTORS:
        errors.append(f"{where}.riskFactors has more than {MAX_RISK_FACTORS} entries")

    created = _pick(raw, "creationDate", "CreationDate")
    if created is not None and (not isinstance(created, str) or len(created) > 64):
        errors.append(f"{where}.creationDate must be a string")

    bucket = {
        "BucketName": name.strip() if isinstance(name, str) else name,
        "Severity": severity.upper() if isinstance(severity, str) else severity,
        "RiskFactors": list(factors) if isinstance(factors, list) else factors,
    }
    if created:
        bucket["CreationDate"] = created
    return bucket


def validate_audit(data):
    """Return the normalised audit, or raise ValidationError listing every problem."""
    if not isinstance(data, dict):
        raise ValidationError(["body must be a JSON object"])

    errors = []

    raw_buckets = data.get("atRiskBuckets")
    if raw_buckets is None:
        raw_buckets = []
    buckets = []
    if not isinstance(raw_buckets, list):
        errors.append("atRiskBuckets must be a list")
    elif len(raw_buckets) > MAX_FINDINGS:
        errors.append(f"atRiskBuckets has more than {MAX_FINDINGS} entries")
    else:
        buckets = [_bucket(i, b, errors) for i, b in enumerate(raw_buckets)]

    flag = data.get("vulnerabilitiesFound")
    if flag is not None and not isinstance(flag, bool):
        errors.append("vulnerabilitiesFound must be true or false")
    elif (
        flag is not None and isinstance(raw_buckets, list) and flag != bool(raw_buckets)
    ):
        # Alerting keys off this flag, so a mismatch would silently drop an
        # alert (false with findings) or raise an empty one.
        errors.append(
            f"vulnerabilitiesFound is {str(flag).lower()} but atRiskBuckets"
            f" has {len(raw_buckets)} entries"
        )

    total = data.get("totalBucketsScanned")
    if total is None:
        total = len(buckets)
    if not _is_int(total) or not 0 <= total <= MAX_RESOURCES_SCANNED:
        errors.append(
            f"totalBucketsScanned must be an integer from 0 to {MAX_RESOURCES_SCANNED}"
        )
    elif isinstance(raw_buckets, list) and total < len(raw_buckets):
        errors.append("totalBucketsScanned is smaller than the number of findings")

    duration = data.get("scanDurationSeconds")
    if duration is not None and (not _is_number(duration) or duration < 0):
        errors.append("scanDurationSeconds must be a finite, non-negative number")

    timestamp = data.get("auditTimestamp")
    if timestamp is not None:
        try:
            if not isinstance(timestamp, str) or len(timestamp) > 64:
                raise ValueError
            _timestamp(timestamp)
        except ValueError:
            errors.append("auditTimestamp must be an ISO-8601 timestamp")

    provider = data.get("cloudProvider")
    if provider is None:
        provider = "aws"
    if not isinstance(provider, str) or provider.lower() not in PROVIDERS:
        errors.append(f"cloudProvider must be one of {', '.join(PROVIDERS)}")

    if errors:
        raise ValidationError(errors)

    return {
        "cloudProvider": provider.lower(),
        "atRiskBuckets": buckets,
        "vulnerabilitiesFound": bool(buckets),
        "totalBucketsScanned": total,
        "scanDurationSeconds": float(duration) if duration is not None else None,
        "auditTimestamp": timestamp,
    }
