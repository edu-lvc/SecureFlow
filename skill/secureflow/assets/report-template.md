# SecureFlow Security Report

- Report schema: `secureflow.gate.report/v1`
- Revision:
- Scan root:
- Profile:
- Generated:

## Summary

| Status | Count |
| --- | --- |
| PASS |  |
| FAIL |  |
| UNVERIFIED |  |
| NOT_APPLICABLE |  |

Overall: `UNVERIFIED`

## Controls

| Control | Status | Reason |
| --- | --- | --- |
| Input validation |  |  |
| Authentication |  |  |
| Authorization |  |  |
| Secrets management |  |  |
| Injection prevention |  |  |

## Findings

| Rule | Control | Severity | Location | Evidence |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## Unverified items

| Control | Reason | Required action |
| --- | --- | --- |
|  |  |  |

## Suppressed findings

| Rule | Location | Reason | Owner | Expiry |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## Claims audit

| Control | Claimed | Gate | Verdict |
| --- | --- | --- | --- |
|  |  |  |  |

## Adapters

- Build:
- Tests:
- Other:

## Manual review and residual risk

- Object-level authorization:
- Authentication flows:
- Business logic:
- Secrets lifecycle:
- Supply chain:
- Out-of-scope components:

## Limitations

- Static analysis does not prove exploitability.
- The gate does not execute application code (unless the build adapter is explicitly enabled).
- Object-level authorization and business logic require manual review and tests.
- The scan covers only the provided root and active profile.

## Conclusion

This report establishes the status of the five baseline controls for the scanned revision, with
the evidence above. It does not establish that the application is secure.
