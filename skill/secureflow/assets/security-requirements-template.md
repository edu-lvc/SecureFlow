# Security Requirements

- System:
- Revision:
- Owner:
- Date:

## Requirements

| ID | Control | Requirement | Verification method | Evidence | Status |
| --- | --- | --- | --- | --- | --- |
| REQ-INVAL-001 | Input validation | Server rejects invalid or out-of-range input. | Integration test + gate |  | UNVERIFIED |
| REQ-AUTHN-001 | Authentication | Authentication middleware is registered and invoked before endpoints. | Static + runtime test |  | UNVERIFIED |
| REQ-AUTHZ-001 | Authorization | Every mutating endpoint requires an authenticated principal or a documented public decision. | Static + negative test |  | UNVERIFIED |
| REQ-AUTHZ-002 | Authorization | Object reads and writes enforce owner, tenant, or policy. | Negative test + manual review |  | UNVERIFIED |
| REQ-SEC-001 | Secrets | No credential value is stored in source, configuration, fixtures, or artifacts. | Gate + history scan |  | UNVERIFIED |
| REQ-INJ-001 | Injection | Database access uses parameterization or ORM composition. | Gate + test |  | UNVERIFIED |
| REQ-INJ-002 | Injection | OS processes use a fixed executable and argument vector. | Gate + review |  | UNVERIFIED |

## Accepted exceptions

| Rule or requirement | Scope | Reason | Owner | Expiry |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## Verification notes

- Gate command:
- Test command:
- Report path:
- Residual risk:
