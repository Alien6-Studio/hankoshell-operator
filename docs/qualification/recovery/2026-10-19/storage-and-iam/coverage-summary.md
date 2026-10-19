### Go statement coverage

Global: 65.27%; floor: 60.1%.

| Package | Covered / statements | Coverage | Floor |
| --- | ---: | ---: | ---: |
| `api/v1alpha1` | 0 / 2087 | 0.00% | 0% |
| `api/v1beta1` | 71 / 166 | 42.77% | 41.7% |
| `cmd/operator` | 75 / 204 | 36.76% | 32.7% |
| `internal/adoption` | 221 / 258 | 85.66% | 84.6% |
| `internal/applicationbinding` | 315 / 393 | 80.15% | 78.2% |
| `internal/applications` | 285 / 535 | 53.27% | 34.7% |
| `internal/authentik` | 222 / 261 | 85.06% | 80% |
| `internal/authorization` | 584 / 796 | 73.37% | 70.3% |
| `internal/controller` | 8637 / 11276 | 76.60% | 73.4% |
| `internal/decommission` | 131 / 160 | 81.88% | 80.8% |
| `internal/fleetplan` | 350 / 357 | 98.04% | 90% |
| `internal/hankoapi` | 113 / 140 | 80.71% | 79.7% |
| `internal/httpsecurity` | 61 / 62 | 98.39% | 85% |
| `internal/hub` | 309 / 337 | 91.69% | 89.4% |
| `internal/iamconformance` | 80 / 125 | 64.00% | 14.3% |
| `internal/iamcontract` | 42 / 51 | 82.35% | 81.3% |
| `internal/imagevalidator` | 149 / 162 | 91.98% | 90.5% |
| `internal/keycloak` | 3216 / 5475 | 58.74% | 54.9% |
| `internal/observability` | 107 / 119 | 89.92% | 89.5% |
| `internal/organization` | 7 / 7 | 100.00% | 100% |
| `internal/roles` | 135 / 188 | 71.81% | 50.3% |
| `internal/selfupdate` | 41 / 43 | 95.35% | 94.3% |
| `internal/supervision` | 95 / 108 | 87.96% | 86.9% |
| `internal/workloadauth` | 32 / 32 | 100.00% | 92.7% |
| `internal/workloadbinding` | 63 / 231 | 27.27% | 23.2% |
| `internal/workloadtrust` | 174 / 199 | 87.44% | 85% |
| `scripts/api-surface` | 60 / 76 | 78.95% | 77.5% |
| `scripts/delegation-resource-server` | 66 / 90 | 73.33% | 70% |
| `scripts/workload-auth-review` | 0 / 25 | 0.00% | 0% |

| Security function | Coverage | Floor |
| --- | ---: | ---: |
| `internal/authorization/plan.go:Validate` | 100.0% | 100% |
| `internal/fleetplan/verify.go:Verify` | 100.0% | 100% |
| `internal/fleetplan/verify.go:approvedKey` | 100.0% | 100% |
| `internal/fleetplan/verify.go:validatePlan` | 100.0% | 100% |
| `internal/fleetplan/verify.go:validity` | 100.0% | 100% |
| `internal/fleetplan/verify.go:verifyCheckpoint` | 100.0% | 100% |
| `internal/httpsecurity/client.go:RequireHTTPS` | 100.0% | 100% |
| `internal/httpsecurity/client.go:RoundTrip` | 100.0% | 100% |
| `internal/httpsecurity/json.go:ValidateJSON` | 100.0% | 100% |
| `internal/hub/client.go:VerifyBundle` | 100.0% | 100% |
| `internal/imagevalidator/approval.go:VerifyImage` | 100.0% | 100% |
| `internal/imagevalidator/approval.go:VerifyOperatorImage` | 100.0% | 100% |
| `internal/imagevalidator/approval.go:immutableImage` | 100.0% | 100% |
| `internal/imagevalidator/approval.go:verifyCurrentApproval` | 91.7% | 90% |
| `internal/organization/ownership.go:StrictOwnership` | 100.0% | 100% |
| `internal/selfupdate/selfupdate.go:Run` | 96.2% | 95% |
| `internal/workloadauth/contract.go:Decode` | 100.0% | 90% |
| `internal/workloadauth/contract.go:ParseJournal` | 100.0% | 100% |
| `internal/workloadtrust/contract.go:Compile` | 100.0% | 100% |
| `internal/workloadtrust/contract.go:ValidHTTPS` | 100.0% | 100% |
| `internal/workloadtrust/contract.go:Validate` | 100.0% | 100% |

Coverage measures executed statements, not assertion quality or security correctness.

All reviewed coverage floors passed.
