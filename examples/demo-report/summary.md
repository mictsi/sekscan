# Security scan: failed

Target: `SYNTHETIC DEMO / checkout-service` (dir)  
Completed: 2026-10-02T06:40:41Z  
Coverage complete: true  
Exit code: 1

| Components | Findings | Policy failures | Review required | Accepted |
|---:|---:|---:|---:|---:|
| 10 | 12 | 7 | 2 | 0 |

## Engines

| Engine | Version | Status |
|---|---|---|
| syft | fixture-1.2.3 | completed |
| grype | fixture-1.2.3 | completed |
| trivy | fixture-1.2.3 | completed |
| gitleaks | fixture-1.2.3 | completed |

## Coverage notes

- SYNTHETIC DEMONSTRATION DATA. CVE-2099 identifiers and scanner results are fabricated test fixtures, not verified vulnerabilities or live scanner output.
- Coverage is limited to artifacts visible to the scanners. No project builds or dependency installations were executed.
- License checks apply to application dependencies; results express organizational policy, not legal compatibility.
- A directory scan does not inspect a built container image or provide general source-code SAST. Use image/archive targets and optional SARIF extensions for those checks.

Open `index.html` for the searchable dashboard. Raw secret values are omitted from built-in secret findings.
