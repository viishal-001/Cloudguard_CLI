# Architecture

## System Design

Per PRD §7 and MVP §11:

```
┌─────────────────────────────────────────────┐
│                  USER CLI                    │
│           (cloudguard scan --all)            │
├─────────────────────────────────────────────┤
│              CLI Interface                   │
│         (Click + Rich terminal)              │
├─────────────────────────────────────────────┤
│            CloudGuard Engine                 │
│     (ScanEngine.run() orchestrator)          │
├─────────────────────────────────────────────┤
│         Service Scanner Layer                │
│   ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐          │
│   │IAM│ │S3 │ │EC2│ │RDS│ │...│  x20      │
│   └───┘ └───┘ └───┘ └───┘ └───┘          │
├─────────────────────────────────────────────┤
│            Rule Engine                       │
│     (YAML rules per service)                 │
├─────────────────────────────────────────────┤
│          CVSS v3.1 Scoring                   │
│  (Deterministic base score calculator)       │
├─────────────────────────────────────────────┤
│         Report Generator                     │
│   ┌──────┐ ┌───────┐ ┌───────┐             │
│   │ JSON │ │ Table │ │ SARIF │             │
│   └──────┘ └───────┘ └───────┘             │
└─────────────────────────────────────────────┘
```

## Scan Flow Sequence

```
User ──> CLI (Click)
         │
         ├──> ScanEngine.run()
         │    ├──> Create Boto3 Session
         │    ├──> Get Account ID (STS)
         │    │
         │    ├──> For each service:
         │    │    ├──> Scanner.scan()
         │    │    │    ├──> Load YAML rules
         │    │    │    ├──> Call AWS APIs (Boto3)
         │    │    │    ├──> Evaluate rules against resources
         │    │    │    ├──> Calculate CVSS score
         │    │    │    └──> Return Finding[]
         │    │    └──> Collect findings
         │    │
         │    └──> Return ScanResult
         │
         └──> Reporter.generate(ScanResult)
              └──> Output (terminal / JSON / SARIF)
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| YAML rules | Easy to extend, review, and map to CIS. Per PRD §5. |
| Self-registering scanners | `@register_scanner` decorator enables plug-and-play. |
| Internal CVSS calculator | No heavy external dependency; deterministic scores. |
| BaseScanner ABC | Ensures consistent interface across all 20 scanners. |
| Click + Rich | Per MVP §5 tech stack. Production CLI UX. |
| moto for tests | Per MVP §5. Full AWS mocking without real credentials. |
