# Security Engineering Intelligence Platform

A Tauri packaged, air-gapped Security Engineering platform built with pure HTML/CSS/JavaScript.

## What this corrected build fixes

- Removes fake monthly charts when multiple snapshots are not loaded.
- Centers the dashboard around real portfolio/security-engineering metrics.
- Adds project detail pages with vulnerability drilldown.
- Uses parent group, namespace, project, scope, production, severity, and reconciliation status as first-class dimensions.
- Adds pagination to tables.
- Prevents Backspace from navigating away outside editable fields.
- Keeps charts/visual components inside their cards.
- Provides POA&M, AOR, Delta, Reports, and Settings platform modules.

## Run locally during development

```bash
npm install
npm run dev
```

## Build native desktop app

```bash
npm run build
```

macOS app output:

```text
src-tauri/target/release/bundle/macos/
```

Windows build artifacts are easiest through GitHub Actions on a Windows runner.

## Data model

The platform expects JSON shaped like:

```json
{
  "dataset_id": "snapshot_id",
  "snapshot_name": "May 31 Snapshot",
  "generated_at": "2026-05-31T04:34:06Z",
  "summary_totals": {
    "total_projects_scanned": 1846,
    "in_scope_count": 1437,
    "total_vulnerabilities": 46128,
    "statuses": {
      "PRESENT_STILL_EXISTS": 23860,
      "RESOLVED": 17350,
      "NOT_APPLICABLE_OUT_OF_SCOPE": 4888,
      "DISMISSED_ACCEPTED_RISK": 30
    }
  },
  "projects": {
    "6301": {
      "project_id": "6301",
      "project_path": "census/ditd/2030_cmmu_rd/cmmu-auth",
      "project_name": "CMMU Auth",
      "namespace": "census/ditd/2030_cmmu_rd",
      "parent_group": "census/ditd/2030_cmmu_rd",
      "in_scope": true,
      "reason_included": "TARGET_GROUP_LINEAGE_MATCH",
      "reason_excluded": "NONE",
      "is_prod": false,
      "tech_stack": "DETECTED",
      "vulnerabilities": []
    }
  }
}
```
