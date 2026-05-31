# Security Engineering Intelligence Platform

Air-gapped, browser-runnable Security Engineering platform for GitLab/OIS-style vulnerability reconciliation payloads.

## Run without dev tools

Unzip the package and open:

```text
index.html
```

The app contains realistic synthetic data embedded in `js/default-data.js`, so the dashboard loads even from `file://` without a local web server.

## Load real data

Click **Load JSON** and select your generated dashboard payload. The canonical schema is:

```json
{
  "generated_at": "...",
  "summary_totals": {
    "total_projects_scanned": 0,
    "in_scope_count": 0,
    "total_vulnerabilities": 0,
    "statuses": {
      "PRESENT_STILL_EXISTS": 0,
      "RESOLVED": 0,
      "NOT_APPLICABLE_OUT_OF_SCOPE": 0,
      "DISMISSED_ACCEPTED_RISK": 0
    }
  },
  "projects": {
    "6301": {
      "project_id": "6301",
      "project_path": "...",
      "project_name": "...",
      "namespace": "...",
      "parent_group": "...",
      "in_scope": "TRUE",
      "is_prod": "TRUE",
      "tech_stack": "...",
      "vulnerabilities": []
    }
  }
}
```

## Features

- Canonical payload normalization layer
- Portfolio executive dashboard
- Parent group drilldown
- Project detail pages
- Vulnerability detail pages
- Clickable GitLab/evidence links
- Universal search and filters
- Table pagination and page-size control
- Collapsible sidebar and panels
- Inspector panel
- Theme switching
- POA&M CSV export
- Report generation stubs
- Local browser persistence

## Notes

Pure browser JavaScript cannot silently overwrite files on disk. Use **Export Dataset** or report export buttons to download generated files.
