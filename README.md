# Security Engineering Intelligence Platform

Air-gapped browser and Tauri desktop platform for GitLab/OIS security payloads.

## Browser mode
Open:

```text
web/index.html
```

No server, npm, Node, Rust, or admin rights required.

## Data schema
The platform expects the canonical object-map payload:

```json
{
  "generated_at": "...",
  "summary_totals": {
    "total_accessible_projects": 2115,
    "total_scanned_projects": 1439,
    "in_scope_count": 1439,
    "out_of_scope_count": 676,
    "total_vulnerabilities": 159100,
    "statuses": {
      "PRESENT_STILL_EXISTS": 108143,
      "RESOLVED": 46145,
      "DISMISSED_ACCEPTED_RISK": 4812
    }
  },
  "projects": {
    "6307": {
      "project_id": "6307",
      "project_path": "...",
      "parent_group": "...",
      "gitlab_url": "...",
      "pipeline_url": "...",
      "container_registry_url": "...",
      "vulnerabilities": []
    }
  }
}
```

## Desktop/Tauri mode
Requires Node and Rust only on the build machine:

```bash
npm install
npm run build
```

## CI/CD
Use the included GitLab CI or GitHub Actions workflows to generate artifacts.