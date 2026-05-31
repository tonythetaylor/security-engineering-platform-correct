# Security Engineering Intelligence Platform

Air-gapped GitLab / OIS / POA&M security engineering workbench.

This repo contains both delivery modes:

- `web/` pure HTML/CSS/JS dashboard that can be opened directly with `index.html`.
- `src-tauri/` optional Tauri desktop wrapper for building native Windows/macOS/Linux apps.

## Browser Mode

Open:

```text
web/index.html
```

No Node, Rust, Python, admin rights, or network access required.

## Tauri Desktop Mode

Use this when you want a standalone desktop application.

```bash
npm install
npm run dev
npm run build
```

Build artifacts will be under:

```text
src-tauri/target/release/bundle/
```

## Canonical Data Shape

The platform expects the uploaded JSON model:

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
      "project_path": "group/project",
      "project_name": "Project Name",
      "namespace": "group",
      "parent_group": "parent/group",
      "in_scope": true,
      "reason_included": "...",
      "reason_excluded": "...",
      "policy_tags": "...",
      "inferred_system_name": "...",
      "program_area": "...",
      "ato_status": "ACTIVE",
      "is_prod": true,
      "tech_stack": "Python/FastAPI",
      "vulnerabilities": []
    }
  }
}
```

## CI/CD

- `.gitlab-ci.yml` packages the web app and includes an optional Windows Tauri build job.
- `.github/workflows/build-tauri.yml` builds desktop artifacts with GitHub Actions.

For locked-down workstations, download the web artifact from CI and open `web/index.html`.
