# Dependency Health Report Event Contract

This document defines the ingest event emitted automatically by the SDK for dependency health.

## Event Overview

- Event type: `dependency_health_report`
- Emitted by: `SecployClient` on startup (automatic)
- Transport: standard SDK ingest pipeline (`send_event` batched to ingest endpoint)
- Frequency: once per process start (default behavior)

## Event Envelope

The SDK emits the event in the standard envelope used by ingest batching:

```json
{
  "type": "dependency_health_report",
  "payload": {
    "name": "dependency_health_report",
    "message": "Dependency health report generated",
    "summary": {
      "total_dependencies": 42,
      "outdated_dependencies": 5,
      "dependencies_with_current_issues": 2,
      "dependencies_with_latest_issues": 1
    },
    "dependencies": [
      {
        "name": "requests",
        "current_version": "2.31.0",
        "latest_version": "2.32.3",
        "is_outdated": true,
        "latest_check_error": null,
        "has_current_issues": true,
        "current_issue_count": 1,
        "has_latest_issues": false,
        "latest_issue_count": 0,
        "recent_incidents": [
          {
            "id": "OSV-REQ-1",
            "summary": "Example issue summary",
            "details": "Example issue details",
            "published": "2026-01-12T10:00:00Z",
            "modified": "2026-01-14T10:00:00Z",
            "aliases": ["CVE-2026-12345"],
            "severity": [],
            "references": []
          }
        ]
      }
    ],
    "context": {
      "type": "dependency_health_report",
      "source": "secploy-python-sdk"
    }
  },
  "timestamp": 1712000000.0
}
```

## Field Definitions

### summary

- `total_dependencies` (number): count of scanned installed dependencies
- `outdated_dependencies` (number): dependencies where `current_version < latest_version`
- `dependencies_with_current_issues` (number): dependencies with known issues at installed version
- `dependencies_with_latest_issues` (number): dependencies where latest version still has known issues

### dependencies[]

- `name` (string): package name
- `current_version` (string): installed version
- `latest_version` (string or null): latest PyPI version if resolved
- `is_outdated` (boolean)
- `latest_check_error` (string or null): latest-version lookup error when applicable
- `has_current_issues` (boolean)
- `current_issue_count` (number)
- `has_latest_issues` (boolean)
- `latest_issue_count` (number)
- `recent_incidents` (array): normalized issue records (OSV-backed)

### recent_incidents[]

- `id` (string)
- `summary` (string)
- `details` (string)
- `published` (string datetime)
- `modified` (string datetime)
- `aliases` (string[])
- `severity` (object[])
- `references` (object[])

## Frontend Rendering Guidance

Recommended UI blocks:

1. Summary cards: total dependencies, outdated dependencies, dependencies with current issues, dependencies with latest issues.

1. Dependency table: columns should include name, current version, latest version, outdated status, current issues, latest issues. Suggested default sort is current issues desc, then outdated desc, then name asc.

1. Incidents drawer/panel: on dependency row click, display `recent_incidents` including issue id, summary, modified/published date, and aliases.

1. Empty and error states: if `dependencies` is empty, show "No dependencies detected". If `latest_check_error` exists for a row, show a non-blocking warning badge.

## Compatibility Notes

- Treat unknown fields as forward-compatible additions.
- UI should not fail if `recent_incidents` is empty.
- `latest_version` may be null for packages not resolvable on PyPI.
