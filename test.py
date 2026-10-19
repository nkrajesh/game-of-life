
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

TOKEN = os.environ["GITHUB_TOKEN"]
ORG = os.environ["GITHUB_ORG"]
BASE = "https://api.github.com"
API_VERSION = "2022-11-28"

# Optional: set GITHUB_REPO to test a single repository first.
ONLY_REPO = os.getenv("GITHUB_REPO")

OUT = Path("github_audit_output")
REPORTS = OUT / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
})

COLLECTED_AT = datetime.now(timezone.utc).isoformat()
ROWS = []
ERRORS = []


def api(path, params=None):
    """GET all pages; return JSON objects or raise on API errors."""
    url = path if path.startswith("https://") else BASE + path
    result = []

    while url:
        response = session.get(url, params=params, timeout=45)

        if response.status_code == 403 and response.headers.get(
            "X-RateLimit-Remaining"
        ) == "0":
            reset = int(response.headers.get("X-RateLimit-Reset", "0"))
            time.sleep(max(1, reset - int(time.time()) + 1))
            continue

        response.raise_for_status()
        data = response.json()

        if isinstance(data, list):
            result.extend(data)
        else:
            return data

        # GitHub's Link header provides the next page.
        url = response.links.get("next", {}).get("url")
        params = None

    return result


def safe_api(path, repo, area, params=None):
    try:
        return api(path, params)
    except requests.RequestException as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        ERRORS.append({
            "repository": repo,
            "area": area,
            "endpoint": path,
            "http_status": status,
            "error": str(exc),
        })
        return None


def json_text(value):
    """Stable, CSV-safe representation of nested GitHub API data."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def add_row(repo, area, resource_id, resource_name, resource_type,
            configuration, value, enforcement="", target_type="",
            target_include=None, target_exclude=None, bypass=None,
            result="observed", source="", notes=""):
    ROWS.append({
        "organization": ORG,
        "repository": repo,
        "repository_url": f"https://github.com/{ORG}/{repo}",
        "control_area": area,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "configuration": configuration,
        "configured_value": (
            value if isinstance(value, str) else json_text(value)
        ),
        "enforcement": enforcement,
        "target_type": target_type,
        "target_include": json_text(target_include or []),
        "target_exclude": json_text(target_exclude or []),
        "bypass_actors": json_text(bypass or []),
        "assessment_result": result,
        "evidence_source": source,
        "collected_at": COLLECTED_AT,
        "notes": notes,
    })


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def fetch_rulesets(repo):
    """Repository rulesets."""
    path = f"/repos/{ORG}/{repo}/rulesets"
    rulesets = safe_api(path, repo, "repository_rulesets",
                        {"includes_parents": "true"})

    if rulesets is None:
        return []

    for rs in rulesets:
        rid = rs.get("id", "")
        name = rs.get("name", str(rid))
        detail_path = f"/repos/{ORG}/{repo}/rulesets/{rid}"
        detail = safe_api(detail_path, repo, f"ruleset_{rid}") or rs

        conditions = detail.get("conditions", {})
        target = detail.get("target", "")

        # Retain all conditions and every rule, including unknown types.
        add_row(
            repo, "ruleset", rid, name, "ruleset",
            "metadata", {
                "source_type": detail.get("source_type"),
                "source": detail.get("source"),
                "created_at": detail.get("created_at"),
                "updated_at": detail.get("updated_at"),
            },
            detail.get("enforcement", ""),
            target,
            conditions.get("ref_name", {}).get("include", []),
            conditions.get("ref_name", {}).get("exclude", []),
            detail.get("bypass_actors", []),
            source=detail_path,
            notes="Full ruleset details are also rendered in Markdown.",
        )

        add_row(
            repo, "ruleset", rid, name, "ruleset",
            "conditions", conditions,
            detail.get("enforcement", ""), target,
            conditions.get("ref_name", {}).get("include", []),
            conditions.get("ref_name", {}).get("exclude", []),
            detail.get("bypass_actors", []),
            source=detail_path,
        )

        for index, rule in enumerate(detail.get("rules", []), start=1):
            add_row(
                repo, "ruleset", rid, name, "rule",
                rule.get("type", f"unknown_rule_{index}"),
                rule.get("parameters", {}),
                detail.get("enforcement", ""), target,
                conditions.get("ref_name", {}).get("include", []),
                conditions.get("ref_name", {}).get("exclude", []),
                detail.get("bypass_actors", []),
                source=detail_path,
                notes="Rule parameters stored as JSON.",
            )

    return rulesets


def fetch_legacy_protection(repo, branches):
    """Legacy protection for each branch, where accessible."""
    for branch in branches:
        name = branch["name"]
        path = f"/repos/{ORG}/{repo}/branches/{quote(name, safe='')}/protection"
        data = safe_api(path, repo, f"branch_protection:{name}")

        if data is None:
            # A 404 can mean unprotected, but it can also mean inaccessible.
            # safe_api records the status; distinguish it below.
            last = ERRORS[-1] if ERRORS and ERRORS[-1]["repository"] == repo \
                and ERRORS[-1]["area"] == f"branch_protection:{name}" else {}
            status = last.get("http_status")
            result = "not_configured" if status == 404 else "access_error"
            add_row(
                repo, "branch_protection", name, name, "branch",
                "legacy_protection", None,
                result=result,
                source=path,
                notes=f"API returned HTTP {status}; verify permissions and branch existence.",
            )
            continue

        def record(key, value):
            add_row(
                repo, "branch_protection", name, name, "branch",
                key, value, source=path
            )

        record("required_status_checks", data.get("required_status_checks"))
        record("enforce_admins", data.get("enforce_admins"))
        record("required_pull_request_reviews",
               data.get("required_pull_request_reviews"))
        record("restrictions", data.get("restrictions"))
        record("allow_force_pushes", data.get("allow_force_pushes"))
        record("allow_deletions", data.get("allow_deletions"))
        record("required_linear_history", data.get("required_linear_history"))
        record("required_signatures", data.get("required_signatures"))
        record("lock_branch", data.get("lock_branch"))
        record("allow_fork_syncing", data.get("allow_fork_syncing"))


def fetch_effective_rules(repo, branches):
    """Combined active rules for assessed branches."""
    for branch in branches:
        name = branch["name"]
        path = f"/repos/{ORG}/{repo}/rules/branches/{quote(name, safe='')}"
        data = safe_api(path, repo, f"effective_rules:{name}")

        if data is None:
            continue

        for index, rule in enumerate(data, start=1):
            add_row(
                repo, "effective_branch_rules", name, name, "branch",
                rule.get("type", f"unknown_rule_{index}"),
                rule.get("parameters", {}),
                source=path,
                notes="Effective active branch rules returned by GitHub.",
            )


def fetch_environments(repo):
    path = f"/repos/{ORG}/{repo}/environments"
    data = safe_api(path, repo, "environments", {"per_page": 100})

    if data is None:
        return []

    environments = data.get("environments", [])

    for env in environments:
        name = env.get("name", "")
        eid = env.get("id", "")
        protection = {
            "protection_rules": env.get("protection_rules", []),
            "deployment_branch_policy": env.get("deployment_branch_policy"),
            "can_admins_bypass": env.get("can_admins_bypass"),
        }

        add_row(
            repo, "environment", eid, name, "environment",
            "protection_configuration", protection,
            source=path,
            notes="Environment settings are preserved as JSON.",
        )

        # Deployment branch policies are returned separately.
        policy_path = (
            f"/repos/{ORG}/{repo}/environments/"
            f"{quote(name, safe='')}/deployment-branch-policies"
        )
        policies = safe_api(policy_path, repo, f"environment_policy:{name}")

        if policies is not None:
            add_row(
                repo, "environment", eid, name, "environment",
                "deployment_branch_policies", policies,
                source=policy_path,
            )

    return environments


def md_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_report(repo, metadata, rulesets, branches, environments):
    lines = [
        f"# GitHub Repository Security Configuration: `{repo}`",
        "",
        f"- Organization: `{ORG}`",
        f"- Repository URL: https://github.com/{ORG}/{repo}",
        f"- Visibility: `{metadata.get('visibility', 'unknown')}`",
        f"- Default branch: `{metadata.get('default_branch', 'unknown')}`",
        f"- Archived: `{metadata.get('archived', 'unknown')}`",
        f"- Collected at (UTC): `{COLLECTED_AT}`",
        "",
        "> This report documents observed configuration. It does not by itself "
        "certify compliance or prove that every workflow is secure.",
        "",
        "## 1. Executive summary",
        "",
        f"- Repository rulesets returned: **{len(rulesets)}**",
        f"- Branches assessed: **{len(branches)}**",
        f"- Environments returned: **{len(environments)}**",
        f"- Collection errors recorded: **{sum(1 for e in ERRORS if e['repository'] == repo)}**",
        "",
        "## 2. Rulesets",
        "",
    ]

    if not rulesets:
        lines.append("No repository rulesets were returned, or the API could not retrieve them.")
        lines.append("")

    for rs in rulesets:
        rid = rs.get("id", "")
        name = rs.get("name", str(rid))
        path = f"/repos/{ORG}/{repo}/rulesets/{rid}"
        detail = safe_api(path, repo, f"report_ruleset_{rid}") or rs

        lines += [
            f"### {name}",
            "",
            f"- ID: `{rid}`",
            f"- Enforcement: `{detail.get('enforcement', 'unknown')}`",
            f"- Target: `{detail.get('target', 'unknown')}`",
            f"- Source: `{detail.get('source', 'unknown')}`",
            "- Conditions:",
            "```json",
            json.dumps(detail.get("conditions", {}), indent=2),
            "```",
            "- Bypass actors:",
            "```json",
            json.dumps(detail.get("bypass_actors", []), indent=2),
            "```",
            "- Rules:",
        ]

        for rule in detail.get("rules", []):
            lines.append(
                f"  - **{rule.get('type', 'unknown')}** — "
                f"`{json_text(rule.get('parameters', {}))}`"
            )

        lines.append("")

    lines += ["## 3. Branch protection and effective rules", ""]

    for branch in branches:
        name = branch["name"]
        lines += [f"### `{name}`", ""]

        legacy_path = (
            f"/repos/{ORG}/{repo}/branches/{quote(name, safe='')}/protection"
        )
        legacy = safe_api(legacy_path, repo, f"report_protection:{name}")

        lines.append("**Legacy branch protection**")
        lines.append("")
        if legacy is None:
            lines.append("Protection configuration was not retrieved. Check the collection log.")
        else:
            lines += ["```json", json.dumps(legacy, indent=2), "```"]

        effective_path = (
            f"/repos/{ORG}/{repo}/rules/branches/{quote(name, safe='')}"
        )
        effective = safe_api(effective_path, repo, f"report_effective:{name}")

        lines += ["", "**Effective active rules returned by GitHub**", ""]
        if effective is None:
            lines.append("Effective rules were not retrieved. Check the collection log.")
        else:
            lines += ["```json", json.dumps(effective, indent=2), "```"]

        lines.append("")

    lines += ["## 4. Environments", ""]

    for env in environments:
        name = env.get("name", "")
        lines += [
            f"### `{name}`",
            "",
            "```json",
            json.dumps({
                "protection_rules": env.get("protection_rules", []),
                "deployment_branch_policy": env.get("deployment_branch_policy"),
                "can_admins_bypass": env.get("can_admins_bypass"),
            }, indent=2),
            "```",
            "",
        ]

        policy_path = (
            f"/repos/{ORG}/{repo}/environments/"
            f"{quote(name, safe='')}/deployment-branch-policies"
        )
        policies = safe_api(policy_path, repo, f"report_env_policy:{name}")
        if policies is not None:
            lines += [
                "**Deployment branch policies**",
                "",
                "```json",
                json.dumps(policies, indent=2),
                "```",
                "",
            ]

    lines += [
        "## 5. Collection errors and limitations",
        "",
    ]

    repo_errors = [e for e in ERRORS if e["repository"] == repo]
    if not repo_errors:
        lines.append("No collection errors recorded.")
    else:
        for error in repo_errors:
            lines.append(
                f"- **{error['area']}** — HTTP `{error['http_status']}`; "
                f"endpoint `{error['endpoint']}`; {error['error']}"
            )

    lines += [
        "",
        "## 6. Audit interpretation",
        "",
        "- Active rulesets are distinguished from evaluate-only and disabled rulesets.",
        "- Ruleset conditions and bypass actors are retained for scope review.",
        "- Effective rules are reported separately from legacy branch protection.",
        "- Environment settings are documented separately from source-code branch protection.",
        "- Missing data is not automatically treated as evidence of a missing control.",
        "- Workflow YAML, secrets, and actual deployment behavior are outside this report's scope.",
        "",
    ]

    (REPORTS / f"{safe_name(repo)}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main():
    if ONLY_REPO:
        repos = [safe_api(
            f"/repos/{ORG}/{ONLY_REPO}", ONLY_REPO, "repository_metadata"
        )]
    else:
        repos = api(
            f"/orgs/{ORG}/repos",
            {"per_page": 100, "type": "all", "sort": "full_name"}
        )

    for metadata in repos:
        if not metadata:
            continue

        repo = metadata["name"]
        print(f"Collecting {ORG}/{repo} ...")

        branches = safe_api(
            f"/repos/{ORG}/{repo}/branches",
            repo, "branches", {"per_page": 100}
        ) or []

        rulesets = fetch_rulesets(repo)
        fetch_legacy_protection(repo, branches)
        fetch_effective_rules(repo, branches)
        environments = fetch_environments(repo)

        # Inventory row.
        add_row(
            repo, "repository_inventory", metadata.get("id", ""),
            repo, "repository", "metadata", {
                "visibility": metadata.get("visibility"),
                "default_branch": metadata.get("default_branch"),
                "archived": metadata.get("archived"),
                "fork": metadata.get("fork"),
                "private": metadata.get("private"),
            },
            source=f"/repos/{ORG}/{repo}",
        )

        render_report(repo, metadata, rulesets, branches, environments)

    columns = [
        "organization", "repository", "repository_url", "control_area",
        "resource_id", "resource_name", "resource_type", "configuration",
        "configured_value", "enforcement", "target_type", "target_include",
        "target_exclude", "bypass_actors", "assessment_result",
        "evidence_source", "collected_at", "notes",
    ]

    with (OUT / "github_security_audit.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(ROWS)

    with (OUT / "collection_errors.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        columns = [
            "repository", "area", "endpoint", "http_status", "error"
        ]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(ERRORS)

    print(f"\nDone. Output directory: {OUT.resolve()}")
    print(f"CSV rows: {len(ROWS)}")
    print(f"Collection errors: {len(ERRORS)}")


if __name__ == "__main__":
    main()
