
import csv
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests


# ============================================================
# Configuration
# ============================================================

TOKEN = os.environ["GITHUB_TOKEN"]
ORG = os.environ["GITHUB_ORG"]
ONLY_REPO = os.getenv("GITHUB_REPO")  # Optional pilot repository

BASE_URL = os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")
API_VERSION = "2022-11-28"

OUTPUT = Path("github_audit_output")
REPORTS = OUTPUT / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

COLLECTED_AT = datetime.now(timezone.utc).isoformat()

CSV_COLUMNS = [
    "organization",
    "repository",
    "repository_url",
    "control_area",
    "resource_id",
    "resource_name",
    "resource_type",
    "configuration",
    "configured_value",
    "enforcement",
    "target_type",
    "target_include",
    "target_exclude",
    "bypass_actors",
    "evidence_source",
    "collected_at",
    "notes",
]

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": API_VERSION,
})

CSV_ROWS = []
ERRORS = []
REPO_REPORTS = {}


# ============================================================
# Utilities
# ============================================================

def json_value(value):
    """Serialize structured values without losing nested data."""
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def safe_filename(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def api_url(path):
    if path.startswith("https://") or path.startswith("http://"):
        return path
    return f"{BASE_URL}{path}"


def get_json(url, params=None):
    """GET with rate-limit handling. Returns (JSON, HTTP status)."""
    url = api_url(url)

    while True:
        response = session.get(url, params=params, timeout=45)

        remaining = response.headers.get("X-RateLimit-Remaining")
        if response.status_code == 403 and remaining == "0":
            reset = int(response.headers.get("X-RateLimit-Reset", "0"))
            time.sleep(max(1, reset - int(time.time()) + 1))
            continue

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "10"))
            time.sleep(max(1, retry_after))
            continue

        try:
            body = response.json()
        except ValueError:
            body = {"message": response.text[:1000]}

        return body, response.status_code


def record_error(repo, area, url, status, body):
    ERRORS.append({
        "organization": ORG,
        "repository": repo,
        "area": area,
        "url": url,
        "http_status": status,
        "error": json_value(body),
        "collected_at": COLLECTED_AT,
    })


def get_checked(path, repo, area, params=None, expected_404=False):
    """GET a single resource; log unexpected API errors."""
    body, status = get_json(path, params)

    if 200 <= status < 300:
        return body, status

    if not (status == 404 and expected_404):
        record_error(repo, area, api_url(path), status, body)

    return None, status


def get_collection(path, repo, area, params=None, key=None):
    """
    Follow pagination links.

    Supports endpoints returning either a JSON list or an object such
    as {"environments": [...], "total_count": ...}.
    """
    url = api_url(path)
    first_params = params
    results = []

    while url:
        body, status = get_json(url, params=first_params)
        first_params = None

        if not (200 <= status < 300):
            record_error(repo, area, url, status, body)
            return None

        if isinstance(body, list):
            results.extend(body)
        elif isinstance(body, dict) and key:
            items = body.get(key, [])
            if isinstance(items, list):
                results.extend(items)
            else:
                record_error(
                    repo, area, url, status,
                    {"message": f"Expected list in response key {key}"},
                )
                return None
        else:
            return body

        url = (
            session.get  # Placeholder avoided: use the response Link header
            and None
        )

        # Pagination is handled below by following Link headers on requests.
        # This assignment is replaced by paginated_get() in normal use.
        break

    return results


def paginated_get(path, repo, area, params=None, key=None):
    """Paginate list endpoints and object-wrapped collection endpoints."""
    url = api_url(path)
    next_params = params
    results = []

    while url:
        response = session.get(url, params=next_params, timeout=45)
        next_params = None

        remaining = response.headers.get("X-RateLimit-Remaining")
        if response.status_code == 403 and remaining == "0":
            reset = int(response.headers.get("X-RateLimit-Reset", "0"))
            time.sleep(max(1, reset - int(time.time()) + 1))
            continue

        if response.status_code == 429:
            time.sleep(max(
                1, int(response.headers.get("Retry-After", "10"))
            ))
            continue

        try:
            body = response.json()
        except ValueError:
            body = {"message": response.text[:1000]}

        if not response.ok:
            record_error(
                repo, area, response.url,
                response.status_code, body,
            )
            return None

        if isinstance(body, list):
            results.extend(body)
        elif key and isinstance(body, dict):
            items = body.get(key, [])
            if not isinstance(items, list):
                record_error(
                    repo, area, response.url, response.status_code,
                    {"message": f"Expected list in response key {key}"},
                )
                return None
            results.extend(items)
        else:
            return body

        url = response.links.get("next", {}).get("url")

    return results


def add_row(
    repo,
    area,
    resource_id,
    resource_name,
    resource_type,
    configuration,
    value,
    enforcement="",
    target_type="",
    target_include=None,
    target_exclude=None,
    bypass=None,
    source="",
    notes="",
):
    CSV_ROWS.append({
        "organization": ORG,
        "repository": repo,
        "repository_url": f"https://github.com/{ORG}/{repo}",
        "control_area": area,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "configuration": configuration,
        "configured_value": json_value(value),
        "enforcement": enforcement,
        "target_type": target_type,
        "target_include": json_value(target_include or []),
        "target_exclude": json_value(target_exclude or []),
        "bypass_actors": json_value(bypass or []),
        "evidence_source": source,
        "collected_at": COLLECTED_AT,
        "notes": notes,
    })


def flatten_parameters(value, prefix=""):
    """
    Flatten nested dictionaries into individual configuration rows.
    Lists remain JSON arrays to preserve their relationships.
    """
    flattened = []

    if isinstance(value, dict):
        if not value:
            flattened.append((prefix or "value", {}))
        else:
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                flattened.extend(flatten_parameters(child, name))

    elif isinstance(value, list):
        flattened.append((prefix or "value", value))

    else:
        flattened.append((prefix or "value", value))

    return flattened


def md_json(value):
    return "```json\n" + json.dumps(
        value, indent=2, ensure_ascii=False
    ) + "\n```"


# ============================================================
# Rulesets: list first, then fetch every detail response
# ============================================================

def collect_rulesets(repo):
    path = f"/repos/{ORG}/{repo}/rulesets"

    summaries = paginated_get(
        path,
        repo,
        "repository_rulesets",
        {"per_page": 100, "includes_parents": "true"},
    )

    if summaries is None:
        return []

    details = []

    for summary in summaries:
        rid = summary.get("id")
        if rid is None:
            continue

        detail_path = f"/repos/{ORG}/{repo}/rulesets/{rid}"
        detail, status = get_checked(
            detail_path,
            repo,
            f"ruleset_detail:{rid}",
            {"includes_parents": "true"},
        )

        if detail is None:
            # Preserve the list result when detail retrieval fails.
            detail = dict(summary)
            detail["_detail_fetch_status"] = status

        details.append(detail)

        name = detail.get("name", str(rid))
        enforcement = detail.get("enforcement", "")
        target = detail.get("target", "")
        conditions = detail.get("conditions") or {}
        ref_name = conditions.get("ref_name") or {}
        include = ref_name.get("include", [])
        exclude = ref_name.get("exclude", [])
        bypass = detail.get("bypass_actors", [])

        source = detail_path

        # One metadata row per ruleset.
        add_row(
            repo, "ruleset", rid, name, "ruleset",
            "metadata",
            {
                "source_type": detail.get("source_type"),
                "source": detail.get("source"),
                "created_at": detail.get("created_at"),
                "updated_at": detail.get("updated_at"),
                "detail_fetch_status": detail.get(
                    "_detail_fetch_status", 200
                ),
            },
            enforcement, target, include, exclude, bypass, source,
        )

        # Preserve every condition, not only ref_name.
        for key, value in flatten_parameters(conditions):
            add_row(
                repo, "ruleset", rid, name, "condition",
                key, value, enforcement, target,
                include, exclude, bypass, source,
            )

        # One row per rule and one per nested parameter.
        for index, rule in enumerate(detail.get("rules") or [], 1):
            rule_type = rule.get("type", f"unknown_rule_{index}")
            parameters = rule.get("parameters") or {}

            add_row(
                repo, "ruleset", rid, name, "rule",
                f"{rule_type}.type", rule_type,
                enforcement, target, include, exclude, bypass, source,
            )

            for parameter, value in flatten_parameters(parameters):
                add_row(
                    repo, "ruleset", rid, name, "rule_parameter",
                    f"{rule_type}.{parameter}", value,
                    enforcement, target, include, exclude, bypass, source,
                )

        # Preserve bypass actors as their own explicit configuration row.
        add_row(
            repo, "ruleset", rid, name, "ruleset",
            "bypass_actors", bypass,
            enforcement, target, include, exclude, bypass, source,
        )

    return details


# ============================================================
# Protected branches + legacy protection + effective rules
# ============================================================

def collect_branch_controls(repo):
    path = f"/repos/{ORG}/{repo}/branches"

    branches = paginated_get(
        path,
        repo,
        "protected_branches",
        {"protected": "true", "per_page": 100},
    )

    if branches is None:
        return []

    results = []

    for branch in branches:
        name = branch["name"]
        encoded = quote(name, safe="")
        branch_path = f"{path}/{encoded}"
        protection_url = f"{branch_path}/protection"
        rules_url = f"/repos/{ORG}/{repo}/rules/branches/{encoded}"

        # The branch response itself is evidence of protected=true.
        branch_evidence = {
            "protected": branch.get("protected"),
            "protection": branch.get("protection"),
            "protection_url": branch.get("protection_url"),
            "commit_sha": (branch.get("commit") or {}).get("sha"),
        }

        branch_record = {
            "name": name,
            "branch_evidence": branch_evidence,
            "legacy_protection": None,
            "legacy_status": None,
            "effective_rules": None,
            "effective_status": None,
        }

        add_row(
            repo, "branch_protection", name, name, "branch",
            "branch_inventory", branch_evidence,
            source=path,
            notes="Branch returned by protected=true query.",
        )

        # Legacy protection can return 404 for ruleset-only protection.
        legacy, legacy_status = get_checked(
            protection_url,
            repo,
            f"legacy_branch_protection:{name}",
            expected_404=True,
        )

        branch_record["legacy_protection"] = legacy
        branch_record["legacy_status"] = legacy_status

        if legacy is None:
            add_row(
                repo, "branch_protection", name, name, "branch",
                "legacy_protection_endpoint_status",
                legacy_status,
                source=protection_url,
                notes=(
                    "HTTP 404: no legacy protection details returned; "
                    "branch may be protected by rulesets. Verify permissions "
                    "and API response if unexpected."
                    if legacy_status == 404
                    else "Legacy protection details unavailable."
                ),
            )
        else:
            for key, value in flatten_parameters(legacy):
                add_row(
                    repo, "branch_protection", name, name, "branch",
                    key, value, source=protection_url,
                    notes="Legacy branch protection API configuration.",
                )

        # Active rules applying to the branch, with provenance where supplied.
        effective, effective_status = get_checked(
            rules_url,
            repo,
            f"effective_branch_rules:{name}",
        )

        branch_record["effective_rules"] = effective
        branch_record["effective_status"] = effective_status

        if effective is not None:
            for index, rule in enumerate(effective, 1):
                rule_type = rule.get("type", f"unknown_rule_{index}")
                ruleset_id = rule.get("ruleset_id")
                ruleset_source_type = rule.get("ruleset_source_type")
                ruleset_source = rule.get("ruleset_source")

                provenance = {
                    "ruleset_id": ruleset_id,
                    "ruleset_source_type": ruleset_source_type,
                    "ruleset_source": ruleset_source,
                }

                # Retain complete rule response, including unknown fields.
                add_row(
                    repo, "effective_branch_rules",
                    ruleset_id if ruleset_id is not None else name,
                    name, "effective_rule",
                    f"{rule_type}.full_rule", rule,
                    source=rules_url,
                    notes="Full active rule JSON and provenance.",
                )

                add_row(
                    repo, "effective_branch_rules",
                    ruleset_id if ruleset_id is not None else name,
                    name, "effective_rule",
                    f"{rule_type}.ruleset_provenance", provenance,
                    source=rules_url,
                    notes="Ruleset ID/source returned by GitHub, if present.",
                )

                for parameter, value in flatten_parameters(
                    rule.get("parameters") or {}
                ):
                    add_row(
                        repo, "effective_branch_rules",
                        ruleset_id if ruleset_id is not None else name,
                        name, "effective_rule_parameter",
                        f"{rule_type}.{parameter}", value,
                        source=rules_url,
                    )

        results.append(branch_record)

    return results


# ============================================================
# Environments
# ============================================================

def collect_environments(repo):
    path = f"/repos/{ORG}/{repo}/environments"

    environments = paginated_get(
        path,
        repo,
        "environments",
        {"per_page": 100},
        key="environments",
    )

    if environments is None:
        return []

    results = []

    for env in environments:
        name = env.get("name", "")
        eid = env.get("id", "")
        encoded = quote(name, safe="")

        env_path = f"{path}/{encoded}"
        policy_path = f"{env_path}/deployment-branch-policies"

        # Keep complete environment configuration.
        env_record = {
            "id": eid,
            "name": name,
            "protection_rules": env.get("protection_rules", []),
            "deployment_branch_policy": env.get(
                "deployment_branch_policy"
            ),
            "can_admins_bypass": env.get("can_admins_bypass"),
            "environment_url": env.get("html_url"),
        }

        results.append({
            "environment": env_record,
            "deployment_policies": None,
            "policy_status": None,
        })

        for key, value in flatten_parameters(env_record):
            add_row(
                repo, "environment", eid, name, "environment",
                key, value, source=path,
                notes="Environment configuration returned by GitHub.",
            )

        policies, status = get_checked(
            policy_path,
            repo,
            f"environment_deployment_policies:{name}",
            {"per_page": 100},
        )

        results[-1]["deployment_policies"] = policies
        results[-1]["policy_status"] = status

        if policies is not None:
            for key, value in flatten_parameters(policies):
                add_row(
                    repo, "environment", eid, name, "environment",
                    f"deployment_branch_policies.{key}", value,
                    source=policy_path,
                )
        else:
            add_row(
                repo, "environment", eid, name, "environment",
                "deployment_branch_policies_endpoint_status",
                status,
                source=policy_path,
                notes="Deployment branch policy details not retrieved.",
            )

    return results


# ============================================================
# Markdown report renderer
# ============================================================

def render_report(repo, metadata, rulesets, branches, environments):
    lines = [
        f"# GitHub Repository Security Audit: `{repo}`",
        "",
        f"- Organization: `{ORG}`",
        f"- Repository: https://github.com/{ORG}/{repo}",
        f"- Visibility: `{metadata.get('visibility', 'unknown')}`",
        f"- Default branch: `{metadata.get('default_branch', 'unknown')}`",
        f"- Archived: `{metadata.get('archived', 'unknown')}`",
        f"- Collected at (UTC): `{COLLECTED_AT}`",
        "",
        "> This is a configuration inventory, not a compliance certification.",
        "",
        "## 1. Overview",
        "",
        f"- Rulesets returned: **{len(rulesets)}**",
        f"- Protected branches returned: **{len(branches)}**",
        f"- Environments returned: **{len(environments)}**",
        f"- Collection errors: **{sum(1 for e in ERRORS if e['repository'] == repo)}**",
        "",
        "## 2. Rulesets",
        "",
    ]

    if not rulesets:
        lines += [
            "No rulesets were returned. Check collection errors and permissions.",
            "",
        ]

    for rs in rulesets:
        rid = rs.get("id", "")
        name = rs.get("name", str(rid))
        conditions = rs.get("conditions") or {}
        ref_name = conditions.get("ref_name") or {}
        include = ref_name.get("include", [])
        exclude = ref_name.get("exclude", [])
        enforcement = rs.get("enforcement", "unknown")
        target = rs.get("target", "unknown")
        source_type = rs.get("source_type", "unknown")
        source = rs.get("source", "unknown")

        lines += [
            f"### {name}",
            "",
            f"- **Ruleset ID:** `{rid}`",
            f"- **Source type:** `{source_type}`",
            f"- **Source:** `{source}`",
            f"- **Target:** `{target}`",
            f"- **Enforcement:** `{enforcement}`",
            f"- **Included refs:** `{json_value(include)}`",
            f"- **Excluded refs:** `{json_value(exclude)}`",
            "",
            "**All conditions**",
            "",
            md_json(conditions),
            "",
            "**Bypass actors**",
            "",
            md_json(rs.get("bypass_actors", [])),
            "",
            "**Configured rules**",
            "",
        ]

        rules = rs.get("rules") or []
        if not rules:
            lines += ["No rules were returned in the detail response.", ""]

        for rule in rules:
            rule_type = rule.get("type", "unknown")
            lines += [
                f"- **{rule_type}**",
                "",
                md_json(rule),
                "",
            ]

    lines += [
        "## 3. Protected branches and applied active rules",
        "",
        "Branches listed here were returned by GitHub with `protected=true`.",
        "Effective rules are retrieved separately and include provenance fields",
        "where GitHub returns them.",
        "",
    ]

    if not branches:
        lines += ["No protected branches were returned.", ""]

    for branch in branches:
        name = branch["name"]
        lines += [
            f"### `{name}`",
            "",
            "**Branch protection summary**",
            "",
            md_json(branch["branch_evidence"]),
            "",
            "**Legacy branch protection details**",
            "",
        ]

        if branch["legacy_protection"] is not None:
            lines += [md_json(branch["legacy_protection"]), ""]
        else:
            lines += [
                f"No legacy protection JSON returned (HTTP "
                f"{branch['legacy_status']}). This can occur when protection "
                "comes from rulesets; see the effective active rules below.",
                "",
            ]

        lines += ["**Effective active rules**", ""]

        effective = branch["effective_rules"]
        if effective is None:
            lines += [
                f"Could not retrieve effective rules (HTTP "
                f"{branch['effective_status']}). Check collection errors.",
                "",
            ]
        elif not effective:
            lines += [
                "GitHub returned no active rules for this branch.",
                "",
            ]
        else:
            # Group active rules by source type and ruleset ID.
            grouped = {}
            for rule in effective:
                source_type = rule.get("ruleset_source_type", "Unknown source")
                source = rule.get("ruleset_source", "Unknown source")
                rid = rule.get("ruleset_id", "Unknown ID")
                key = (source_type, source, str(rid))
                grouped.setdefault(key, []).append(rule)

            for (source_type, source, rid), rules in grouped.items():
                lines += [
                    f"**{source_type}: {source} — ruleset ID `{rid}`**",
                    "",
                ]
                for rule in rules:
                    lines += [
                        f"- **{rule.get('type', 'unknown')}**",
                        "",
                        md_json(rule.get("parameters", {})),
                        "",
                    ]

    lines += ["## 4. Environments", ""]

    if not environments:
        lines += ["No environments were returned.", ""]

    for item in environments:
        env = item["environment"]
        name = env.get("name", "unknown")
        lines += [
            f"### `{name}`",
            "",
            "**Environment configuration**",
            "",
            md_json(env),
            "",
            "**Deployment branch policies**",
            "",
        ]

        if item["deployment_policies"] is not None:
            lines += [md_json(item["deployment_policies"]), ""]
        else:
            lines += [
                f"Policy details were not retrieved (HTTP "
                f"{item['policy_status']}).",
                "",
            ]

    lines += [
        "## 5. Collection errors and limitations",
        "",
    ]

    repo_errors = [e for e in ERRORS if e["repository"] == repo]

    if not repo_errors:
        lines += ["No collection errors recorded.", ""]
    else:
        for error in repo_errors:
            lines.append(
                f"- **{error['area']}** — HTTP `{error['http_status']}`; "
                f"`{error['url']}`; `{error['error']}`"
            )
        lines.append("")

    lines += [
        "## 6. Interpretation notes",
        "",
        "- Ruleset configuration documents defined rules and target conditions.",
        "- Effective branch rules document active rules returned for each assessed branch.",
        "- Legacy branch protection is reported independently.",
        "- Evaluate-only and disabled rulesets remain in the ruleset inventory, "
        "but their rules are not expected in effective active branch rules.",
        "- Environment deployment policies are separate from branch protection.",
        "- This report does not assess workflow YAML, secrets, or actual deployment execution.",
        "- Missing configuration data should be investigated; it is not automatically "
        "proof that a security control is absent.",
        "",
    ]

    report_path = REPORTS / f"{safe_filename(repo)}.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")


# ============================================================
# Main
# ============================================================

def main():
    if ONLY_REPO:
        repo_metadata, status = get_checked(
            f"/repos/{ORG}/{ONLY_REPO}",
            ONLY_REPO,
            "repository_metadata",
        )
        repositories = [repo_metadata] if repo_metadata else []
    else:
        repositories = paginated_get(
            f"/orgs/{ORG}/repos",
            ORG,
            "organization_repositories",
            {"per_page": 100, "type": "all", "sort": "full_name"},
        ) or []

    for metadata in repositories:
        if not metadata:
            continue

        repo = metadata["name"]
        print(f"Collecting {ORG}/{repo} ...")

        add_row(
            repo,
            "repository_inventory",
            metadata.get("id", ""),
            repo,
            "repository",
            "metadata",
            {
                "visibility": metadata.get("visibility"),
                "default_branch": metadata.get("default_branch"),
                "archived": metadata.get("archived"),
                "fork": metadata.get("fork"),
                "private": metadata.get("private"),
            },
            source=f"/repos/{ORG}/{repo}",
        )

        # Collection phase: do not make API calls from the report renderer.
        rulesets = collect_rulesets(repo)
        branches = collect_branch_controls(repo)
        environments = collect_environments(repo)

        render_report(
            repo, metadata, rulesets, branches, environments
        )

    # Consolidated CSV across all collected repositories.
    with (OUTPUT / "github_security_audit.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(CSV_ROWS)

    error_columns = [
        "organization",
        "repository",
        "area",
        "url",
        "http_status",
        "error",
        "collected_at",
    ]

    with (OUTPUT / "collection_errors.csv").open(
        "w", newline="", encoding="utf-8-sig"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=error_columns)
        writer.writeheader()
        writer.writerows(ERRORS)

    print("\nCollection complete.")
    print(f"Output directory: {OUTPUT.resolve()}")
    print(f"CSV configuration rows: {len(CSV_ROWS)}")
    print(f"Collection errors: {len(ERRORS)}")
    print(f"Repository reports: {len(repositories)}")


if __name__ == "__main__":
    main()
