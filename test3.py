
import os
import csv
import json
import base64
import re
from pathlib import Path
from urllib.parse import quote

import requests
import yaml

API = "https://api.github.com"
TOKEN = os.environ["GITHUB_TOKEN"]
ORG = os.environ["GITHUB_ORG"]
OUTPUT = "github_auditor_report.csv"

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
})

ERRORS = []


def api_get(path, params=None, optional=False):
    """GET a GitHub API endpoint. Return None on errors."""
    url = path if path.startswith("https://") else API + path
    try:
        response = session.get(url, params=params, timeout=30)
        if response.status_code == 404 and optional:
            return None
        if not response.ok:
            message = (
                f"{response.status_code} GET {response.url}: "
                f"{response.text[:180]}"
            )
            ERRORS.append(message)
            return None
        return response.json()
    except requests.RequestException as exc:
        ERRORS.append(f"GET {url}: {exc}")
        return None


def api_pages(path, params=None):
    """Read all pages from a paginated endpoint."""
    result = []
    page = 1
    while True:
        query = dict(params or {})
        query.update({"per_page": 100, "page": page})
        data = api_get(path, query)
        if not isinstance(data, list):
            return result if data is None else result
        result.extend(data)
        if len(data) < 100:
            break
        page += 1
    return result


def yes_no_unknown(value):
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def compact(items):
    """Readable semicolon-separated CSV cell."""
    return "; ".join(str(x) for x in items if x not in (None, ""))


def get_org_rulesets():
    """Fetch organization ruleset definitions once."""
    result = {}
    rulesets = api_pages(f"/orgs/{ORG}/rulesets")
    for item in rulesets:
        detail = api_get(
            f"/orgs/{ORG}/rulesets/{item['id']}"
        )
        result[item["id"]] = detail or item
    return result


def get_repo_rulesets(owner, repo):
    """Fetch repository rulesets and their details."""
    result = []
    items = api_pages(f"/repos/{owner}/{repo}/rulesets")
    for item in items:
        detail = api_get(
            f"/repos/{owner}/{repo}/rulesets/{item['id']}"
        )
        result.append(detail or item)
    return result


def summarize_rulesets(repo_rulesets, org_rulesets):
    all_items = []
    for source, items in (
        ("Repository", repo_rulesets),
        ("Organization", list(org_rulesets.values())),
    ):
        for item in items:
            enforcement = item.get("enforcement", "Unknown")
            rules = item.get("rules") or []
            rule_types = [r.get("type", "unknown") for r in rules]

            all_items.append({
                "source": source,
                "id": item.get("id"),
                "name": item.get("name", "Unknown"),
                "enforcement": enforcement,
                "target": item.get("target", "Unknown"),
                "conditions": item.get("conditions") or {},
                "rules": rule_types,
                "raw_rules": rules,
            })

    active = [
        x for x in all_items
        if x["enforcement"] == "active"
    ]
    evaluate = [
        x for x in all_items
        if x["enforcement"] == "evaluate"
    ]
    disabled = [
        x for x in all_items
        if x["enforcement"] == "disabled"
    ]

    names = [
        f"{x['source']}: {x['name']} [{x['enforcement']}]"
        for x in all_items
    ]

    control_names = sorted({
        rule for item in all_items for rule in item["rules"]
    })

    return {
        "all": all_items,
        "total": len(all_items),
        "active": len(active),
        "evaluate": len(evaluate),
        "disabled": len(disabled),
        "names": compact(names),
        "controls": compact(control_names),
    }


def get_branch_protection(owner, repo, branch):
    branch_q = quote(branch, safe="")
    return api_get(
        f"/repos/{owner}/{repo}/branches/{branch_q}/protection",
        optional=True,
    )


def classic_summary(protection):
    if protection is None:
        return {
            "configured": "No / unavailable",
            "approvals": "Unknown",
            "codeowners": "Unknown",
            "stale_reviews": "Unknown",
            "last_push_approval": "Unknown",
            "status_checks": "Unknown",
            "status_check_count": "Unknown",
            "up_to_date": "Unknown",
            "admin_enforcement": "Unknown",
            "force_push": "Unknown",
            "deletion": "Unknown",
            "linear_history": "Unknown",
            "conversation_resolution": "Unknown",
        }

    reviews = protection.get("required_pull_request_reviews") or {}
    status = protection.get("required_status_checks")
    checks = []

    if isinstance(status, dict):
        checks = [
            x.get("context") for x in status.get("checks", [])
        ]
        checks += status.get("contexts", [])
        checks = sorted(set(x for x in checks if x))

    def enabled_object(key):
        obj = protection.get(key)
        if isinstance(obj, dict):
            return yes_no_unknown(obj.get("enabled"))
        return "Unknown"

    return {
        "configured": "Yes",
        "approvals": reviews.get(
            "required_approving_review_count", 0
        ),
        "codeowners": yes_no_unknown(
            reviews.get("require_code_owner_reviews")
        ),
        "stale_reviews": yes_no_unknown(
            reviews.get("dismiss_stale_reviews")
        ),
        "last_push_approval": yes_no_unknown(
            reviews.get("require_last_push_approval")
        ),
        "status_checks": compact(checks) if status else "None configured",
        "status_check_count": len(checks),
        "up_to_date": (
            yes_no_unknown(status.get("strict"))
            if isinstance(status, dict) else "No"
        ),
        "admin_enforcement": yes_no_unknown(
            (protection.get("enforce_admins") or {}).get("enabled")
        ),
        "force_push": enabled_object("allow_force_pushes"),
        "deletion": enabled_object("allow_deletions"),
        "linear_history": enabled_object("required_linear_history"),
        "conversation_resolution": enabled_object(
            "required_conversation_resolution"
        ),
    }


def ruleset_branch_controls(rulesets, branch_name):
    """Report configured rulesets whose include/exclude patterns
    appear to match the branch. This is a candidate match, not proof
    of effective enforcement.
    """
    matched = []
    for item in rulesets:
        if item["enforcement"] not in ("active", "evaluate"):
            continue

        conditions = item.get("conditions") or {}
        ref_conditions = conditions.get("ref_name") or {}
        include = ref_conditions.get("include") or []
        exclude = ref_conditions.get("exclude") or []

        # GitHub ref patterns commonly use refs/heads/*.
        ref = "refs/heads/" + branch_name
        if not include:
            continue

        def pattern_matches(pattern):
            # GitHub ruleset patterns use fnmatch-style wildcards.
            import fnmatch
            return fnmatch.fnmatchcase(ref, pattern)

        if not any(pattern_matches(p) for p in include):
            continue
        if any(pattern_matches(p) for p in exclude):
            continue

        matched.append(
            f"{item['source']}: {item['name']} "
            f"[{item['enforcement']}]"
        )
    return compact(matched)


def get_environments(owner, repo):
    data = api_get(f"/repos/{owner}/{repo}/environments")
    if not isinstance(data, dict):
        return [], "Unknown"

    output = []
    for env in data.get("environments", []):
        name = env.get("name", "Unknown")
        env_q = quote(name, safe="")
        reviewers = []
        wait_timer = "Unknown"
        other_rules = []

        for rule in env.get("protection_rules") or []:
            rule_type = rule.get("type")
            if rule_type == "required_reviewers":
                for reviewer in rule.get("reviewers") or []:
                    reviewer_name = reviewer.get("name") or reviewer.get("id")
                    reviewer_type = reviewer.get("type", "reviewer")
                    reviewers.append(f"{reviewer_type}:{reviewer_name}")
            elif rule_type == "wait_timer":
                wait_timer = rule.get("wait_timer", "Unknown")
            elif rule_type:
                other_rules.append(rule_type)

        policy = env.get("deployment_branch_policy") or {}
        protected_branches = policy.get("protected_branches")
        custom_policies = policy.get("custom_branch_policies")

        policy_summary = "Unknown"
        if protected_branches is True:
            policy_summary = "Protected branches only"
        elif custom_policies is True:
            policy_summary = "Custom branch policy"
            custom = api_get(
                f"/repos/{owner}/{repo}/environments/"
                f"{env_q}/deployment-branch-policies"
            )
            if isinstance(custom, dict):
                patterns = [
                    x.get("name", "")
                    for x in custom.get("branch_policies", [])
                ]
                if patterns:
                    policy_summary += ": " + compact(patterns)
        elif protected_branches is False and custom_policies is False:
            policy_summary = "No branch restriction"

        secrets = api_get(
            f"/repos/{owner}/{repo}/environments/{env_q}/secrets"
        )
        secret_presence = (
            yes_no_unknown(bool(secrets.get("secrets")))
            if isinstance(secrets, dict) else "Unknown"
        )
        secret_count = (
            len(secrets["secrets"])
            if isinstance(secrets, dict) else "Unknown"
        )

        output.append({
            "name": name,
            "reviewers": compact(reviewers) if reviewers else "None configured",
            "reviewer_count": len(reviewers),
            "wait_timer": wait_timer,
            "deployment_policy": policy_summary,
            "other_rules": compact(other_rules),
            "secrets_present": secret_presence,
            "secret_count": secret_count,
        })

    return output, len(output)


def check_codeowners(owner, repo, default_branch):
    paths = [
        "CODEOWNERS",
        ".github/CODEOWNERS",
        "docs/CODEOWNERS",
    ]
    for path in paths:
        data = api_get(
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": default_branch},
            optional=True,
        )
        if isinstance(data, dict) and data.get("type") == "file":
            return "Yes", path
    return "No / unavailable", ""


def get_workflows(owner, repo, default_branch):
    """Read workflow YAML from the default branch and infer likely
    deployment-related trigger/job/environment information.
    """
    listing = api_get(f"/repos/{owner}/{repo}/contents/.github/workflows",
                      params={"ref": default_branch},
                      optional=True)
    if not isinstance(listing, list):
        return {
            "workflow_files": "Unknown",
            "workflow_triggers": "Unknown",
            "deployment_branch_filters": "Unknown",
            "workflow_environments": "Unknown",
            "deployment_workflows": "Unknown",
            "deployment_evidence": "Unable to inspect workflows",
        }

    triggers, branch_filters, environments = set(), set(), set()
    deployment_workflows = set()
    errors = []

    for file in listing:
        if file.get("type") != "file" or not file.get("name", "").endswith(
            (".yml", ".yaml")
        ):
            continue

        content = api_get(
            f"/repos/{owner}/{repo}/contents/{file['path']}",
            params={"ref": default_branch},
        )
        if not isinstance(content, dict) or not content.get("content"):
            errors.append(file.get("name", "unknown"))
            continue

        try:
            raw = base64.b64decode(content["content"]).decode("utf-8")
            doc = yaml.load(raw, Loader=yaml.BaseLoader) or {}
        except Exception:
            errors.append(file.get("name", "unknown"))
            continue

        on = doc.get("on", {})
        if isinstance(on, dict):
            for event, cfg in on.items():
                triggers.add(event)
                if isinstance(cfg, dict):
                    for branch in cfg.get("branches", []) or []:
                        branch_filters.add(f"{event}: {branch}")
                    for tag in cfg.get("tags", []) or []:
                        branch_filters.add(f"{event} tag: {tag}")
        elif isinstance(on, list):
            triggers.update(on)
        elif isinstance(on, str):
            triggers.add(on)

        jobs = doc.get("jobs") or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            env = job.get("environment")
            env_name = env.get("name") if isinstance(env, dict) else env
            if env_name:
                environments.add(str(env_name))

            steps_text = " ".join(
                str(step.get("run", "")) + " " + str(step.get("uses", ""))
                for step in (job.get("steps") or [])
                if isinstance(step, dict)
            )
            text = (job_name + " " + steps_text).lower()
            looks_deploy_related = any(
                word in text
                for word in (
                    "deploy", "deployment", "release",
                    "publish", "upload-artifact",
                    "aws-actions/configure-aws-credentials",
                    "kubectl", "terraform apply",
                )
            )
            if looks_deploy_related:
                deployment_workflows.add(
                    f"{file['name']}:{job_name}"
                )

    evidence = (
        "Inferred from workflow YAML; verify deployment scripts and targets"
        if deployment_workflows
        else "No obvious deployment job detected; manual verification needed"
    )
    if errors:
        evidence += "; workflow files unreadable: " + compact(errors)

    return {
        "workflow_files": len([
            f for f in listing
            if f.get("type") == "file"
            and f.get("name", "").endswith((".yml", ".yaml"))
        ]),
        "workflow_triggers": compact(sorted(triggers)),
        "deployment_branch_filters": compact(sorted(branch_filters)),
        "workflow_environments": compact(sorted(environments)),
        "deployment_workflows": compact(sorted(deployment_workflows)),
        "deployment_evidence": evidence,
    }


def audit_repository(repo, org_rulesets):
    owner, name = repo["owner"]["login"], repo["name"]
    repo_path = f"/repos/{owner}/{name}"
    default_branch = repo.get("default_branch", "")

    repo_rulesets = get_repo_rulesets(owner, name)
    rules = summarize_rulesets(repo_rulesets, org_rulesets)

    branches = api_pages(
        f"{repo_path}/branches",
        params={"protected": "true"},
    )
    branch_names = [b.get("name", "") for b in branches]
    classic_details = []
    branch_reviewers = []
    branch_rule_matches = []

    for branch in branch_names:
        protection = get_branch_protection(owner, name, branch)
        summary = classic_summary(protection)
        classic_details.append(
            f"{branch}: approvals={summary['approvals']}, "
            f"CODEOWNERS-review={summary['codeowners']}, "
            f"status-checks={summary['status_check_count']}"
        )
        branch_reviewers.append(str(summary["approvals"]))
        branch_rule_matches.append(
            f"{branch}: "
            f"{ruleset_branch_controls(rules['all'], branch) or 'No pattern match identified'}"
        )

    # Repository Actions secrets: metadata only; values are never fetched.
    repo_secrets = api_get(f"{repo_path}/actions/secrets")
    if isinstance(repo_secrets, dict):
        repo_secret_count = len(repo_secrets.get("secrets", []))
        repo_secrets_present = yes_no_unknown(repo_secret_count > 0)
    else:
        repo_secret_count = "Unknown"
        repo_secrets_present = "Unknown"

    envs, env_count = get_environments(owner, name)
    codeowners_present, codeowners_path = check_codeowners(
        owner, name, default_branch
    )
    workflows = get_workflows(owner, name, default_branch)

    env_secret_values = [e["secrets_present"] for e in envs]
    if not env_secret_values:
        env_secrets_present = "No environments"
    elif "Yes" in env_secret_values:
        env_secrets_present = "Yes"
    elif all(x == "No" for x in env_secret_values):
        env_secrets_present = "No"
    else:
        env_secrets_present = "Unknown"

    # Check legacy CODEOWNERS-review requirement per protected branch.
    codeowner_review_values = []
    for branch in branch_names:
        p = get_branch_protection(owner, name, branch)
        if p is not None:
            r = p.get("required_pull_request_reviews") or {}
            codeowner_review_values.append(
                yes_no_unknown(r.get("require_code_owner_reviews"))
            )
    codeowner_review = (
        "Yes" if "Yes" in codeowner_review_values
        else "No" if codeowner_review_values
        and all(x == "No" for x in codeowner_review_values)
        else "Mixed / Unknown"
    )

    repo_errors = compact(ERRORS)
    ERRORS.clear()

    return {
        "organization": owner,
        "repository": name,
        "visibility": repo.get("visibility", "Unknown"),
        "default_branch": default_branch,
        "archived": repo.get("archived", False),

        "protected_branch_count": len(branch_names),
        "protected_branches": compact(branch_names),
        "classic_protection_summary": compact(classic_details),
        "classic_required_approvals": compact(
            f"{branch}={get_branch_protection(owner, name, branch).get('required_pull_request_reviews', {}).get('required_approving_review_count', 'Unknown')}"
            if get_branch_protection(owner, name, branch) else f"{branch}=Unknown"
            for branch in branch_names
        ),
        "codeowners_file_present": codeowners_present,
        "codeowners_file_path": codeowners_path,
        "codeowner_review_required_classic": codeowner_review,

        "rulesets_total": rules["total"],
        "rulesets_active": rules["active"],
        "rulesets_evaluate": rules["evaluate"],
        "rulesets_disabled": rules["disabled"],
        "ruleset_names_and_status": rules["names"],
        "ruleset_control_types": rules["controls"],
        "rulesets_matching_protected_branches": compact(branch_rule_matches),

        "environment_count": env_count,
        "environment_names": compact(e["name"] for e in envs),
        "environment_required_reviewers": compact(
            f"{e['name']}={e['reviewers']}" for e in envs
        ),
        "environment_wait_timers_minutes": compact(
            f"{e['name']}={e['wait_timer']}" for e in envs
        ),
        "environment_deployment_policies": compact(
            f"{e['name']}={e['deployment_policy']}" for e in envs
        ),
        "environment_secrets_present": env_secrets_present,
        "environment_secret_counts": compact(
            f"{e['name']}={e['secret_count']}" for e in envs
        ),

        "repository_actions_secrets_present": repo_secrets_present,
        "repository_actions_secret_count": repo_secret_count,

        **workflows,
        "collection_errors": repo_errors,
    }


def main():
    repos = api_pages(
        f"/orgs/{ORG}/repos",
        params={"type": "all", "sort": "full_name"},
    )
    if not repos:
        raise SystemExit(
            "No repositories retrieved. Check organization name, token "
            "permissions and API errors."
        )

    org_rulesets = get_org_rulesets()
    rows = []

    for index, repo in enumerate(repos, start=1):
        print(f"[{index}/{len(repos)}] Auditing {repo['full_name']}")
        try:
            rows.append(audit_repository(repo, org_rulesets))
        except Exception as exc:
            rows.append({
                "organization": ORG,
                "repository": repo.get("name", "Unknown"),
                "collection_errors": str(exc),
            })

    # CSV fields are consistent even when a repository has an error.
    fields = list(dict.fromkeys(
        key for row in rows for key in row.keys()
    ))
    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nCreated {OUTPUT} with {len(rows)} repositories.")


if __name__ == "__main__":
    main()
