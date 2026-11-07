#!/usr/bin/env python3
"""
Fetch all public ("open") repositories of a GitHub organization and write them
to a projects JSON file.

Output format:

    {
      "version": 1,
      "continue_on_error": true,
      "projects": [
        { "project": "repo", "repo_url": "https://github.com/ORG/repo" },
        ...
      ]
    }

Usage:
    python github_org_to_projects.py                  # SAMPLE_ORG -> projects.json
    python github_org_to_projects.py --org SAMPLE_ORG --output SAMPLE_ORG.json
    python github_org_to_projects.py --style path     # local checkouts only, no repo_url
    python github_org_to_projects.py --exclude-forks --include-archived

No login needed (60 requests/hour limit). To raise the limit, set GITHUB_TOKEN.
Uses only the Python standard library.

GitHub scans use repo_url, never path. The optional path style is only for
repositories already checked out beside the manifest directory (../repo).
Validate the generated file with: ./sekscan batch validate projects.json
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"


def fetch_repos(org, token=None):
    """Return all public repos of an organization, following pagination."""
    url = f"{API}/orgs/{org}/repos?type=public&per_page=100"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "org-to-projects-script",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    repos = []
    while url:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                repos.extend(json.load(resp))
                link = resp.headers.get("Link", "")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                sys.exit(f"Organization '{org}' not found.")
            if e.code in (403, 429):
                reset = e.headers.get("x-ratelimit-reset", "unknown")
                sys.exit(
                    "GitHub rate limit hit (unix reset time: "
                    f"{reset}). Set GITHUB_TOKEN to raise the limit."
                )
            sys.exit(f"GitHub API error: HTTP {e.code} {e.reason}")
        except urllib.error.URLError as e:
            sys.exit(f"Network error: {e.reason}")

        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = match.group(1) if match else None

    return repos


def to_project(repo, style="url"):
    """Select exactly one source kind, as required by sekscan batch schema v1."""
    if style == "path":
        return {"project": repo["name"], "path": f"../{repo['name']}"}
    if style == "url":
        return {"project": repo["name"], "repo_url": repo["html_url"]}
    raise ValueError(f"Unknown project style: {style}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--org", default="SAMPLE_ORG", help="GitHub organization (default: SAMPLE_ORG)")
    parser.add_argument("--output", "-o", default="projects.json", help="Output file (default: projects.json)")
    parser.add_argument(
        "--style",
        choices=["url", "path"],
        default="url",
        help='"url": GitHub scans using project + repo_url (default); '
             '"path": existing local checkouts using project + path, without repo_url',
    )
    parser.add_argument("--include-archived", action="store_true", help="Include archived repos")
    parser.add_argument("--exclude-forks", action="store_true", help="Skip forked repos")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    repos = fetch_repos(args.org, token)

    if not args.include_archived:
        repos = [r for r in repos if not r.get("archived")]
    if args.exclude_forks:
        repos = [r for r in repos if not r.get("fork")]

    repos.sort(key=lambda r: r["name"].lower())

    # Refuse invalid manifests without replacing an existing output file.
    if not 1 <= len(repos) <= 1000:
        parser.error(
            f"sekscan requires 1..1000 projects; {len(repos)} repositories remain "
            "after filtering. Output file was not changed."
        )
    names = [r["name"].lower() for r in repos]
    if len(set(names)) != len(names):
        parser.error("Duplicate repository names returned; output file was not changed.")

    data = {
        "version": 1,
        "continue_on_error": True,
        "projects": [to_project(r, args.style) for r in repos],
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {len(repos)} projects from '{args.org}' to {args.output}")


if __name__ == "__main__":
    main()
