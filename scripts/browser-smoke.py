#!/usr/bin/env python3
"""Optional Playwright tests of the portable report's actual embedded UI.

Install Playwright/browser separately. Example:
  python scripts/browser-smoke.py --chromium /usr/bin/chromium
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from playwright.sync_api import sync_playwright


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=Path(__file__).resolve().parents[1] / "examples/demo-report/index.html")
    parser.add_argument("--chromium", default=None)
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    checks: list[str] = []
    errors: list[str] = []
    requests: list[str] = []
    original = json.loads(args.report.with_name("results.json").read_text())
    with sync_playwright() as playwright:
        options = {"headless": True}
        if args.chromium:
            options["executable_path"] = args.chromium
        browser = playwright.chromium.launch(**options)
        try:
            context = browser.new_context(viewport={"width": 1440, "height": 1100}, accept_downloads=True)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url))
            # Direct HTML loading also works where managed browsers restrict file://.
            page.set_content(args.report.read_text(), wait_until="load")
            rows = page.locator("#table-body tr")
            assert rows.count() == len(original["findings"])
            assert page.locator('#overview-panels').is_visible()
            assert not page.locator('#data-section').is_visible()
            page.get_by_role('tab',name='Findings',exact=False).click()
            checks.append("embedded dashboard and findings use separate accessible tabs without requests")
            page.locator("#search").fill("lodash")
            assert rows.count() == 1
            checks.append("search filters findings")
            page.locator("#reset-filters").click()
            page.locator("#severity").select_option("critical")
            assert rows.count() == 2
            checks.append("severity filter")
            page.locator("#reset-filters").click()
            page.locator("#category").select_option("license")
            assert rows.count() == 3
            checks.append("category filter")
            page.locator("#reset-filters").click()
            page.locator("#engine").select_option("gitleaks")
            assert rows.count() == 1
            checks.append("engine filter")
            page.locator("[data-view=licenses]").click()
            assert rows.count() == 9
            page.locator("#scope").select_option("operating-system")
            assert rows.count() == 1 and "busybox" in rows.inner_text()
            checks.append("application-only license view with explicit OS inventory access")
            page.locator("[data-view=components]").click()
            assert rows.count() == 10
            page.get_by_role("button", name="internal-widget", exact=True).click()
            assert page.locator("#detail").is_visible()
            assert "MIT" in page.locator("#detail-body").inner_text()
            assert "GPL-3.0-only" in page.locator("#detail-body").inner_text()
            page.locator("#close-detail").click()
            checks.append("component evidence dialog")
            page.locator("[data-view=health]").click()
            assert page.locator(".health-card").count() == 4
            assert "SYNTHETIC" in page.locator("#warnings").inner_text()
            checks.append("scan-health diagnostics")
            page.locator("[data-view=findings]").click()
            # Capture exported Blob bytes without requiring OS download permission.
            page.evaluate("""() => {
              window.exports = [];
              const old = URL.createObjectURL.bind(URL);
              URL.createObjectURL = blob => {window.exports.push(blob); return old(blob);};
              document.addEventListener('click', event => {
                if (event.target.tagName === 'A' && event.target.download) event.preventDefault();
              }, true);
            }""")
            assert page.locator("#engine").input_value() == "gitleaks"
            checks.append("per-tab filters are restored")
            page.locator("#reset-filters").click()
            page.locator("#search").fill("lodash")
            page.locator("#export-csv").click()
            csv = page.evaluate("async () => await window.exports.at(-1).text()")
            assert "lodash" in csv and len(csv.splitlines()) == 2
            checks.append("filtered CSV content")
            page.locator("#download-json").click()
            exported = page.evaluate("async () => await window.exports.at(-1).text()")
            assert json.loads(exported)["id"] == original["id"]
            checks.append("JSON export content")

            def load(data: dict) -> None:
                page.locator("#report-file").set_input_files({"name": "report.json", "mimeType": "application/json", "buffer": json.dumps(data).encode()})
                page.wait_for_timeout(100)

            modified = copy.deepcopy(original)
            modified["findings"][0]["title"] = '<img src=x onerror="window.xss=true"><script>window.xss=true</script>'
            modified["status"] = "incomplete"
            modified["complete"] = False
            modified["exit_code"] = 2
            load(modified)
            page.locator("[data-view=overview]").click()
            assert "INCOMPLETE" in page.locator("#coverage-banner").inner_text()
            assert not page.evaluate("() => Boolean(window.xss)")
            checks.append("JSON import, incomplete banner and untrusted text safety")
            modified["findings"] = [copy.deepcopy(original["findings"][0]) for _ in range(61)]
            load(modified)
            page.locator("[data-view=findings]").click()
            assert rows.count() == 25
            assert page.locator("#page-number").inner_text() == "1 / 3"
            page.locator("#next").click()
            assert page.locator("#page-number").inner_text() == "2 / 3"
            checks.append("pagination")
            load(original)
            page.locator("[data-view=overview]").click()
            if args.screenshot:
                page.evaluate("window.scrollTo(0, 0)")
                page.screenshot(path=str(args.screenshot), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.locator("[data-view=findings]").click()
            assert page.locator("#search").is_visible()
            assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")
            checks.append("mobile layout fits viewport")
            assert not errors, errors
            assert not requests, requests
            checks.append("no uncaught JavaScript errors or network requests")
        finally:
            browser.close()
    print(json.dumps({"passed": len(checks), "checks": checks, "mode": "embedded HTML via Playwright set_content; export content captured before OS download"}, indent=2))


if __name__ == "__main__":
    main()
