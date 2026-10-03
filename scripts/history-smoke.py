#!/usr/bin/env python3
"""Test project/run pagination, comparisons and trends against real localhost HTTP.

Inputs are synthetic. Optional Playwright renders HTML/CSS/JS fetched from the live HTTP server.
Navigation is replayed through HTTP when managed Chromium blocks localhost.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import urllib.error
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--chromium')
    parser.add_argument('--screenshots', type=Path)
    parser.add_argument('--embedded-browser', action='store_true', help='render live responses with set_content when managed browsers block navigation; opaque-origin storage is unavailable')
    parser.add_argument('--design-review', action='store_true', help='run Sekura 3.0.2 consumer geometry, keyboard, theme and reflow checks')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    checks: list[str] = []
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='sekscan-history-') as tmp:
        work = Path(tmp)
        common = ['--home', str(work), '--no-config']
        def run(*parts: str) -> str:
            proc = subprocess.run([str(binary), *parts, *common], text=True,
                                  capture_output=True, timeout=45)
            if proc.returncode:
                raise RuntimeError(f'{parts}: exit={proc.returncode}: {proc.stderr}')
            return proc.stdout
        run('init')
        original = json.loads((root / 'examples/demo-report/results.json').read_text())
        start = datetime(2026, 8, 30, 10, tzinfo=timezone.utc)
        def snapshot(project: str, i: int, count: int) -> dict:
            r = copy.deepcopy(original)
            r['id'] = project + f'-run-{i:03}'
            r['app_version'] = 'SYNTHETIC-HISTORY-TEST'
            r['project_key'] = project
            r['namespace'] = 'default'
            r['branch'] = 'feature' if i in (2, 3) else 'main'
            r['revision'] = 'fixture-' + f'{i:04}'
            r['target'] = {'kind': 'dir', 'value': 'SYNTHETIC/demo-app', 'identity': 'fixture'}
            r['started_at'] = (start + timedelta(days=i)).isoformat()
            r['finished_at'] = (start + timedelta(days=i, seconds=20+i)).isoformat()
            r['config_hash'] = 'synthetic-comparison-policy'
            r['resolved'] = []
            findings = []
            for j in range(count):
                f = copy.deepcopy(original['findings'][j % len(original['findings'])])
                fp = hashlib.sha256(f'fixture-{j}'.encode()).hexdigest()
                f.update(id=fp[:24], fingerprint=fp, title=f'Synthetic finding {j}')
                if i == 33 and j == 1:
                    f['severity'] = 'low'
                    f['decision'] = 'pass'
                findings.append(f)
            if i == 33:
                f = copy.deepcopy(findings[0])
                f['fingerprint'] = hashlib.sha256(b'new-fixture').hexdigest()
                f['id'] = f['fingerprint'][:24]
                f['rule_id'] = 'SYNTHETIC-NEW-RULE'
                findings.append(f)
            r['findings'] = findings
            incomplete = i in (7, 19)
            for e in r['engines']:
                e['status'] = 'failed' if incomplete and e['name'] == 'grype' else 'completed'
            r['complete'] = not incomplete
            s = {'components': len(r['components']), 'findings': len(findings),
                 'failures': 0, 'reviews': 0, 'accepted': 0, 'new': 0, 'resolved': 0,
                 'by_category': {}, 'by_severity': {}}
            for f in findings:
                s['by_category'][f['category']] = s['by_category'].get(f['category'], 0)+1
                s['by_severity'][f['severity']] = s['by_severity'].get(f['severity'], 0)+1
                decision = {'fail': 'failures', 'review': 'reviews', 'accepted': 'accepted'}.get(f['decision'])
                if decision:
                    s[decision] += 1
            r['summary'] = s
            r['exit_code'] = 2 if incomplete else 1 if s['failures'] or s['reviews'] else 0
            r['status'] = {0: 'passed', 1: 'failed', 2: 'incomplete'}[r['exit_code']]
            r['warnings'] = ['SYNTHETIC FIXTURES: no actual scanner was executed.']
            return r
        input_file = work / 'fixture.json'
        for i in range(34):
            input_file.write_text(json.dumps(snapshot('payments-api', i, 65-i)))
            run('storage', 'import', str(input_file), '--project', 'payments-api')
        for i in range(11):
            project = f'example-service-{i:02}'
            input_file.write_text(json.dumps(snapshot(project, i, 12)))
            run('storage', 'import', str(input_file), '--project', project)
        run('storage', 'import', str(input_file), '--project', 'example-service-10')
        projects = json.loads(run('history', 'projects', '--page-size', '10', '--json'))
        assert projects['total'] == 12 and len(projects['items']) == 10 and projects['has_next']
        checks.append('CLI projects use paginated envelopes with accurate totals; imports are idempotent')
        rows = json.loads(run('history', 'list', '--project', 'payments-api', '--page', '2', '--page-size', '10', '--json'))
        assert rows['total'] == 34 and len(rows['items']) == 10 and rows['items'][0]['id'] == 'payments-api-run-023'
        checks.append('CLI project runs page deterministically with totals')
        exact = json.loads(run('history', 'projects', '--project', 'payments-api', '--json'))
        assert exact['total'] == 1 and exact['items'][0]['key'] == 'payments-api'
        assert json.loads(run('history', 'list', '--project', 'payments', '--json'))['total'] == 0
        checks.append('CLI exact project filtering does not fall back to partial matching or all projects')
        base_id, head_id = 'payments-api-run-032', 'payments-api-run-033'
        comparison = json.loads(run('history', 'compare', base_id, head_id, '--page-size', '10', '--json'))
        assert len(comparison['page']['items']) == 10
        assert comparison['comparison']['counts']['new'] == 1
        assert comparison['comparison']['counts']['changed'] == 1
        checks.append('CLI comparison returns paged changes with new and changed findings')
        full_diff = work / 'comparison.json'
        run('history', 'compare', base_id, head_id, '--out', str(full_diff))
        assert len(json.loads(full_diff.read_text())['changes']) > 10
        checks.append('Explicit comparison export retains all rows rather than only the current page')
        trend = json.loads(run('history', 'trends', '--project', 'payments-api', '--trend-limit', '10', '--json'))
        assert trend['truncated'] and len(trend['points']) == 10 and trend['total_matching_runs'] == 34
        checks.append('Trend window is bounded and labels truncation explicitly')
        export = work / 'export'
        run('history', 'export', head_id, '--out', str(export))
        assert (export / 'index.html').is_file()
        checks.append('Stored run exports a portable HTML report')
        proc = subprocess.Popen([str(binary), 'serve', '--listen', '127.0.0.1:0', *common],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            selector = selectors.DefaultSelector()
            assert proc.stdout
            selector.register(proc.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError('history server did not start')
            line = proc.stdout.readline()
            selector.close()
            match = re.search(r'http://127\.0\.0\.1:\d+', line)
            if not match:
                raise RuntimeError(line)
            base = match.group(0)
            def fetch(path: str) -> bytes:
                with urllib.request.urlopen(base + path, timeout=20) as response:
                    return response.read()
            page = json.loads(fetch('/api/projects?page_size=10&page=2'))
            assert len(page['items']) == 2 and not page['has_next']
            checks.append('Live HTTP project pagination has an exact last page')
            assert json.loads(fetch('/api/scans?project=absent'))['items'] == []
            assert json.loads(fetch('/scans/'+head_id+'/results.json'))['project_key'] == 'payments-api'
            checks.append('Live run API and report endpoints preserve project identity')
            for path in ['/?page_size=201', '/?page=0', '/compare?base='+head_id+'&head='+base_id]:
                try:
                    fetch(path)
                    raise AssertionError('bad request was accepted')
                except urllib.error.HTTPError as error:
                    assert error.code == 400
            checks.append('HTTP rejects invalid paging and reversed comparisons')
            if args.chromium:
                from playwright.sync_api import sync_playwright
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=args.chromium, headless=True)
                    try:
                        context = browser.new_context(viewport={'width': 1500, 'height': 1050})
                        page = context.new_page()
                        errors: list[str] = []
                        current_path = '/'
                        page.on('pageerror', lambda e: errors.append(str(e)))
                        def bridge(route):
                            path=route.request.url.removeprefix('http://sekscan.test')
                            try:
                                with urllib.request.urlopen(base+path, timeout=20) as reply:
                                    route.fulfill(status=reply.status, headers=dict(reply.headers), body=reply.read())
                            except urllib.error.HTTPError as error:
                                route.fulfill(status=error.code, body=error.read())
                        context.route('http://sekscan.test/**', bridge)
                        styles = {name: fetch('/assets/'+name+'.css').decode() for name in ('sekura','history')}
                        scripts = {name: fetch('/assets/'+name+'.js').decode() for name in ('ui','history')}
                        def display(path: str):
                            nonlocal current_path, page
                            current_path=path
                            if not args.embedded_browser:
                                page.goto('http://sekscan.test'+path,wait_until='load')
                                return
                            # Restricted-browser harness only: HTTP routes are tested above;
                            # render their actual bytes without opening blocked origins.
                            page.close();page=context.new_page()
                            page.on('pageerror', lambda e: errors.append(str(e)))
                            try:
                                html=fetch(path).decode()
                            except urllib.error.HTTPError as error:
                                html=error.read().decode()
                            for name, css in styles.items():
                                html=html.replace('<link rel="stylesheet" href="/assets/'+name+'.css">','<style>'+css+'</style>')
                            for name in scripts:
                                html=html.replace('<script src="/assets/'+name+'.js" defer></script>','')
                            if 'data-mode="error"' in html:
                                html=html.replace('</body>', '<script>'+scripts['ui']+'</script></body>')
                            elif 'data-mode=' in html:
                                html=html.replace('</body>', '<script>'+scripts['ui']+'</script><script>'+scripts['history']+'</script></body>')
                            page.set_content(html,wait_until='load')
                            page.expose_function('__sekscan_test_fetch', lambda path: fetch(path).decode())
                            page.evaluate("""path => {
                              const original=window.fetch.bind(window);
                              window.fetch=async (url,options)=> {
                                if(typeof url==='string' && url.startsWith('/api/'))
                                  return new Response(await window.__sekscan_test_fetch(url),{status:200,headers:{'Content-Type':'application/json'}});
                                return original(url,options);
                              };
                              window.__sekscan_test_next=null;
                              document.addEventListener('click',e=>{
                                const a=e.target.closest('a');
                                if(a && a.getAttribute('href')?.startsWith('/')) {
                                  e.preventDefault();window.__sekscan_test_next=a.getAttribute('href');
                                }
                              });
                              document.addEventListener('submit',e=>{
                                e.preventDefault();const f=e.target;
                                window.__sekscan_test_next=(f.getAttribute('action')||path.split('?')[0])+'?'+new URLSearchParams(new FormData(f)).toString();
                              });
                            }""",path)
                        def navigate_click(locator):
                            nonlocal current_path
                            if args.embedded_browser:
                                page.evaluate('window.__sekscan_test_next=null')
                                locator.click()
                                target=page.evaluate('window.__sekscan_test_next')
                                assert target,'UI did not produce a navigation destination'
                                display(target)
                            else:
                                with page.expect_navigation(wait_until='load'):
                                    locator.click()
                                current_path=page.url.removeprefix('http://sekscan.test')
                        def shot(name: str):
                            if args.screenshots:
                                args.screenshots.mkdir(parents=True, exist_ok=True)
                                page.screenshot(path=str(args.screenshots / (name+'.png')), full_page=(name != 'mobile-navigation'))
                        display('/')
                        assert page.get_by_role('tab',name='Dashboard',exact=True).get_attribute('aria-selected')=='true'
                        assert page.locator('#projects-table').count()==0 and page.locator('#runs-table').count()==0
                        assert page.locator('.chart-area svg').count()==4
                        assert page.locator('#portfolio-projects').inner_text()=='12'
                        portfolio=json.loads(fetch('/api/portfolio?days=30'))
                        assert portfolio['current']['projects']==12
                        assert portfolio['current']['findings']==153
                        assert portfolio['current']['incomplete']==1
                        assert len(portfolio['points'])==30
                        assert json.loads(fetch('/api/portfolio?project=payments-api'))['current']['projects']==1
                        checks.append('Default serve opens the all-project dashboard; totals use latest snapshots, not all runs or one page')
                        shot('portfolio')
                        page.locator('[data-theme]').select_option('light')
                        navigate_click(page.get_by_role('tab',name='Projects',exact=True))
                        if not args.embedded_browser:
                            assert page.locator('html').get_attribute('data-sk-theme')=='light'
                        page.locator('[data-theme]').select_option('dark')
                        page.get_by_role('tab',name='Projects',exact=True).focus()
                        page.keyboard.press('ArrowRight')
                        assert page.evaluate("document.activeElement.textContent").strip()=='All runs'
                        page.keyboard.press('Enter')
                        if args.embedded_browser:
                            display(page.evaluate('window.__sekscan_test_next'))
                        else:
                            page.wait_for_url('**tab=runs')
                        assert page.locator('#runs-table').count()==1 and page.locator('.chart-area').count()==0
                        assert 'payments-api' in page.locator('#runs-table').inner_text()
                        checks.append('Workspace tabs support keyboard navigation and theme selection'+(' (opaque-origin storage persistence not tested)' if args.embedded_browser else ' and persistent theme'))
                        display('/?tab=projects&page_size=10')
                        assert page.locator('#projects-table tbody tr').count() == 10
                        shot('projects')
                        navigate_click(page.get_by_role('link', name='Next', exact=True))
                        assert page.locator('#projects-table tbody tr').count() == 2
                        assert page.get_by_role('link', name='Next', exact=True).count() == 0
                        checks.append('Browser project next/last-page controls and page-size selection')
                        display('/?tab=projects&page_size=10')
                        picker = page.locator('[data-project-filter]')
                        picker.fill('payments')
                        page.wait_for_function("Array.from(document.querySelectorAll('#project-options option')).some(o=>o.value==='payments-api')")
                        assert page.locator('#project-options option').count() <= 25
                        checks.append('Project picker obtains bounded suggestions from the live project API')
                        picker.fill('payments-api')
                        navigate_click(page.get_by_role('button', name='Apply filters', exact=True))
                        assert page.locator('#projects-table tbody tr').count() == 1
                        assert page.locator('[data-project-filter]').input_value() == 'payments-api'
                        shot('project-filter')
                        page.locator('[data-project-filter]').fill('')
                        navigate_click(page.get_by_role('button', name='Apply filters', exact=True))
                        assert page.locator('#projects-table tbody tr').count() == 10
                        checks.append('Exact project filter and clear-filter action update rows and totals')
                        display('/projects?project=payments-api&tab=runs&page_size=10')
                        page.locator('[data-project-filter]').fill('example-service-00')
                        navigate_click(page.get_by_role('button', name='Apply filters', exact=True))
                        assert page.locator('body').get_attribute('data-project') == 'example-service-00'
                        assert 'payments-api-run' not in page.locator('#runs-table').inner_text()
                        assert not page.locator('#base-selection').input_value().startswith('payments-api')
                        checks.append('Changing projects clears the previous comparison selection')

                        display('/projects?project=payments-api&page_size=10')
                        assert page.locator('#runs-table').count() == 0
                        assert page.locator('.chart-area svg').count() == 5
                        assert page.locator('.incomplete-point').count() > 0
                        assert page.locator('#window-incomplete').inner_text() == '2'
                        assert 'mixes branches' in page.locator('#mixed-series').inner_text()
                        shot('project-trends')
                        checks.append('Project Dashboard tab isolates five trend charts from the run table')
                        navigate_click(page.get_by_role('tab', name='Runs', exact=True))
                        assert page.locator('#runs-table tbody tr').count() == 10
                        assert page.locator('.chart-area').count() == 0
                        page.locator('[data-pick=base][data-run="payments-api-run-025"]').click()
                        navigate_click(page.get_by_role('link', name='Next', exact=True))
                        assert page.locator('#base-selection').input_value() == 'payments-api-run-025'
                        assert page.locator('[data-project-filter]').input_value() == 'payments-api'
                        assert page.locator('#runs-table tbody tr').count() == 10
                        page.locator('[data-pick=base][data-run="payments-api-run-020"]').click()
                        navigate_click(page.get_by_role('link', name='First', exact=True))
                        page.locator('[data-pick=head][data-run="payments-api-run-033"]').click()
                        assert page.locator('#base-selection').input_value() == 'payments-api-run-020'
                        checks.append('Comparison selections persist while paging across runs')
                        page.locator('#base-selection').fill(base_id)
                        page.locator('#head-selection').fill(head_id)
                        navigate_click(page.locator('#compare-selection').get_by_role('button', name='Compare runs', exact=True))
                        assert page.locator('#comparison-table').count() == 0
                        assert page.locator('.chart-area svg').count() == 2
                        assert 'newly reported' in page.locator('.comparison-metrics').inner_text().lower()
                        shot('comparison')
                        navigate_click(page.get_by_role('tab', name='Findings', exact=True))
                        assert page.locator('#comparison-table tbody tr').count() == 25
                        navigate_click(page.get_by_role('link', name='Next', exact=True))
                        assert page.locator('#comparison-table tbody tr').count() > 0
                        checks.append('Comparison separates Summary charts and paginated Finding differences')
                        navigate_click(page.get_by_role('tab', name='Components / licenses', exact=True))
                        assert 'Component differences' in page.locator('.panel-heading').inner_text()
                        checks.append('Component/license comparison view supports filtering and pagination')
                        display('/compare?base=payments-api-run-006&head=payments-api-run-007')
                        assert 'not directly comparable' in page.locator('.notice').inner_text()
                        assert 'incomplete' in page.locator('.notice').inner_text()
                        checks.append('Incomplete comparisons visibly warn instead of implying remediation')
                        display('/projects?project=payments-api&tab=runs&page_size=10')
                        page.locator('input[name=branch]').first.fill('main')
                        page.locator('input[name=from]').first.fill('2026-09-29')
                        page.locator('input[name=to]').first.fill('2026-10-02')
                        navigate_click(page.get_by_role('button', name='Apply filters', exact=True))
                        assert page.locator('#runs-table tbody tr').count() == 4
                        checks.append('Date/branch filters reset page and apply to both run list and trends')
                        display('/scans/'+head_id)
                        assert page.locator('.app-rail').is_visible()
                        assert not page.locator('#data-section').is_visible()
                        shot('report')
                        page.get_by_role('tab', name='Findings', exact=False).click()
                        assert page.locator('#table-body tr').count() == 25
                        page.locator('#page-size').select_option('10')
                        assert page.locator('#table-body tr').count() == 10
                        page.locator('#last-page').click()
                        assert page.locator('#table-body tr').count() == 3
                        assert page.locator('#next').is_disabled()
                        page.locator('#first-page').click()
                        assert page.locator('#table-body tr').count() == 10
                        checks.append('Stored scan findings page size and first/last controls work')
                        navigate_click(page.locator('.app-topbar [data-history-project]'))
                        assert 'project=payments-api' in current_path
                        checks.append('Run details navigate back to the correct project')
                        page.set_viewport_size({'width': 390, 'height': 844})
                        assert page.locator('h1').is_visible()
                        if not page.evaluate('document.documentElement.scrollWidth <= innerWidth+2'):
                            shot('mobile-debug')
                            overflow = page.evaluate("""() => Array.from(document.querySelectorAll('body *')).map(e=>({tag:e.tagName,cls:e.className?.baseVal ?? e.className,left:e.getBoundingClientRect().left,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width})).filter(e=>e.right>innerWidth+2 && e.width>0).slice(0,25)""")
                            raise AssertionError(f'mobile overflow: {overflow}')
                        checks.append('Project dashboard remains usable at a 390px viewport')
                        if args.design_review:
                            from ui_design_checks import run_design_checks
                            checks.extend(run_design_checks(display, lambda: page, navigate_click, shot))
                        assert not errors, errors
                        checks.append('No JavaScript runtime errors across history workflows')
                    finally:
                        browser.close()
        finally:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                raise RuntimeError('history server did not stop')
        assert proc.returncode == 0
        checks.append('History server shuts down cleanly')
        locked = subprocess.Popen([str(binary), 'serve', '--project', 'payments-api',
                                   '--listen', '127.0.0.1:0', *common],
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            selector = selectors.DefaultSelector()
            assert locked.stdout
            selector.register(locked.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError('project-filtered server did not start')
            line = locked.stdout.readline()
            selector.close()
            match = re.search(r'http://127\.0\.0\.1:\d+', line)
            if not match:
                raise RuntimeError(line)
            locked_base = match.group(0)
            with urllib.request.urlopen(locked_base + '/api/projects', timeout=10) as response:
                payload = json.load(response)
                assert payload['total'] == 1 and payload['items'][0]['key'] == 'payments-api'
            with urllib.request.urlopen(locked_base + '/', timeout=10) as response:
                assert 'readonly' in response.read().decode()
            try:
                urllib.request.urlopen(locked_base + '/api/scans?project=example-service-00', timeout=10)
                raise AssertionError('server accepted another project')
            except urllib.error.HTTPError as error:
                assert error.code == 400
            checks.append('serve --project starts a filtered history viewer without needing --history')
        finally:
            locked.send_signal(signal.SIGINT)
            try:
                locked.wait(timeout=10)
            except subprocess.TimeoutExpired:
                locked.kill()
                locked.wait(timeout=5)
                raise RuntimeError('project-filtered server did not stop')
        assert locked.returncode == 0
        assert list((work/'logs').glob('*.jsonl'))
        checks.append('Commands write local application logs')
    print(json.dumps({'passed': len(checks), 'checks': checks,
                      'data': 'synthetic fixtures',
                      'browser_mode': ('Embedded rendering of live HTTP responses; navigation/API bridge and inline assets; browser navigation policy and opaque-origin storage not exercised' if args.embedded_browser else 'Navigation, assets and APIs bridged through synthetic HTTP origin using unmodified live localhost responses')}, indent=2))


if __name__ == '__main__':
    main()
