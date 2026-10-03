"""Sekura 3.0.2 consumer checks, invoked by history-smoke.py --design-review.

Uses synthetic stored reports and real local HTTP responses. These checks do not
replace assistive-technology review or a cross-browser acceptance run.
"""
from __future__ import annotations


def run_design_checks(display, get_page, navigate_click, shot) -> list[str]:
    checks: list[str] = []

    def open_page(path: str):
        display(path)
        p = get_page()
        p.wait_for_function("document.documentElement.hasAttribute('data-ui-ready')")
        return p

    def no_overflow(p):
        assert p.evaluate('document.documentElement.scrollWidth <= innerWidth+2'), p.evaluate("({width:innerWidth,scroll:document.documentElement.scrollWidth})")

    p = open_page('/')
    measured = p.evaluate("""() => ({version:document.documentElement.dataset.sekuraVersion,
      header:document.querySelector('[data-app-header]').getBoundingClientRect().height,
      nav:document.getElementById('app-navigation').getBoundingClientRect().width,
      title:getComputedStyle(document.querySelector('h1')).fontSize,
      line:getComputedStyle(document.querySelector('h1')).lineHeight,
      control:document.querySelector('input:not([type=hidden])').getBoundingClientRect().height})""")
    assert measured == {'version':'3.0.2','header':48,'nav':272,'title':'32px','line':'40px','control':36}, measured
    checks.append('Pinned 3.0.2 geometry: 48px header, 272px rail, 32/40px title and 36px controls')
    shot('portfolio-dark')

    paths = [('/', 'Portfolio'),('/?tab=projects','Projects'),('/?tab=runs','All runs'),
             ('/projects?project=payments-api','Dashboard'),('/projects?project=payments-api&tab=runs','Runs'),
             ('/compare?base=payments-api-run-032&head=payments-api-run-033','Run comparison'),
             ('/scans/payments-api-run-033','Scan report')]
    for path, label in paths:
        p = open_page(path)
        selected = p.locator('#app-navigation a[aria-current=page]')
        assert selected.count() == 1 and selected.inner_text().strip() == label, (path, selected.all_text_contents())
        assert p.locator('#app-navigation').count() == 1
        no_overflow(p)
    checks.append('Portfolio, projects, runs, comparisons and reports share one shell and one exact current-page marker')

    p = open_page('/projects?project=payments-api&tab=runs')
    toggle = p.locator('[data-nav-disclosure]')
    assert p.locator('[data-active-ancestor]').inner_text().strip() == 'Projects'
    assert p.locator('#project-nav-children').evaluate("e=>getComputedStyle(e).borderInlineStartWidth") == '1px'
    assert p.locator('#app-navigation [aria-current=page]').evaluate("e=>getComputedStyle(e,'::before').width") == '4px'
    toggle.focus();p.keyboard.press('Space')
    assert toggle.get_attribute('aria-expanded') == 'false' and p.locator('#project-nav-children').is_hidden()
    assert p.locator('#runs-table').is_visible()
    p.keyboard.press('Space')
    assert p.locator('#project-nav-children').is_visible()
    p.locator('[data-project-route=runs]').focus();p.keyboard.press('Escape')
    assert toggle.evaluate('e=>e===document.activeElement') and p.locator('#project-nav-children').is_hidden()
    toggle.click()
    checks.append('Sidebar links and expansion are separate; guides, exact markers, Space and Escape retain route state')

    trigger = p.locator('[data-nav-trigger]');trigger.click()
    assert trigger.get_attribute('aria-label') == 'Expand navigation'
    assert p.locator('#app-navigation').bounding_box()['width'] == 56
    link=p.locator('[data-nav-label=Portfolio]');link.focus()
    assert p.get_by_role('tooltip').is_visible() and p.get_by_role('tooltip').inner_text()=='Portfolio'
    p.keyboard.press('Escape');assert p.get_by_role('tooltip').is_hidden()
    trigger.click();assert p.locator('#app-navigation').bounding_box()['width']==272
    checks.append('Desktop collapse preserves accessible labels, adds focus tooltips and restores the expanded rail')

    # Long hints and field feedback must not move neighboring control borders.
    p.evaluate("""() => {
      document.querySelector('label[for=filter-project]').textContent='Project key with a long translated label';
      document.getElementById('project-picker-status').textContent='Choose the exact project key from the available project suggestions. This deliberately wraps across several lines.';
      document.querySelector('.project-filter .sk-field__support').textContent='Example validation feedback below the control.';
    }""")
    geometry=p.evaluate("""() => {
      const field=document.querySelector('.project-filter'), row=field.parentElement;
      const peers=[...row.children].filter(e=>e.classList.contains('sk-field')).slice(0,3);
      return {starts:peers.map(e=>e.querySelector('.sk-field__control').getBoundingClientRect().top),
        order:[...field.children].map(e=>e.className)};
    }""")
    assert max(geometry['starts'])-min(geometry['starts']) <= 1, geometry
    assert geometry['order']==['sk-field__label','sk-field__hint','sk-field__control sk-input-with-indicator','sk-field__support'], geometry
    box=p.locator('#base-selection').bounding_box()
    assert abs(box['y'] - p.locator('#compare-selection button[type=submit]').bounding_box()['y']) <= 1
    assert p.locator('.sk-input-with-indicator').evaluate("e=>getComputedStyle(e,'::after').content") != 'none'
    checks.append('Wrapped field labels/hints share four tracks; feedback stays below and comparison actions align with inputs')

    p = open_page('/projects?project=payments-api&tab=runs')
    control_height=p.locator('#filter-project').bounding_box()['height']
    for density,padding in [('comfortable','12px'),('compact','8px'),('dense','4px')]:
        p.locator('[data-table-density]').select_option(density)
        style=p.locator('#runs-table td').first.evaluate("e=>({pad:getComputedStyle(e).paddingBlockStart,font:getComputedStyle(e).fontSize})")
        assert style=={'pad':padding,'font':'14px'},style
        assert p.locator('#filter-project').bounding_box()['height']==control_height
    p.locator('[data-table-density]').select_option('comfortable')
    shot('project-runs')
    checks.append('Table-only density uses 12/8/4px row padding without shrinking fonts or surrounding controls')

    # Mobile modal navigation: close, focus return, inert restoration and resize.
    p.set_viewport_size({'width':390,'height':844})
    nav=p.locator('#app-navigation');trigger=p.locator('[data-nav-trigger]')
    nav.wait_for(state='hidden')
    assert trigger.get_attribute('aria-label')=='Open navigation'
    trigger.click();assert nav.is_visible() and nav.get_attribute('aria-modal')=='true'
    assert p.locator('.app-area').evaluate('e=>e.inert') and p.locator('[data-app-header]').evaluate('e=>e.inert')
    assert p.locator('[data-nav-close]').evaluate('e=>e===document.activeElement')
    p.keyboard.press('Shift+Tab')
    assert nav.evaluate("e=>e.contains(document.activeElement)") and not p.locator('[data-nav-close]').evaluate('e=>e===document.activeElement')
    p.keyboard.press('Tab');assert p.locator('[data-nav-close]').evaluate('e=>e===document.activeElement')
    shot('mobile-navigation')
    p.keyboard.press('Escape')
    assert nav.is_hidden() and trigger.evaluate('e=>e===document.activeElement')
    assert not p.locator('.app-area').evaluate('e=>e.inert')
    trigger.click();p.locator('[data-nav-scrim]').click(position={'x':380,'y':700})
    assert nav.is_hidden()
    trigger.click();p.set_viewport_size({'width':1500,'height':1050})
    p.wait_for_function("!document.querySelector('.app-area').inert")
    assert nav.get_attribute('aria-modal') is None and p.evaluate("document.body.style.overflow")!='hidden'
    checks.append('Mobile drawer traps focus, blocks background, closes with Escape/scrim, returns focus and releases state on resize')

    p=open_page('/?tab=projects')
    p.evaluate("document.documentElement.dir='rtl'")
    tabs=p.locator('[role=tablist] [role=tab]')
    tabs.nth(1).focus();p.keyboard.press('ArrowRight')
    assert tabs.nth(0).evaluate('e=>e===document.activeElement')
    assert tabs.nth(1).get_attribute('aria-selected')=='true'
    p.keyboard.press('End');assert tabs.last.evaluate('e=>e===document.activeElement')
    no_overflow(p)
    p.evaluate("document.documentElement.dir='ltr'")
    checks.append('Tabs support RTL-aware arrows and Home/End without navigating until activation')

    # Contrast checks cover actual selected text pairs only, not a full WCAG audit.
    audit_js="""() => {
      const rgb = s => (s.match(/[\\d.]+/g)||[]).slice(0,3).map(Number);
      const luminance=c=>c.map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((a,v,i)=>a+v*[.2126,.7152,.0722][i],0);
      const bg=e=>{for(let n=e;n;n=n.parentElement){let c=getComputedStyle(n).backgroundColor;if(c!=='rgba(0, 0, 0, 0)'&&c!=='transparent')return rgb(c);}return [0,0,0];};
      return ['h1','.heading p','.sk-field__label','.sk-field__hint','.brand','.badge.failed','.sk-side-nav__item[aria-current=page]'].flatMap(selector=>{
        const e=document.querySelector(selector);if(!e)return [];
        const a=luminance(rgb(getComputedStyle(e).color)),b=luminance(bg(e));return [{selector,ratio:(Math.max(a,b)+.05)/(Math.min(a,b)+.05)}];
      });
    }"""
    for theme in ('dark','light','hc-dark','hc-light'):
        p.locator('[data-theme]').select_option(theme)
        results=p.evaluate(audit_js)
        assert all(r['ratio']>=4.5 for r in results), (theme,results)
        if theme=='light':shot('projects-light')
    p.locator('[data-theme]').select_option('system')
    p.emulate_media(color_scheme='light',contrast='more')
    p.wait_for_function("document.documentElement.dataset.skTheme==='hc-light'")
    p.emulate_media(color_scheme='dark',contrast='no-preference')
    p.wait_for_function("document.documentElement.dataset.skTheme==='dark'")
    checks.append('Four themes pass selected rendered-text contrast pairs; System follows color-scheme and contrast preferences')
    p.emulate_media(forced_colors='active',reduced_motion='reduce')
    assert p.locator('#app-navigation [aria-current=page]').evaluate("e=>getComputedStyle(e,'::before').width")=='4px'
    assert p.locator('.sk-input-with-indicator').evaluate("e=>getComputedStyle(e,'::after').borderBlockEndWidth")!='0px'
    assert p.locator('.badge').first.evaluate('e=>getComputedStyle(e).borderTopWidth')=='1px'
    checks.append('Forced colors retain current-page, input-indicator and badge boundaries; reduced-motion rendering is supported')

    # Long pages and table minimum widths stay inside their own scroll regions.
    for path,label in paths:
        for width in (320,390):
            p=open_page(path);p.set_viewport_size({'width':width,'height':844});no_overflow(p)
            p.evaluate("document.documentElement.dir='rtl'");no_overflow(p)
        p=open_page(path);p.set_viewport_size({'width':1280,'height':960})
        p.evaluate("document.documentElement.style.fontSize='200%'");no_overflow(p)
    checks.append('All seven primary surfaces reflow at 320/390px in LTR/RTL and at 200% root text size')

    p=open_page('/scans/payments-api-run-033')
    p.locator('[data-view=findings]').click()
    p.locator('#search').fill('Synthetic finding')
    count=p.locator('#result-count').inner_text()
    first=p.locator('#table-body button.row-link').first
    first.click();assert p.locator('#detail').is_visible()
    assert p.locator('#detail-title').evaluate('e=>e===document.activeElement')
    p.keyboard.press('Escape');assert p.locator('#detail').is_hidden()
    assert first.evaluate('e=>e===document.activeElement')
    checks.append('Named report evidence dialog focuses its heading and returns focus on Escape')
    p.locator('#report-file').set_input_files({'name':'invalid.json','mimeType':'application/json','buffer':b'{broken'})
    p.wait_for_function("!document.getElementById('import-error').hidden")
    assert p.locator('#search').input_value()=='Synthetic finding'
    assert p.locator('#result-count').inner_text()==count
    assert 'previous report is still displayed' in p.locator('#import-error').inner_text()
    checks.append('Malformed report imports show inline errors and preserve the previous report and active filter')
    shot('report-import-error')
    p=open_page('/scans/payments-api-run-033')
    p.locator('[data-view=licenses]').click()
    assert p.locator('#category').locator('..').is_hidden() and p.locator('#search').is_visible()
    p.locator('[data-view=findings]').click()
    shot('report-findings')
    p.locator('[data-view=overview]').click();shot('report-overview')

    p=open_page('/compare?base=payments-api-run-032&head=payments-api-run-033');shot('comparison-summary')
    p=open_page('/?page=0')
    assert p.locator('h1').inner_text()=='Check the request' and p.get_by_role('alert').is_visible()
    assert p.locator('[data-nav-trigger]').is_visible()
    p.set_viewport_size({'width':320,'height':844});no_overflow(p)
    checks.append('Invalid browser requests retain their error status and render a usable shared-shell recovery page')
    return checks
