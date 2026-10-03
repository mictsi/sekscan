/* Sekura 3.0.2 host-owned controllers. No network access or executable user content.
 * Full-page navigation disposes controllers; report imports reuse the same shell. */
(() => {
  'use strict';
  const root = document.documentElement;
  const themes = ['dark', 'light', 'hc-dark', 'hc-light', 'system'];
  const darkQuery = matchMedia('(prefers-color-scheme: dark)');
  const contrastQuery = matchMedia('(prefers-contrast: more)');
  const read = (key, fallback) => { try { return localStorage.getItem(key) || fallback; } catch { return fallback; } };
  const save = (key, value) => { try { localStorage.setItem(key, value); } catch { /* Preferences are optional. */ } };
  let preference = read('sekscan.theme', contrastQuery.matches ? (darkQuery.matches ? 'hc-dark' : 'hc-light') : 'dark');
  if (!themes.includes(preference)) preference = 'dark';
  function applyTheme(value, persist = true) {
    if (!themes.includes(value)) return;
    preference = value;
    const resolved = value === 'system'
      ? (contrastQuery.matches ? 'hc-' : '') + (darkQuery.matches ? 'dark' : 'light') : value;
    root.dataset.skTheme = resolved;
    document.querySelectorAll('[data-theme]').forEach(select => { select.value = value; });
    if (persist) save('sekscan.theme', value);
  }
  applyTheme(preference, false);
  document.querySelectorAll('[data-theme]').forEach(select => select.addEventListener('change', () => applyTheme(select.value)));
  const followSystem = () => { if (preference === 'system') applyTheme(preference, false); };
  darkQuery.addEventListener('change', followSystem);
  contrastQuery.addEventListener('change', followSystem);

  // Manual activation: arrows move focus; Enter/Space selects. Links keep browser Back.
  document.querySelectorAll('[role="tablist"]').forEach(list => list.addEventListener('keydown', event => {
    const tabs = [...list.querySelectorAll('[role="tab"]')].filter(tab => !tab.hidden && !tab.disabled);
    const index = tabs.indexOf(document.activeElement);
    if (index < 0) return;
    const rtl = getComputedStyle(list).direction === 'rtl';
    let next;
    if (event.key === 'ArrowRight') next = (index + (rtl ? -1 : 1) + tabs.length) % tabs.length;
    else if (event.key === 'ArrowLeft') next = (index + (rtl ? 1 : -1) + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else if (event.key === ' ' && tabs[index].tagName === 'A') { event.preventDefault(); tabs[index].click(); return; }
    else return;
    event.preventDefault();
    tabs.forEach((tab, i) => { tab.tabIndex = i === next ? 0 : -1; });
    tabs[next].focus();
  }));

  const nav = document.getElementById('app-navigation');
  const trigger = document.querySelector('[data-nav-trigger]');
  const scrim = document.querySelector('[data-nav-scrim]');
  const header = document.querySelector('[data-app-header]');
  if (header && typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(() => root.style.setProperty('--sekscan-header-size', header.getBoundingClientRect().height + 'px')).observe(header);
  }
  if (nav && trigger && scrim) {
    const narrow = matchMedia('(max-width: 63.999rem)');
    let collapsed = read('sekscan.nav.collapsed', 'false') === 'true';
    let modal = false;
    let inertStates = [];
    let oldOverflow = '';
    const focusables = () => [...nav.querySelectorAll('a[href],button:not(:disabled),input,select,[tabindex="0"]')]
      .filter(element => element.getClientRects().length && !element.closest('[hidden]') && !element.inert);
    function releaseBackground() {
      inertStates.forEach(([element, value]) => { element.inert = value; });
      inertStates = [];
      document.body.style.overflow = oldOverflow;
    }
    function sync() {
      root.toggleAttribute('data-nav-collapsed', !narrow.matches && collapsed);
      nav.classList.toggle('sk-side-nav--collapsed', !narrow.matches && collapsed);
      nav.hidden = narrow.matches && !modal;
      scrim.hidden = !modal;
      trigger.setAttribute('aria-expanded', String(narrow.matches ? modal : !collapsed));
      trigger.setAttribute('aria-label', narrow.matches ? (modal ? 'Close navigation' : 'Open navigation') : (collapsed ? 'Expand navigation' : 'Collapse navigation'));
      if (modal) { nav.setAttribute('role', 'dialog'); nav.setAttribute('aria-modal', 'true'); }
      else { nav.removeAttribute('role'); nav.removeAttribute('aria-modal'); }
    }
    function close(returnFocus = true) {
      if (!modal) return;
      modal = false;
      releaseBackground();
      sync();
      if (returnFocus) trigger.focus();
    }
    function open() {
      if (!narrow.matches || modal) return;
      modal = true;
      oldOverflow = document.body.style.overflow;
      inertStates = [...document.body.children].filter(element => element !== nav && element !== scrim)
        .map(element => [element, element.inert]);
      inertStates.forEach(([element]) => { element.inert = true; });
      document.body.style.overflow = 'hidden';
      sync();
      (nav.querySelector('[data-nav-close]') || nav).focus();
    }
    trigger.addEventListener('click', () => {
      if (narrow.matches) { if (modal) close(); else open(); }
      else { collapsed = !collapsed; save('sekscan.nav.collapsed', String(collapsed)); sync(); }
    });
    nav.querySelector('[data-nav-close]')?.addEventListener('click', () => close());
    scrim.addEventListener('click', () => close());
    nav.addEventListener('keydown', event => {
      if (!modal) return;
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
      if (event.key === 'Tab') {
        const items = focusables();
        const first = items[0], last = items[items.length - 1];
        if (!first) { event.preventDefault(); nav.focus(); return; }
        if (event.shiftKey && (document.activeElement === first || document.activeElement === nav)) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
    nav.addEventListener('click', event => {
      if (modal && event.target.closest('a[href]')) {
        close(false);
        document.getElementById('main')?.focus();
      }
    });
    narrow.addEventListener('change', () => {
      if (modal) close();
      sync();
      if (narrow.matches && nav.contains(document.activeElement)) trigger.focus();
    });
    // Disclosure state owns only expansion; it never changes routes/current markers.
    nav.querySelectorAll('[data-nav-disclosure]').forEach(button => {
      const children = document.getElementById(button.dataset.navDisclosure);
      if (!children || !nav.contains(children)) return;
      const setExpanded = value => { button.setAttribute('aria-expanded', String(value)); children.hidden = !value; };
      setExpanded(button.getAttribute('aria-expanded') === 'true');
      button.addEventListener('click', () => setExpanded(button.getAttribute('aria-expanded') !== 'true'));
      children.addEventListener('keydown', event => {
        if (event.key === 'Escape' && !modal) { event.preventDefault(); event.stopPropagation(); setExpanded(false); button.focus(); }
      });
    });
    sync();
    // Labels remain accessible in icon-only mode; tooltips also help pointer users.
    const tooltip = document.createElement('div');
    tooltip.id = 'nav-tooltip'; tooltip.className = 'nav-tooltip'; tooltip.setAttribute('role', 'tooltip'); tooltip.hidden = true;
    document.body.append(tooltip);
    let tooltipOwner;
    const hideTooltip = () => { tooltip.hidden = true; if (tooltipOwner) tooltipOwner.removeAttribute('aria-describedby'); tooltipOwner = null; };
    nav.querySelectorAll('[data-nav-label]').forEach(link => {
      const show = () => {
        if (narrow.matches || !collapsed) return;
        hideTooltip(); tooltipOwner = link; tooltip.textContent = link.dataset.navLabel;
        tooltip.hidden = false; link.setAttribute('aria-describedby', tooltip.id);
        const rect = link.getBoundingClientRect();
        const rtl = getComputedStyle(nav).direction === 'rtl';
        const left = rtl ? rect.left - tooltip.offsetWidth - 12 : rect.right + 12;
        tooltip.style.left = Math.max(8, Math.min(left, innerWidth - tooltip.offsetWidth - 8)) + 'px';
        tooltip.style.top = Math.max(8, Math.min(rect.top, innerHeight - tooltip.offsetHeight - 8)) + 'px';
      };
      link.addEventListener('mouseenter', show); link.addEventListener('focus', show);
      link.addEventListener('mouseleave', hideTooltip); link.addEventListener('blur', hideTooltip);
    });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') hideTooltip(); });
    trigger.addEventListener('click', hideTooltip);
    narrow.addEventListener('change', hideTooltip);
  }

  // Density is local to a table's scrolling region, never the surrounding controls.
  document.querySelectorAll('.panel').forEach((panel, index) => {
    const table = panel.querySelector('table');
    const head = panel.querySelector('.panel-heading, .panel-head');
    const region = panel.querySelector('.scroll, .table-wrap');
    if (!table || !head || !region) return;
    const key = 'sekscan.tableDensity:' + (table.id || (document.body.dataset.mode + ':' + index));
    const choices = ['comfortable', 'compact', 'dense'];
    const label = document.createElement('label'); label.className = 'table-density';
    label.append(document.createTextNode('Table density'));
    const select = document.createElement('select'); select.dataset.tableDensity = '';
    select.setAttribute('aria-label', 'Table density');
    choices.forEach(value => { const option = document.createElement('option'); option.value = value; option.textContent = value[0].toUpperCase() + value.slice(1); select.append(option); });
    const stored = read(key, 'comfortable'); select.value = choices.includes(stored) ? stored : 'comfortable';
    region.dataset.skDensity = select.value;
    select.addEventListener('change', () => { region.dataset.skDensity = select.value; save(key, select.value); });
    label.append(select); head.append(label);
    region.tabIndex = 0; region.setAttribute('role', 'region'); region.setAttribute('aria-label', (head.querySelector('h2')?.textContent || 'Evidence') + ' table');
  });
  root.setAttribute('data-ui-ready', '');
})();
