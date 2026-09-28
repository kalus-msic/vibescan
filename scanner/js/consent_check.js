#!/usr/bin/env node
// Vibescan cookie consent enforcement collector.
//
// Usage: node consent_check.js <url> '<config json>'
//   config: {"tracking_host_suffixes": ["google-analytics.com", ...]}
//
// Prints exactly one JSON line on stdout and always exits 0. The script only
// collects raw data (cookies, matching request URLs, banner buttons, whether
// the banner closed); classification happens in scanner/consent_check.py.
'use strict';

const puppeteer = require('puppeteer-core');

const CHROME_PATH = process.env.CHROME_PATH || '/usr/bin/chromium';
const NAV_TIMEOUT_MS = 15000;
const IDLE_MS = 2000;
const IDLE_CAP_MS = 10000;
const BANNER_POLL_MS = 5000;
const BANNER_POLL_STEP_MS = 500;
const DEADLINE_MS = 80000;
const MAX_REQUESTS = 200;
const MAX_URL_LENGTH = 2000;
const ACCEPT_LANGUAGE = 'cs-CZ,cs;q=0.9,en;q=0.8';

// Known CMP buttons, tried before text matching (trusted as consent context).
const REJECT_SELECTORS = [
  '#onetrust-reject-all-handler',
  '#CybotCookiebotDialogBodyButtonDecline',
  '.cc-deny',
  '.cmpboxbtnno',
  '#didomi-notice-disagree-button',
  '.cky-btn-reject',
  '#cookiescript_reject',
  '.cmplz-deny',
  '#tarteaucitronAllDenied2',
  '.cm__btn[data-role="necessary"]',
];
const ACCEPT_SELECTORS = [
  '#onetrust-accept-btn-handler',
  '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
  '#CybotCookiebotDialogBodyButtonAccept',
  '.cc-allow',
  '.cmpboxbtnyes',
  '#didomi-notice-agree-button',
  '.cky-btn-accept',
  '#cookiescript_accept',
  '.cmplz-accept',
  '#tarteaucitronPersonalize2',
  '.cm__btn[data-role="all"]',
];
// Patterns match text lowercased and stripped of diacritics.
// Reject is tested first, so "nesouhlasim" / "pokracovat bez prijeti" /
// "continue without accepting" never count as accept.
const BUTTON_CFG = {
  rejectSelectors: REJECT_SELECTORS,
  acceptSelectors: ACCEPT_SELECTORS,
  rejectText: '(odmitnout|odmitam|nesouhlasim|pouze nezbytne|jen nezbytne|pouze nutne|pouze technicke|bez prijeti|bez souhlasu|pokracovat bez|reject|decline|deny|refuse|necessary only|only necessary|without accepting|continue without)',
  acceptText: '(prijmout|prijimam|souhlasim|povolit vse|rozumim|accept|allow all|agree|got it)',
  contextAttr: '(cookie|consent|gdpr|cmp|privacy|souhlas|soukromi)',
  contextText: '(cookie|gdpr|osobni udaj|soukromi|privacy)',
  maxText: 40,
  maxContextText: 1500,
  maxContextDepth: 8,
};

let emitted = false;
let activeBrowser = null;

// stdout is a pipe: resolve only after the write is flushed.
function emit(obj) {
  if (emitted) return Promise.resolve();
  emitted = true;
  return new Promise((resolve) => {
    process.stdout.write(JSON.stringify(obj) + '\n', () => resolve());
  });
}

function errorText(e) {
  return String((e && e.message) || e).slice(0, 300);
}

// Runs inside a frame (serialized by puppeteer) - must be self-contained.
// Returns the first first-layer consent button of the given kind, or null.
function findConsentButton(kind, cfg) {
  const norm = (t) => (t || '')
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/\s+/g, ' ').trim().toLowerCase();
  const parentOf = (node) => {
    if (node.parentElement) return node.parentElement;
    const root = node.getRootNode();
    return root instanceof ShadowRoot ? root.host : null;
  };
  const isFirstLayerVisible = (el) => {
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
    const st = window.getComputedStyle(el);
    if (st.visibility === 'hidden' || st.display === 'none') return false;
    for (let n = el; n && n.nodeType === 1; n = parentOf(n)) {
      if (window.getComputedStyle(n).opacity === '0') return false;
    }
    // First layer = visible without scrolling: centre inside the viewport
    const cx = r.left + r.width / 2;
    const cy = r.top + r.height / 2;
    if (cx < 0 || cy < 0 || cx >= window.innerWidth || cy >= window.innerHeight) return false;
    const hit = el.getRootNode().elementFromPoint(cx, cy);
    return !!hit && (hit === el || el.contains(hit));  // not covered
  };
  const attrRe = new RegExp(cfg.contextAttr, 'i');
  const textRe = new RegExp(cfg.contextText, 'i');
  const inIframe = window !== window.top;
  const hasConsentContext = (el) => {
    let n = parentOf(el);
    for (let depth = 0; n && depth < cfg.maxContextDepth; depth++, n = parentOf(n)) {
      if (n === document.documentElement) break;
      // Top-level body text covers the whole page (footer "cookies" links)
      if (n === document.body && !inIframe) break;
      const cls = typeof n.className === 'string' ? n.className : '';
      if (attrRe.test(norm([n.id, cls, n.getAttribute('aria-label')].join(' ')))) return true;
      const text = norm(n.innerText);
      if (text.length <= cfg.maxContextText && textRe.test(text)) return true;
    }
    return false;
  };

  const roots = [document];
  for (let i = 0; i < roots.length; i++) {
    roots[i].querySelectorAll('*').forEach((el) => {
      if (el.shadowRoot) roots.push(el.shadowRoot);
    });
  }
  const selectors = kind === 'reject' ? cfg.rejectSelectors : cfg.acceptSelectors;
  for (const root of roots) {
    for (const sel of selectors) {
      const el = root.querySelector(sel);
      if (el && isFirstLayerVisible(el)) return el;
    }
  }
  const rejectRe = new RegExp(cfg.rejectText, 'i');
  const acceptRe = new RegExp(cfg.acceptText, 'i');
  const candidates = 'button, a, [role="button"], input[type="button"], input[type="submit"]';
  for (const root of roots) {
    for (const el of root.querySelectorAll(candidates)) {
      const text = norm(el.innerText || el.value || el.getAttribute('aria-label'));
      if (!text || text.length > cfg.maxText) continue;
      const isReject = rejectRe.test(text);
      const matches = kind === 'reject' ? isReject : (!isReject && acceptRe.test(text));
      if (matches && isFirstLayerVisible(el) && hasConsentContext(el)) return el;
    }
  }
  return null;
}

// Runs in the parent frame on an <iframe> element: is the frame itself
// visible, inside the viewport and not covered? Self-contained (serialized).
function frameElementVisible(el) {
  const parentOf = (node) => {
    if (node.parentElement) return node.parentElement;
    const root = node.getRootNode();
    return root instanceof ShadowRoot ? root.host : null;
  };
  const r = el.getBoundingClientRect();
  if (r.width === 0 || r.height === 0) return false;
  if (r.right <= 0 || r.bottom <= 0 || r.left >= window.innerWidth || r.top >= window.innerHeight) return false;
  for (let n = el; n && n.nodeType === 1; n = parentOf(n)) {
    const st = window.getComputedStyle(n);
    if (st.visibility === 'hidden' || st.display === 'none' || st.opacity === '0') return false;
  }
  const cx = Math.min(Math.max(r.left + r.width / 2, 0), window.innerWidth - 1);
  const cy = Math.min(Math.max(r.top + r.height / 2, 0), window.innerHeight - 1);
  return el.getRootNode().elementFromPoint(cx, cy) === el;
}

// Every <iframe> between the frame and the top page must be visible.
async function frameChainVisible(frame) {
  for (let f = frame; f.parentFrame(); f = f.parentFrame()) {
    const owner = await f.frameElement();
    if (!owner) return false;
    try {
      if (!(await owner.evaluate(frameElementVisible))) return false;
    } finally {
      await owner.dispose().catch(() => {});
    }
  }
  return true;
}

// Searches all frames (CMPs such as Sourcepoint render in iframes).
async function findButton(page, kind) {
  for (const frame of page.frames()) {
    let handle;
    try {
      handle = await frame.evaluateHandle(findConsentButton, kind, BUTTON_CFG);
    } catch (e) {
      continue;  // detached or navigating frame
    }
    const el = handle.asElement();
    if (!el) {
      await handle.dispose().catch(() => {});
      continue;
    }
    let visible = false;
    try {
      visible = await frameChainVisible(frame);
    } catch (e) {
      visible = false;
    }
    if (visible) return el;
    await el.dispose().catch(() => {});
  }
  return null;
}

async function hasButton(page, kind) {
  const el = await findButton(page, kind);
  if (!el) return false;
  await el.dispose().catch(() => {});
  return true;
}

async function clickButton(page, kind) {
  const el = await findButton(page, kind);
  if (!el) return false;
  try {
    await el.click();  // trusted mouse click, scrolls into view
  } catch (e) {
    await el.evaluate((node) => node.click());  // covered element - DOM click fallback
  } finally {
    await el.dispose().catch(() => {});
  }
  return true;
}

async function bannerGone(page) {
  return !(await hasButton(page, 'reject')) && !(await hasButton(page, 'accept'));
}

async function settle(page) {
  try {
    await page.waitForNetworkIdle({ idleTime: IDLE_MS, timeout: IDLE_CAP_MS });
  } catch (e) {
    // Busy page (long polling, analytics beacons) - continue with what we have
  }
}

async function waitForBanner(page) {
  const until = Date.now() + BANNER_POLL_MS;
  for (;;) {
    const reject = await hasButton(page, 'reject');
    const accept = await hasButton(page, 'accept');
    if (reject || accept || Date.now() >= until) return { reject, accept };
    await new Promise((r) => setTimeout(r, BANNER_POLL_STEP_MS));
  }
}

async function contextCookies(context, page) {
  // All domains of the context, incl. third-party (_fbp on .facebook.com)
  if (typeof context.cookies === 'function') return context.cookies();
  const cdp = await page.createCDPSession();
  const { cookies } = await cdp.send('Network.getAllCookies');
  return cookies;
}

async function openPage(context, suffixes, userAgent) {
  const page = await context.newPage();
  await page.setUserAgent(userAgent);
  await page.setExtraHTTPHeaders({ 'Accept-Language': ACCEPT_LANGUAGE });
  const state = { requests: [] };
  page.on('request', (req) => {
    if (state.requests.length >= MAX_REQUESTS) return;
    let host;
    try {
      host = new URL(req.url()).hostname.toLowerCase();
    } catch (e) {
      return;
    }
    if (suffixes.some((s) => host === s || host.endsWith('.' + s))) {
      state.requests.push(req.url().slice(0, MAX_URL_LENGTH));
    }
  });
  return {
    page,
    resetRequests() {
      state.requests = [];
    },
    async snapshot() {
      const cookies = await contextCookies(context, page);
      return {
        cookies: cookies.map((c) => ({ name: c.name, domain: c.domain })),
        requests: state.requests.slice(),
      };
    },
  };
}

async function main() {
  const url = process.argv[2];
  if (!url) return { fatal: 'missing url' };
  let config;
  try {
    config = JSON.parse(process.argv[3] || '{}');
  } catch (e) {
    return { fatal: 'invalid config json' };
  }
  const suffixes = (config.tracking_host_suffixes || []).map((s) => String(s).toLowerCase());

  const out = {
    reject_button_found: false,
    accept_button_found: false,
    reject_banner_closed: false,
    baseline: null,
    after_reject: null,
    after_accept: null,
    errors: [],
  };

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--lang=cs-CZ'],
  });
  activeBrowser = browser;
  try {
    // Several CMPs (Cookiebot) hide the banner for bot user agents
    const userAgent = (await browser.userAgent()).replace('HeadlessChrome', 'Chrome');

    // Phase 1 (baseline) + phase 2 (reject) share one fresh context
    const ctx1 = await browser.createBrowserContext();
    const s1 = await openPage(ctx1, suffixes, userAgent);
    await s1.page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
    await settle(s1.page);
    const found = await waitForBanner(s1.page);
    out.reject_button_found = found.reject;
    out.accept_button_found = found.accept;
    out.baseline = await s1.snapshot();

    if (found.reject) {
      try {
        s1.resetRequests();
        // Banner may auto-close between detection and click - then nothing is verified
        if (await clickButton(s1.page, 'reject')) {
          await settle(s1.page);
          out.reject_banner_closed = await bannerGone(s1.page);
          out.after_reject = await s1.snapshot();
        } else {
          out.errors.push('reject: button disappeared before click');
        }
      } catch (e) {
        out.errors.push('reject: ' + errorText(e));
      }
    }
    await ctx1.close();

    // Phase 3 (accept) in a new context - no cookies from phases 1-2
    if (found.accept) {
      try {
        const ctx2 = await browser.createBrowserContext();
        const s2 = await openPage(ctx2, suffixes, userAgent);
        await s2.page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
        await settle(s2.page);
        await waitForBanner(s2.page);
        s2.resetRequests();
        if (await clickButton(s2.page, 'accept')) {
          await settle(s2.page);
          out.after_accept = await s2.snapshot();
        }
        await ctx2.close();
      } catch (e) {
        out.errors.push('accept: ' + errorText(e));
      }
    }
  } finally {
    await browser.close().catch(() => {});
    activeBrowser = null;
  }
  return out;
}

// A half-finished run could look like "no reject button" - report it as fatal.
const watchdog = setTimeout(() => {
  const proc = activeBrowser && activeBrowser.process();
  if (proc) proc.kill('SIGKILL');
  emit({ fatal: 'deadline' }).then(() => process.exit(0));
}, DEADLINE_MS);

main()
  .then((out) => emit(out), (e) => emit({ fatal: errorText(e) }))
  .then(() => {
    clearTimeout(watchdog);
    process.exit(0);
  });
