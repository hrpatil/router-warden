# Router Warden

A local Tauri desktop app for managing website access rules by device on a home network.

## Development

Install dependencies and start the Svelte app:

```powershell
npm install
npm run dev
```

Run the desktop app with Tauri:

```powershell
npm run tauri dev
```

Run checks and a production frontend build:

```powershell
npm run check
npm run build
```

## Current Scope

- Device records are loaded from the authenticated router session; there is no sample-device fallback. The router may retain disconnected devices, so `LastConnection` is shown instead of claiming every listed device is online.
- New rules are saved locally as previews until explicitly applied to the router.
- The ZTE F670L v9.0 interface was confirmed to offer per-device `URL Black List` and `URL White List` parental-control actions.
- The Router screen can make a read-only HTTP reachability check to a private IPv4 address.
- Router login follows the F670L challenge-hash flow. The password is not persisted; the cookie-backed session stays in Rust memory until disconnect or app exit.
- A saved rule requires 1-5 domains, a device label, and a MAC address. The rule form has a YouTube app preset (`youtube.com`, `youtubei.googleapis.com`, `googlevideo.com`, `ytimg.com`, `youtube.googleapis.com`). Applying a rule requires a separate confirmation and creates one all-days, all-day URL Black List profile on the router with those domains.
- Choose a live device row or enter its MAC. Verify every submitted rule in Parental Controls because an HTTP response alone is not proof that the router accepted it.
- The Rules page lists the profiles stored on the router and can delete them after a confirmation. Removing a local record never changes the router.

Do not store router credentials in frontend code or commit them. Keep the router admin page on your trusted LAN; this firmware uses plain HTTP locally, so its session traffic is not encrypted in transit.

## ZTE F670L v9.0 Apply protocol notes

Verified against firmware `V9.0.10P18N3D`. The native `apply_url_blacklist` command in `src-tauri/src/lib.rs` depends on these behaviors:

- Rules are posted to `/?_type=menuData&_tag=firewall_parentctrl_lua.lua` as a form body ending in `&_sessionTOKEN=<token>`.
- The `Check` header is the base64 RSA (PKCS#1 v1.5) encryption of the lowercase hex SHA-256 of the exact body sent. The public key is the one embedded in the router's `asyEncode()`.
- `_sessionTmpToken` is a `\xNN`-escaped literal written into every page the router serves, and only the most recently issued token is valid. Page responses contain several occurrences; use the last assignment.
- Before posting, the app loads the Parental Controls page (`/?_type=menuView&_tag=parentCtrl&Menu3Location=0`) and its data endpoint, and uses the token from that page. Without that step the router answers `SessionTimeout` even though the cookie, token, and `Check` header are all valid.
- `SessionTimeout` is also returned for a missing or wrong `Check` header or a missing cookie. A wrong token gives a "page expired" error instead.
- A profile holds at most 5 URLs, sent as `URLCnt` plus `URL0`-`URL4` (unused slots are `NULL`). Profile names are limited to 10 characters.
- Blocking a whole device uses `FilterMode=NotAllowed` ("Ban Internet Access") and omits all `URL*` fields, as the router's own form does.
- Schedules use `Week` (a 7-bit mask in Sun..Sat order with Sunday as the highest bit, so every day is 127 and Mon-Fri is 62) plus `StartHour`, `StartMin`, `EndHour`, `EndMin`. The app requires the end to be after the start on the same day; whether the router accepts overnight windows is unverified, so use two rules instead.
- Success is `IF_ERRORSTR=SUCC` in the XML response; anything else is shown as a failure and the rule stays retryable.
- Profiles are listed from the same data endpoint (`GET` after loading the Parental Controls page) and deleted with `IF_ACTION=Delete&_InstID=<id>&_sessionTOKEN=<token>`. Profile IDs are strings such as `DEV.PCUser2`, not numbers.
- The router appears to allow one admin session at a time. Signing in through the browser can invalidate the app's session, and the app keeps its session alive with a periodic page request while connected.
- Router-side URL blocking matches the listed hostnames only, so apps that use other hosts or encrypted DNS may still get through. Verify on the device after applying.