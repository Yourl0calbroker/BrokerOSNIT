#!/usr/bin/env python3
"""
BrokerOSNIT.py

Extended investigator version — best-effort collection of all available data for a target Instagram
account using an authenticated mobile API session (sessionid). The script:

- Logs into Instagram mobile API (handles 2FA) and obtains session cookies.
- Lets you query a target username or numeric id and collects maximum available data via:
  - web_profile_info (web_profile_info endpoint)
  - users/{userId}/info (private API)
  - users/lookup (advanced lookup)
  - feed/user/{userId}/?count=... (recent media) to extract timestamps and location metadata
  - HEAD requests to profile picture & recent media to get CDN headers (source, last-modified, size)
- Aggregates and displays:
  - Clean Account Summary
  - Full raw JSONs (for inspection)
  - Extended Investigator view: linked accounts, public contact fields, recent activity timestamps,
    inferred last active (heuristic), media locations & probable places, profile-picture source & headers.
- Presents an interactive menu to navigate outputs (Summary / Raw JSON / Advanced Lookup / Media / Investigator / Cookies).

Limitations & Ethics:
- This is best-effort only. Server-side obfuscation (masked emails/phones) cannot be bypassed.
- Some endpoints may be rate-limited or return less data depending on account privacy, API changes, or session privileges.
- Only use against accounts you own or are authorized to inspect or at least dont get caught (;

Dependencies:
    pip install requests stdiomask
    Optional: pip install phonenumbers pycountry

Run:
    python3 BrokerOSNIT.py
"""

from uuid import uuid4
import os
import sys
import re
import time
import queue
import threading
import json
from datetime import datetime, timezone

import requests
import stdiomask

# Optional libs for nicer phone/country display
try:
    import phonenumbers
    from phonenumbers.phonenumberutil import region_code_for_country_code
    import pycountry
    HAS_PHONE = True
except Exception:
    HAS_PHONE = False

# ------------ Config ------------
OTP_TIMEOUT = 60  # seconds to wait for 2FA code / 2FA request timeout
ANIM_BAR_LEN = 30
ANIM_STEP_DELAY = 0.12
MESSAGE = "Your_l0cal_broker"
LOGIN_URL = "https://i.instagram.com/api/v1/accounts/login/"
TWO_FACTOR_URL = "https://i.instagram.com/api/v1/accounts/login_two_factor/"
WEB_PROFILE_INFO = "https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
USER_INFO = "https://i.instagram.com/api/v1/users/{user_id}/info/"
USER_FEED = "https://i.instagram.com/api/v1/feed/user/{user_id}/?count={count}"
LOOKUP = "https://i.instagram.com/api/v1/users/lookup/"
MEDIA_URL_TEMPLATE = "https://i.instagram.com/api/v1/media/{media_id}/info/"
# ---------------------------------

GREEN = "\033[92m"
RESET = "\033[0m"
CLEAR_LINE = "\033[K"

# ---- utilities ----

def label_cookie_name(name):
    n = (name or "").lower()
    if any(k in n for k in ("session", "sess", "sid", "sessionid")):
        return "session"
    if any(k in n for k in ("auth", "token", "jwt", "access")):
        return "auth"
    if any(k in n for k in ("csrf", "csrftoken")):
        return "csrf"
    if any(k in n for k in ("mid", "mid_")):
        return "mid"
    if any(k in n for k in ("ig_", "ds_user")):
        return "instagram"
    if any(k in n for k in ("lang", "locale")):
        return "locale"
    return "other"

def animate_loading(stop_event, message=MESSAGE, bar_len=ANIM_BAR_LEN, step_delay=ANIM_BAR_LEN and ANIM_STEP_DELAY):
    pos = 0
    width = max(3, bar_len // 4)
    revealed = 0
    try:
        while not stop_event.is_set():
            bar = [" "] * bar_len
            for i in range(width):
                idx = (pos + i) % bar_len
                bar[idx] = "="
            pos = (pos + 1) % bar_len
            bar_str = "[" + "".join(bar) + "]"
            line1 = f"{GREEN}{bar_str}{RESET}"
            if revealed < len(message):
                revealed += 1
            line2 = message[:revealed]
            sys.stdout.write("\r" + CLEAR_LINE + line1 + "\n" + CLEAR_LINE + line2 + "\n")
            sys.stdout.flush()
            sys.stdout.write("\033[2A")
            time.sleep(step_delay)
        sys.stdout.write("\r" + CLEAR_LINE + " " * (bar_len + 2) + "\n" + CLEAR_LINE + message + "\n")
        sys.stdout.flush()
    except Exception:
        stop_event.set()

def input_with_timeout(prompt, timeout, stop_event):
    q = queue.Queue()
    def reader(q):
        try:
            s = input(prompt)
            q.put(s)
        except Exception:
            q.put(None)
    th = threading.Thread(target=reader, args=(q,), daemon=True)
    th.start()
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        stop_event.set()
        return None

def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}

def pretty_print_json(obj, label=None):
    if label:
        print(f"\n--- {label} ---")
    try:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except Exception:
        print(str(obj))

def format_phone(public_phone_country_code, public_phone_number):
    if not public_phone_number:
        return None
    try:
        phonenr = f"+{public_phone_country_code} {public_phone_number}" if public_phone_country_code else str(public_phone_number)
        if HAS_PHONE:
            pn = phonenumbers.parse(phonenr)
            countrycode = region_code_for_country_code(pn.country_code)
            country = pycountry.countries.get(alpha_2=countrycode)
            return f"{phonenr} ({country.name})"
        return phonenr
    except Exception:
        return phonenr

def head_request_headers(url, cookies=None, headers=None, timeout=15):
    """Perform a HEAD request and return selected headers. Return dict or None on error."""
    try:
        r = requests.head(url, cookies=cookies, headers=headers or {}, timeout=timeout, allow_redirects=True)
        return {
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type"),
            "content_length": r.headers.get("Content-Length"),
            "last_modified": r.headers.get("Last-Modified"),
            "etag": r.headers.get("ETag"),
            "date": r.headers.get("Date"),
            "server": r.headers.get("Server"),
            "final_url": r.url
        }
    except Exception:
        return None

def epoch_to_iso(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return str(ts)

# ---- Instagram data collectors (best-effort) ----

def get_user_web_profile(username, sessionid=None):
    """Call web_profile_info endpoint (returns web visible profile)."""
    url = WEB_PROFILE_INFO.format(username=username)
    headers = {"User-Agent": "Mozilla/5.0 (compatible)"}
    cookies = {'sessionid': sessionid} if sessionid else None
    try:
        r = requests.get(url, headers=headers, cookies=cookies, timeout=15)
    except Exception as e:
        return {"error": f"network: {e}"}
    if r.status_code == 404:
        return {"error": "not_found", "raw": safe_json(r)}
    return {"raw": safe_json(r)}

def get_user_info_private(user_id, sessionid):
    url = USER_INFO.format(user_id=user_id)
    headers = {"User-Agent": "Instagram 64.0.0.14.96"}
    try:
        r = requests.get(url, headers=headers, cookies={'sessionid': sessionid}, timeout=15)
    except Exception as e:
        return {"error": f"network: {e}"}
    if r.status_code == 429:
        return {"error": "rate_limit", "raw": safe_json(r)}
    return {"raw": safe_json(r)}

def get_feed_media(user_id, sessionid, count=12):
    """Fetch recent media feed for the user (items may include location and timestamps)."""
    url = USER_FEED.format(user_id=user_id, count=count)
    headers = {"User-Agent": "Instagram 64.0.0.14.96"}
    try:
        r = requests.get(url, headers=headers, cookies={'sessionid': sessionid}, timeout=20)
    except Exception as e:
        return {"error": f"network: {e}"}
    if r.status_code == 429:
        return {"error": "rate_limit", "raw": safe_json(r)}
    return {"raw": safe_json(r)}

def do_advanced_lookup(username, sessionid=None):
    data = "signed_body=SIGNATURE." + json.dumps({"q": username, "skip_recovery": "1"}, separators=(",", ":"))
    headers = {
        "Accept-Language": "en-US",
        "User-Agent": "Instagram 101.0.0.15.120",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-IG-App-ID": "124024574287414",
    }
    cookies = {'sessionid': sessionid} if sessionid else None
    try:
        r = requests.post(LOOKUP, headers=headers, data=data, cookies=cookies, timeout=15)
    except Exception as e:
        return {"error": f"network: {e}"}
    try:
        return {"raw": r.json()}
    except Exception:
        return {"raw_text": r.text}

# ---- aggregation / inference helpers ----

def extract_profile_picture_info(user_raw, sessionid):
    """Find profile pic url and gather CDN/HEAD metadata."""
    # check common fields
    url_candidates = []
    # web_profile_info path: data.user.profile_pic_url or profile_pic_url_hd
    try:
        if isinstance(user_raw, dict):
            # try common shapes
            for path in (
                ("profile_pic_url_hd",),
                ("profile_pic_url",),
                ("hd_profile_pic_url_info", "url"),
                ("hd_profile_pic_versions", 0),
            ):
                cur = user_raw
                for p in path:
                    if cur is None:
                        break
                    if isinstance(p, int):
                        cur = cur[p] if isinstance(cur, list) and len(cur) > p else None
                    else:
                        cur = cur.get(p) if isinstance(cur, dict) else None
                if isinstance(cur, str) and cur:
                    url_candidates.append(cur)
                elif isinstance(cur, dict) and cur.get("url"):
                    url_candidates.append(cur.get("url"))
    except Exception:
        pass
    # unique
    url_candidates = [u for i, u in enumerate(url_candidates) if u and u not in url_candidates[:i]]
    results = []
    for u in url_candidates:
        hdrs = head_request_headers(u, cookies={'sessionid': sessionid} if sessionid else None)
        results.append({"url": u, "head": hdrs})
    return results

def infer_locations_from_feed(feed_raw):
    """Extract any location objects or place names in recent feed items."""
    if not isinstance(feed_raw, dict):
        return []
    items = feed_raw.get("items") or feed_raw.get("items", []) or feed_raw.get("items", [])
    # private API often returns 'items' list
    if not items and isinstance(feed_raw.get("items"), list):
        items = feed_raw.get("items")
    if not items:
        # some responses use 'user' -> 'media' etc; try to find any 'items' or 'posts'
        for v in feed_raw.values():
            if isinstance(v, list) and v and isinstance(v[0], dict) and ("taken_at" in v[0] or "id" in v[0]):
                items = v
                break
    locations = []
    last_post_ts = None
    for it in items or []:
        try:
            loc = it.get("location")
            if loc:
                place = {
                    "name": loc.get("name"),
                    "address": loc.get("address", ""),
                    "pk": loc.get("pk") or loc.get("id"),
                    "lat": loc.get("lat"),
                    "lng": loc.get("lng")
                }
                locations.append(place)
            # taken time
            taken = it.get("taken_at") or it.get("device_timestamp") or it.get("timestamp")
            if taken:
                try:
                    ts = int(taken)
                except Exception:
                    # sometimes ISO
                    try:
                        ts = int(datetime.fromisoformat(taken).timestamp())
                    except Exception:
                        ts = None
                if ts:
                    if not last_post_ts or ts > last_post_ts:
                        last_post_ts = ts
        except Exception:
            continue
    # dedupe location names
    uniq = []
    seen = set()
    for l in locations:
        key = (l.get("pk"), l.get("name"))
        if key not in seen:
            seen.add(key)
            uniq.append(l)
    return {"locations": uniq, "last_post_ts": last_post_ts}

def try_get_last_active(user_raw, feed_info):
    """
    Heuristic last-active inference:
    - prefer most recent post timestamp
    - fallback to 'story' or 'last_online' fields in raw JSON if present
    """
    # look for explicit presence fields
    if isinstance(user_raw, dict):
        # search known keys
        for k in ("last_activity_at", "last_online_time", "last_seen", "last_activity"):
            v = user_raw.get(k)
            if v:
                return v
    # from feed
    if feed_info and feed_info.get("last_post_ts"):
        return epoch_to_iso(feed_info["last_post_ts"])
    return None

def gather_linked_accounts(user_raw, lookup_raw):
    """
    Inspect raw JSONs for possible linked accounts, fb connections, connected_accounts, external urls,
    and attempt to list any usernames / ids that appear related.
    """
    linked = {"facebook_pages": [], "connected_accounts": [], "external_urls": [], "emails": [], "phones": []}
    # look through user_raw dict for predictable keys
    def scan_for_keys(obj):
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            lk = str(k).lower()
            try:
                if any(x in lk for x in ("fb", "facebook", "connected", "connected_accounts", "connected_instagram")):
                    linked["connected_accounts"].append({k: v})
                if "external_url" == lk or "external_urls" in lk or "external" in lk:
                    if isinstance(v, str) and v:
                        linked["external_urls"].append(v)
                    elif isinstance(v, list):
                        linked["external_urls"].extend([x for x in v if isinstance(x, str)])
                if "public_email" in lk or "email" in lk:
                    if isinstance(v, str) and v:
                        linked["emails"].append(v)
                if "public_phone" in lk or "phone" in lk:
                    if isinstance(v, str) and v:
                        linked["phones"].append(v)
                if isinstance(v, dict):
                    scan_for_keys(v)
                if isinstance(v, list):
                    for e in v:
                        if isinstance(e, dict):
                            scan_for_keys(e)
            except Exception:
                continue
    scan_for_keys(user_raw or {})
    # lookup_raw may contain obfuscated_email/phone etc
    if isinstance(lookup_raw, dict):
        for k, v in lookup_raw.items():
            lk = str(k).lower()
            if "obfus" in lk or "masked" in lk or "hidden" in lk:
                linked["connected_accounts"].append({k: v})
            if "email" in lk and isinstance(v, str):
                linked["emails"].append(v)
            if "phone" in lk and isinstance(v, str):
                linked["phones"].append(v)
            # facebook pages or linked ig accounts sometimes appear
            if "facebook" in lk or "fb" in lk:
                linked["facebook_pages"].append({k: v})
    # dedupe lists
    for k in linked:
        seen = set()
        out = []
        for item in linked[k]:
            if isinstance(item, dict):
                tup = tuple(sorted(item.items()))
            else:
                tup = item
            if tup not in seen:
                seen.add(tup)
                out.append(item)
        linked[k] = out
    return linked

# ---- High-level orchestrator & UI ----

def print_account_summary(user):
    """Nicely formatted concise summary."""
    print("\n===== Account Summary =====")
    def p(k, label=None):
        if k in user and user.get(k) not in (None, "", [], {}):
            lbl = label or k
            print(f"{lbl:22}: {user.get(k)}")
    p("username", "Username")
    p("full_name", "Full name")
    p("userID", "User ID")
    p("is_private", "Private")
    p("is_verified", "Verified")
    p("is_business", "Business")
    p("follower_count", "Followers")
    p("following_count", "Following")
    p("media_count", "Posts")
    if user.get("external_url"):
        print(f"{'External URL':22}: {user.get('external_url')}")
    bio = user.get("biography")
    if bio:
        print(f"{'Biography':22}:")
        for line in bio.splitlines():
            print(f"  {line}")
    hd = user.get("hd_profile_pic_url_info", {}) if isinstance(user.get("hd_profile_pic_url_info"), dict) else {}
    if hd.get("url"):
        print(f"{'Profile picture':22}: {hd.get('url')}")
    if user.get("public_email"):
        print(f"{'Public email':22}: {user.get('public_email')}")
    if user.get("public_phone_number") or user.get("public_phone_country_code"):
        ph = format_phone(user.get("public_phone_country_code", ""), user.get("public_phone_number", ""))
        if ph:
            print(f"{'Public phone':22}: {ph}")
    print("=" * 28)

def interactive_user_menu_full(user_raw, sessionid, cookie_dict, web_raw=None, lookup_raw=None, feed_raw=None, feed_media_meta=None):
    """
    Provide interactive exploration, now including Extended Investigator (media, linked accounts, profile-pic metadata).
    """
    # Precompute aggregated things
    feed_info = infer_locations_from_feed(feed_raw) if feed_raw else {"locations": [], "last_post_ts": None}
    linked = gather_linked_accounts(user_raw, lookup_raw)
    pic_infos = extract_profile_picture_info(user_raw or web_raw or lookup_raw, sessionid)

    while True:
        print("\nSelect an option:")
        print("  1) Account Summary")
        print("  2) View Full Raw JSON (private API / user object)")
        print("  3) View Web Profile JSON (web_profile_info)")
        print("  4) Advanced Lookup (raw)")
        print("  5) Recent Media & Locations")
        print("  6) Extended Investigator (linked accounts, contacts, profile-pic metadata, last active heuristics)")
        print("  7) View Cookies")
        print("  8) Exit to previous menu")
        choice = input("Enter choice [1-8]: ").strip()
        if choice == "1":
            print_account_summary(user_raw)
        elif choice == "2":
            pretty_print_json(user_raw, label="User JSON (private API)")
        elif choice == "3":
            pretty_print_json(web_raw, label="Web profile JSON")
        elif choice == "4":
            pretty_print_json(lookup_raw, label="Advanced lookup JSON")
        elif choice == "5":
            # show feed items summary
            if not feed_raw or not isinstance(feed_raw, dict):
                print("[!] No feed data available.")
                continue
            items = feed_raw.get("items") or feed_raw.get("items", []) or []
            print(f"\nRecent media count shown: {len(items)} (first {min(12, len(items))})")
            for idx, it in enumerate(items[:12]):
                taken = it.get("taken_at") or it.get("device_timestamp")
                t_iso = epoch_to_iso(taken) if taken else "unknown"
                caption = None
                if isinstance(it.get("caption"), dict):
                    caption = it["caption"].get("text")
                elif it.get("organic_tracking_token"):
                    caption = "(has tracking token)"
                media_id = it.get("id") or it.get("pk")
                print(f"\n[{idx+1}] id: {media_id}")
                print(f"    taken_at: {t_iso}")
                if it.get("location"):
                    loc = it.get("location")
                    print(f"    location: {loc.get('name')}  (lat:{loc.get('lat')}, lng:{loc.get('lng')})")
                # media URLs
                display_url = it.get("image_versions2", {}).get("candidates", [{}])[0].get("url") if it.get("image_versions2") else it.get("carousel_media", [{}])[0].get("image_versions2", {}).get("candidates", [{}])[0].get("url")
                if display_url:
                    print(f"    media_url: {display_url}")
                    # if we fetched HEAD metadata earlier, show it
                    if feed_media_meta and media_id and media_id in feed_media_meta:
                        meta = feed_media_meta[media_id]
                        print(f"    media_head: {meta}")
                if caption:
                    print(f"    caption: {caption[:160] + ('...' if len(caption) > 160 else '')}")
        elif choice == "6":
            # Extended Investigator
            print("\n=== Extended Investigator ===")
            # linked accounts & contacts
            print("\n- Linked / Connected Accounts & Contacts -")
            if any(linked.values()):
                if linked.get("connected_accounts"):
                    print("Connected accounts:")
                    pretty_print_json(linked.get("connected_accounts"))
                if linked.get("facebook_pages"):
                    print("Facebook pages / FB data:")
                    pretty_print_json(linked.get("facebook_pages"))
                if linked.get("external_urls"):
                    print("External URLs:")
                    for u in linked.get("external_urls"):
                        print("  - " + u)
                if linked.get("emails"):
                    print("Emails (raw / obfuscated if present):")
                    for e in linked.get("emails"):
                        print("  - " + str(e))
                if linked.get("phones"):
                    print("Phones (raw / obfuscated if present):")
                    for p in linked.get("phones"):
                        print("  - " + str(p))
            else:
                print("No linked accounts / contacts detected in returned JSON.")

            # last active heuristics
            print("\n- Activity / Last-seen heuristics -")
            last_active = try_get_last_active(user_raw, feed_info)
            if last_active:
                print(f"Last activity (heuristic): {last_active}")
            else:
                print("No explicit last-active info; no recent posts found to infer last activity.")

            # media locations
            print("\n- Recent media locations (inferred) -")
            if feed_info.get("locations"):
                for loc in feed_info["locations"]:
                    print(f"  - {loc.get('name')} (pk={loc.get('pk')}) lat={loc.get('lat')} lng={loc.get('lng')}")
            else:
                print("  No locations found in recent media items.")

            # profile picture metadata
            print("\n- Profile picture & CDN metadata -")
            if pic_infos:
                for p in pic_infos:
                    print(f"  url: {p.get('url')}")
                    if p.get("head"):
                        print(f"    final_url: {p['head'].get('final_url')}")
                        print(f"    status: {p['head'].get('status_code')}  content-type: {p['head'].get('content_type')}  size: {p['head'].get('content_length')}")
                        print(f"    last_modified: {p['head'].get('last_modified')}  etag: {p['head'].get('etag')}")
                    else:
                        print("    (HEAD request failed or not available)")
                    # attempt to parse timestamp from URL if possible (some CDN URLs include time-ish tokens)
                    # show raw URL as source clue
                    # no more deobfuscation attempted
            else:
                print("  No profile picture URL discovered in returned JSON.")

            # show web and lookup raw (compact)
            print("\n- Raw sources available -")
            if web_raw:
                print("web_profile_info: available")
            if lookup_raw:
                print("advanced_lookup: available")
            if feed_raw:
                print("feed/user: available")
            print("=== End Investigator ===")
        elif choice == "7":
            print("\n=== Cookies ===")
            if not cookie_dict:
                print("No cookies available.")
            else:
                for name, value in cookie_dict.items():
                    label = label_cookie_name(name)
                    print(f"{name:20} ({label}) = {value}")
        elif choice == "8":
            break
        else:
            print("[!] Invalid choice. Enter 1-8.")

# ---- Login & main flows (unchanged core, improved integration) ----

def do_login_interactive():
    print(f"[*] Session ID Grabber with 2FA\n")
    username = input(f"[+] Enter Username: ").strip()
    password = stdiomask.getpass(f"[+] Enter Password: ").strip()

    s = requests.Session()
    headers = {
        "Host": "i.instagram.com",
        "X-Ig-Connection-Type": "WiFi",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Ig-Capabilities": "36r/Fx8=",
        "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1)",
        "X-Ig-App-Locale": "en",
        "Accept-Encoding": "gzip, deflate",
    }

    device_id = str(uuid4())
    phone_id = str(uuid4())

    data = {
        "username": username,
        "reg_login": "0",
        "enc_password": f"#PWD_INSTAGRAM:0:&:{password}",
        "device_id": device_id,
        "login_attempt_count": "0",
        "phone_id": phone_id,
    }

    stop_event = threading.Event()
    anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)

    try:
        stop_event.clear()
        anim_thread.start()
        try:
            r = s.post(LOGIN_URL, headers=headers, data=data, timeout=30)
        except Exception as e:
            stop_event.set()
            print("\n\n[!] Network error during login request:", e)
            return None, None
        stop_event.set()
        anim_thread.join(timeout=0.5)

        text = r.text or ""
        j = safe_json(r)

        if 'The password you entered is incorrect' in text or 'bad_password' in text.lower() or \
           (isinstance(j, dict) and j.get('status') == 'fail' and 'password' in j.get('message', '').lower()):
            print("\n\n[!] Wrong password.")
            input("[+] Press Enter to exit...")
            return None, None

        two_factor_required = False
        two_factor_identifier = None
        if isinstance(j, dict) and (j.get("two_factor_required") or j.get("two_factor_info")):
            two_factor_required = True
            info = j.get("two_factor_info") or {}
            two_factor_identifier = info.get("two_factor_identifier") or j.get("two_factor_identifier")
        elif "two_factor_required" in text or "two_factor" in text:
            m = re.search(r'"two_factor_identifier"\s*:\s*"([^"]+)"', text)
            if m:
                two_factor_required = True
                two_factor_identifier = m.group(1)

        if two_factor_required:
            print("\n\n[+] Two-factor authentication required.")
            if two_factor_identifier:
                print(f"    two_factor_identifier: {two_factor_identifier}")
            else:
                print("    (no two_factor_identifier found; we'll still attempt submission)")

            stop_event.clear()
            anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
            anim_thread.start()
            code = input_with_timeout(f"\nEnter 2FA code (you have {OTP_TIMEOUT} seconds): ", OTP_TIMEOUT, stop_event)
            stop_event.set()
            anim_thread.join(timeout=0.5)

            if not code:
                print("\n\n[!] No 2FA code entered (timed out). Exiting.")
                input("[+] Press Enter to exit...")
                return None, None

            two_data = {
                "username": username,
                "verification_code": code,
                "verificationCode": code,
                "device_id": device_id,
                "phone_id": phone_id,
                "trust_this_device": "1",
            }
            if two_factor_identifier:
                two_data["two_factor_identifier"] = two_factor_identifier

            stop_event.clear()
            anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
            anim_thread.start()
            try:
                r2 = s.post(TWO_FACTOR_URL, headers=headers, data=two_data, timeout=OTP_TIMEOUT)
            except Exception as e:
                stop_event.set()
                print("\n\n[!] Network error during 2FA request:", e)
                return None, None
            stop_event.set()
            anim_thread.join(timeout=0.5)

            j2 = safe_json(r2)
            text2 = r2.text or ""
            success = False
            if 'logged_in_user' in text2:
                success = True
            elif isinstance(j2, dict) and (j2.get("status") == "ok" and j2.get("logged_in_user")):
                success = True
            cookie_dict_after = s.cookies.get_dict()
            if not success and any(label_cookie_name(n) == "session" for n in cookie_dict_after.keys()):
                success = True

            if success:
                print("\n\n[+] Logged In Success (2FA).")
            else:
                print("\n\n[!] 2FA response did not indicate success. Full response below:")
                pretty_print_json(j2, label="2FA response JSON")
                displayed = text2[:1500] + ("..." if len(text2) > 1500 else "")
                print("\n(truncated raw text):")
                print(displayed)
                input("[+] Press Enter to exit...")
                return None, None

        else:
            if 'logged_in_user' in text or (isinstance(j, dict) and j.get("status") == "ok" and j.get("logged_in_user")):
                print("\n\n[+] Logged In Success.")
            else:
                print("\n\n[!] Login response did not clearly indicate success. Full response JSON below:")
                pretty_print_json(j, label="Login response JSON")
                displayed = text[:1500] + ("..." if len(text) > 1500 else "")
                print("\n(truncated raw text):")
                print(displayed)
                input("[+] Press Enter to exit...")
                return None, None

        print("\n\nCookies found:")
        cookie_dict = s.cookies.get_dict()
        if not cookie_dict:
            print("  No cookies found in session.")
        else:
            for name, value in cookie_dict.items():
                label = label_cookie_name(name)
                print(f"  - {name} ({label}) = {value}")

        return s, cookie_dict

    finally:
        try:
            stop_event.set()
        except Exception:
            pass

def prompt_and_scrape(session_cookies):
    yn = input("\n[?] Do you want to scrape an account using the session id? (y/N): ").strip().lower()
    if yn != "y":
        print("[*] Exiting.")
        return

    sessionid = session_cookies.get("sessionid")
    if not sessionid:
        for k, v in session_cookies.items():
            if label_cookie_name(k) in ("session", "instagram"):
                sessionid = v
                break

    if not sessionid:
        sessionid = input("[!] No sessionid cookie found automatically. Enter sessionid manually: ").strip()
        if not sessionid:
            print("[!] No sessionid provided. Cannot proceed.")
            return

    target = input("[+] Enter target username or numeric id: ").strip()
    if not target:
        print("[!] No target provided. Exiting.")
        return

    # determine search type
    if target.isdigit():
        search_type = "id"
        user_id = target
        username = None
    else:
        search_type = "username"
        username = target
        user_id = None

    # gather raw sources
    web_raw = None
    user_raw = None
    lookup_raw = None
    feed_raw = None
    feed_media_meta = {}

    # 1) web_profile_info (helps get user id and web-visible fields)
    if username:
        stop = threading.Event()
        t = threading.Thread(target=animate_loading, args=(stop,), daemon=True)
        stop.clear(); t.start()
        web_raw_res = get_user_web_profile(username, sessionid)
        stop.set(); t.join(timeout=0.5)
        web_raw = web_raw_res.get("raw") or web_raw_res.get("raw_text")
        # try to obtain user_id from web_raw
        try:
            if isinstance(web_raw, dict) and web_raw.get("data") and web_raw["data"].get("user"):
                user_id = web_raw["data"]["user"].get("id") or user_id
        except Exception:
            pass

    # 2) private user info (users/{id}/info/)
    if user_id:
        stop = threading.Event()
        t = threading.Thread(target=animate_loading, args=(stop,), daemon=True)
        stop.clear(); t.start()
        user_info_res = get_user_info_private(user_id, sessionid)
        stop.set(); t.join(timeout=0.5)
        user_raw = user_info_res.get("raw") or user_info_res.get("error")
        # if user_raw contains username and username not set, set it
        if isinstance(user_raw, dict):
            username = username or user_raw.get("user", {}).get("username") or user_raw.get("user", {}).get("external_id")
            # some variants return 'user' wrapper
            if user_raw.get("user"):
                user_raw = user_raw.get("user")
    else:
        print("[!] Could not resolve user id from web_profile_info; try using a username instead.")
        return

    # 3) advanced lookup
    stop = threading.Event()
    t = threading.Thread(target=animate_loading, args=(stop,), daemon=True)
    stop.clear(); t.start()
    lookup_res = do_advanced_lookup(username, sessionid)
    stop.set(); t.join(timeout=0.5)
    lookup_raw = lookup_res.get("raw") or lookup_res.get("raw_text")

    # 4) recent media feed to gather locations & timestamps
    stop = threading.Event()
    t = threading.Thread(target=animate_loading, args=(stop,), daemon=True)
    stop.clear(); t.start()
    feed_res = get_feed_media(user_id, sessionid, count=12)
    stop.set(); t.join(timeout=0.5)
    feed_raw = feed_res.get("raw") or {}

    # Attempt to collect HEAD metadata for media items in feed
    try:
        items = feed_raw.get("items") or []
        for it in items[:12]:
            media_id = it.get("id") or it.get("pk")
            # try to find display url candidate
            display_url = None
            if isinstance(it.get("image_versions2"), dict):
                candidates = it["image_versions2"].get("candidates", [])
                if candidates:
                    display_url = candidates[0].get("url")
            # carousel case
            if not display_url and isinstance(it.get("carousel_media"), list) and it["carousel_media"]:
                cm = it["carousel_media"][0]
                if isinstance(cm.get("image_versions2"), dict):
                    display_url = cm["image_versions2"].get("candidates", [{}])[0].get("url")
            if display_url and media_id:
                hdr = head_request_headers(display_url, cookies={'sessionid': sessionid})
                feed_media_meta[media_id] = hdr
    except Exception:
        pass

    # Create a clean user dict for summary: normalize fields
    if not isinstance(user_raw, dict):
        print("[!] Unexpected user object received; showing raw JSONs for inspection.")
        pretty_print_json(user_raw, label="User raw")
        return

    # add some normalized convenience keys if missing
    if "username" not in user_raw and username:
        user_raw["username"] = username
    if "userID" not in user_raw and user_id:
        user_raw["userID"] = str(user_id)

    # Launch interactive exploration with all collected sources
    interactive_user_menu_full(user_raw, sessionid, session_cookies, web_raw=web_raw, lookup_raw=lookup_raw, feed_raw=feed_raw, feed_media_meta=feed_media_meta)

def main():
    s, cookies = do_login_interactive()
    if s is None:
        return
    prompt_and_scrape(cookies)
    input("\n[+] Done. Press Enter to exit...")

if __name__ == "__main__":
    main()
