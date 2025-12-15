#!/usr/bin/env python3
"""
BrokerOSNIT.py

Changes:
- When performing the "advanced lookup" and the user/info retrieval, the script now prints
  the full raw JSON returned by the API (pretty-printed) so you can see the maximum available
  data. Server-side obfuscation (e.g. masked emails/phones) cannot be bypassed by this script;
  however this will expose any un-obfuscated fields returned by the API.
- All other behavior (login, 2FA prompt, animation, scraping flow) is preserved.

Usage:
    python3 BrokerOSNIT.py

Dependencies:
    pip install requests stdiomask
    Optional: pip install phonenumbers pycountry
"""
from uuid import uuid4
import os
import sys
import re
import time
import queue
import threading
import json

import requests
import stdiomask

# Optional deps
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
# ---------------------------------

GREEN = "\033[92m"
RESET = "\033[0m"
CLEAR_LINE = "\033[K"


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


def animate_loading(stop_event, message=MESSAGE, bar_len=ANIM_BAR_LEN, step_delay=ANIM_STEP_DELAY):
    """
    Animate a moving green bar and reveal `message` one letter at a time beneath it.
    Runs until stop_event is set.
    """
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
        # final print: reveal message fully and stop
        sys.stdout.write("\r" + CLEAR_LINE + " " * (bar_len + 2) + "\n" + CLEAR_LINE + message + "\n")
        sys.stdout.flush()
    except Exception:
        stop_event.set()


def input_with_timeout(prompt, timeout, stop_event):
    """
    Get input from user with timeout seconds. Returns None if timed out.
    If stop_event is set while waiting, returns None.
    """
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
        res = q.get(timeout=timeout)
        return res
    except queue.Empty:
        # signal any animation to stop
        stop_event.set()
        return None


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}


# ----------------- Instagram API helper functions -----------------


def getUserId(username, sessionsId):
    headers = {"User-Agent": "iphone_ua", "x-ig-app-id": "936619743392459"}
    try:
        api = requests.get(
            f'https://i.instagram.com/api/v1/users/web_profile_info/?username={username}',
            headers=headers,
            cookies={'sessionid': sessionsId},
            timeout=20
        )
    except requests.RequestException as e:
        return {"id": None, "error": f"Network error: {e}"}
    try:
        if api.status_code == 404:
            return {"id": None, "error": "User not found"}
        id = api.json()["data"]['user']['id']
        return {"id": id, "error": None, "raw": api.json()}
    except Exception:
        return {"id": None, "error": "Rate limit or invalid response", "raw_text": api.text if 'api' in locals() else ""}


def getInfo(search, sessionId, searchType="username"):
    if searchType == "username":
        data = getUserId(search, sessionId)
        if data["error"]:
            return data
        userId = data["id"]
    else:
        try:
            userId = str(int(search))
        except ValueError:
            return {"user": None, "error": "Invalid ID"}

    try:
        response = requests.get(
            f'https://i.instagram.com/api/v1/users/{userId}/info/',
            headers={'User-Agent': 'Instagram 64.0.0.14.96'},
            cookies={'sessionid': sessionId},
            timeout=20
        )
        if response.status_code == 429:
            return {"user": None, "error": "Rate limit", "raw": safe_json(response)}

        response.raise_for_status()
        info_user = response.json().get("user")
        if not info_user:
            return {"user": None, "error": "Not found", "raw": safe_json(response)}

        info_user["userID"] = userId
        return {"user": info_user, "error": None, "raw": safe_json(response)}

    except requests.exceptions.RequestException as e:
        return {"user": None, "error": f"Network error: {e}"}


from urllib.parse import quote_plus
from json import dumps, decoder


def advanced_lookup(username):
    """
    Post to get obfuscated login infos. Return raw JSON (if any) in the result so caller can
    inspect everything the API returned.
    """
    data = "signed_body=SIGNATURE." + quote_plus(dumps(
        {"q": username, "skip_recovery": "1"},
        separators=(",", ":")
    ))
    try:
        api = requests.post(
            'https://i.instagram.com/api/v1/users/lookup/',
            headers={
                "Accept-Language": "en-US",
                "User-Agent": "Instagram 101.0.0.15.120",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-IG-App-ID": "124024574287414",
                "Accept-Encoding": "gzip, deflate",
                "Host": "i.instagram.com",
                "Connection": "keep-alive",
                "Content-Length": str(len(data))
            },
            data=data,
            timeout=20
        )
    except requests.RequestException as e:
        return {"user": None, "error": f"network: {e}"}

    try:
        parsed = api.json()
        return {"user": parsed, "error": None, "raw": parsed}
    except decoder.JSONDecodeError:
        return {"user": None, "error": "rate limit or invalid json", "raw_text": api.text}


# ----------------- Utility pretty print -----------------


def pretty_print_json(obj, label=None):
    if label:
        print(f"\n--- {label} ---")
    try:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except Exception:
        print(str(obj))


# ----------------- Main flow -----------------


def do_login_interactive():
    """
    Perform login to Instagram mobile API with 2FA handling.
    Returns a requests.Session() (logged-in) and a dict of cookies, or (None, None) on failure.
    """
    print(f"[*] Session ID Grabber with 2FA\n")

    username = input(f"[+] Enter Username: ").strip()
    password = stdiomask.getpass(f"[+] Enter Password: ").strip()

    s = requests.Session()

    headers = {
        "Host": "i.instagram.com",
        "X-Ig-Connection-Type": "WiFi",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Ig-Capabilities": "36r/Fx8=",
        "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
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
        # initial login request with animation (30s timeout for initial login)
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

        # Common checks
        if 'The password you entered is incorrect' in text or 'bad_password' in text.lower() or \
           (isinstance(j, dict) and j.get('status') == 'fail' and 'password' in j.get('message', '').lower()):
            print("\n\n[!] Wrong password.")
            input("[+] Press Enter to exit...")
            return None, None

        # Detect two-factor required
        two_factor_required = False
        two_factor_identifier = None
        # support boolean/string detail in response
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

            # Prompt for 2FA code with animation and timeout (OTP_TIMEOUT)
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

            # Prepare payload. Include both common field names to be robust.
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

            # POST two-factor verification (use 60s timeout as requested)
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

            # Determine success:
            success = False
            # 1) direct indicator in response
            if 'logged_in_user' in text2:
                success = True
            elif isinstance(j2, dict) and (j2.get("status") == "ok" and j2.get("logged_in_user")):
                success = True
            # 2) session cookie present
            cookie_dict_after = s.cookies.get_dict()
            if not success and any(label_cookie_name(n) == "session" for n in cookie_dict_after.keys()):
                success = True

            if success:
                print("\n\n[+] Logged In Success (2FA).")
            else:
                # Provide the full 2FA response JSON to help diagnose / show maximum info
                print("\n\n[!] 2FA response did not indicate success. Full response below:")
                pretty_print_json(j2, label="2FA response JSON")
                displayed = text2[:1500] + ("..." if len(text2) > 1500 else "")
                print("\n(truncated raw text):")
                print(displayed)
                input("[+] Press Enter to exit...")
                return None, None

        else:
            # Not 2FA required; check if login success
            if 'logged_in_user' in text or (isinstance(j, dict) and j.get("status") == "ok" and j.get("logged_in_user")):
                print("\n\n[+] Logged In Success.")
            else:
                # unknown response - show full JSON to reveal maximum info
                print("\n\n[!] Login response did not clearly indicate success. Full response JSON below:")
                pretty_print_json(j, label="Login response JSON")
                displayed = text[:1500] + ("..." if len(text) > 1500 else "")
                print("\n(truncated raw text):")
                print(displayed)
                input("[+] Press Enter to exit...")
                return None, None

        # Print session cookies (all) and label them
        print("\n\nCookies found:")
        cookie_dict = s.cookies.get_dict()
        if not cookie_dict:
            print("  No cookies found in session. The server may set cookies only via JS or different domain.")
        else:
            for name, value in cookie_dict.items():
                label = label_cookie_name(name)
                meta = None
                for c in s.cookies:
                    if c.name == name:
                        meta = c
                        break
                domain = getattr(meta, "domain", "")
                path = getattr(meta, "path", "")
                expires = getattr(meta, "expires", "")
                secure = getattr(meta, "secure", False)
                rest = f"domain: {domain}   path: {path}   expires: {expires}   secure: {secure}"
                print(f"  - {name} = {value}")
                print(f"      {rest}")
                print(f"      label: {label}")

        return s, cookie_dict

    finally:
        try:
            stop_event.set()
        except Exception:
            pass


def prompt_and_scrape(session_cookies):
    """
    Ask the user if they'd like to scrape an account. If yes, prompt for target (username or id)
    and run getInfo/advanced_lookup using the sessionid from session_cookies.

    Shows the broker animation while performing the network calls for scraping and prints
    the full raw JSON returned by each API call so you can inspect maximum data.
    """
    yn = input("\n[?] Do you want to scrape an account using the session id? (y/N): ").strip().lower()
    if yn != "y":
        print("[*] Exiting.")
        return

    # Determine sessionid
    sessionid = session_cookies.get("sessionid")
    if not sessionid:
        # try other cookie names that might contain session-like info
        for k, v in session_cookies.items():
            if label_cookie_name(k) == "session" or label_cookie_name(k) == "instagram":
                sessionid = v
                break

    if not sessionid:
        sessionid = input("[!] No sessionid cookie found automatically. Enter sessionid manually: ").strip()
        if not sessionid:
            print("[!] No sessionid provided. Cannot proceed.")
            return

    # Ask for target
    target = input("[+] Enter target username or numeric id: ").strip()
    if not target:
        print("[!] No target provided. Exiting.")
        return

    # Auto-detect whether it's an id (all digits)
    if target.isdigit():
        search_type = "id"
    else:
        search_type = "username"

    print(f"[*] Looking up {target} ({search_type}) ...")

    # Start broker animation while performing getInfo
    stop_event = threading.Event()
    anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
    stop_event.clear()
    anim_thread.start()

    result = getInfo(target, sessionid, searchType=search_type)

    # Stop animation and wait briefly for refresh
    stop_event.set()
    anim_thread.join(timeout=0.5)

    if result.get("error"):
        print(f"[!] Error: {result['error']}")
        # show raw response if present
        if "raw" in result:
            pretty_print_json(result["raw"], label="Raw getInfo response")
        if "raw_text" in result:
            print("\nRaw text:")
            print(result["raw_text"][:2000])
        return
    user = result.get("user")
    if not user:
        print("[!] No user data returned.")
        if "raw" in result:
            pretty_print_json(result["raw"], label="Raw getInfo response")
        return

    # Pretty-print the full user JSON (maximum info)
    pretty_print_json(user, label="User JSON (full)")

    # Print some common fields as earlier but also list every key/value under the user dict
    print("\n-- Key summary (from returned user JSON) --")
    for k in sorted(user.keys()):
        v = user.get(k)
        # For nested structures, show compact JSON
        if isinstance(v, (dict, list)):
            try:
                compact = json.dumps(v, ensure_ascii=False)
            except Exception:
                compact = str(v)
            print(f"{k}: {compact}")
        else:
            print(f"{k}: {v}")

    # advanced lookup with animation
    print("\n[*] Performing advanced lookup (raw response will be shown)...")
    stop_event = threading.Event()
    anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
    stop_event.clear()
    anim_thread.start()

    other_infos = advanced_lookup(user.get("username", ""))

    stop_event.set()
    anim_thread.join(timeout=0.5)

    # Print full advanced lookup raw JSON (or raw text) to reveal as much as possible
    if other_infos.get("error"):
        print(f"[!] advanced_lookup error: {other_infos['error']}")
        if "raw_text" in other_infos:
            print("\nRaw advanced_lookup text (truncated):")
            print(other_infos["raw_text"][:2000])
        return

    # Show the entire payload returned by the lookup endpoint
    pretty_print_json(other_infos.get("raw"), label="Advanced lookup (full raw JSON)")

    # If the response contains obfuscated fields, show them explicitly (raw)
    if isinstance(other_infos.get("raw"), dict):
        obf_email = None
        obf_phone = None
        # Attempt common paths where obfuscated info appears
        # We print anything that looks like 'obfuscated' in keys
        found = False
        for key, val in other_infos["raw"].items():
            if "obfus" in str(key).lower() or "email" in str(key).lower() or "phone" in str(key).lower():
                found = True
                print(f"{key}: {val}")
        if not found:
            print("(No explicit obfuscated fields detected at top-level of lookup response.)")

    print("-" * 24)
    print("Profile Picture        : " + str(user.get("hd_profile_pic_url_info", {}).get("url", "")))


def main():
    s, cookies = do_login_interactive()
    if s is None:
        return

    prompt_and_scrape(cookies)

    input("\n[+] Done. Press Enter to exit...")


if __name__ == "__main__":
    main()
