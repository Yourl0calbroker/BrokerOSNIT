#!/usr/bin/env python3
"""
BrokerOSNIT.py

Fixed behavior for 2FA:
- When Instagram returns a two-factor challenge the script now prompts the user,
  submits the provided code to the two-factor endpoint, waits for the response,
  and proceeds to print cookies and offer scraping.

Usage:
    BrokerOSNIT.py

Dependencies:
    pip install requests stdiomask
    Optional: pip install phonenumbers pycountry
"""

import os
import sys
import re
import time
import queue
import threading
from uuid import uuid4

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
OTP_TIMEOUT = 60  # seconds to wait for 2FA code
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
        # ensure stop_event is set on any error to prevent orphaned threads
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


# ----------------- Instagram API helper functions (from provided scraper) -----------------

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
        return {"id": id, "error": None}
    except ValueError:
        return {"id": None, "error": "Rate limit or invalid response"}


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
            return {"user": None, "error": "Rate limit"}

        response.raise_for_status()
        info_user = response.json().get("user")
        if not info_user:
            return {"user": None, "error": "Not found"}

        info_user["userID"] = userId
        return {"user": info_user, "error": None}

    except requests.exceptions.RequestException:
        return {"user": None, "error": "Not found"}


from urllib.parse import quote_plus
from json import dumps, decoder


def advanced_lookup(username):
    """
    Post to get obfuscated login infos
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
    except requests.RequestException:
        return ({"user": None, "error": "network"})

    try:
        return ({"user": api.json(), "error": None})
    except decoder.JSONDecodeError:
        return ({"user": None, "error": "rate limit"})


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
        # initial login request with animation
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
        if 'The password you entered is incorrect' in text or 'bad_password' in text.lower() or (j.get('status') == 'fail' and 'password' in j.get('message', '').lower()):
            print("\n\n[!] Wrong password.")
            input("[+] Press Enter to exit...")
            return None, None

        # Detect two-factor required (handle truthy strings as well)
        two_factor_required = False
        two_factor_identifier = None
        # support both boolean and string indicators
        if j.get("two_factor_required") or j.get("two_factor_info"):
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

            # Prompt for 2FA code with animation and timeout
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

            # Prepare payload. Instagram's two_factor endpoint expects 'verification_code' and two_factor_identifier
            two_data = {
                "username": username,
                "verification_code": code,
                "device_id": device_id,
                "phone_id": phone_id,
                "trust_this_device": "1",
            }
            if two_factor_identifier:
                two_data["two_factor_identifier"] = two_factor_identifier

            # POST two-factor verification (animation while network call runs)
            stop_event.clear()
            anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
            anim_thread.start()
            try:
                r2 = s.post(TWO_FACTOR_URL, headers=headers, data=two_data, timeout=30)
            except Exception as e:
                stop_event.set()
                print("\n\n[!] Network error during 2FA request:", e)
                return None, None
            stop_event.set()
            anim_thread.join(timeout=0.5)

            j2 = safe_json(r2)
            text2 = r2.text or ""

            # Consider login success if 'logged_in_user' present or status ok and cookies set
            success = False
            if 'logged_in_user' in text2:
                success = True
            elif isinstance(j2, dict) and (j2.get("status") == "ok" and j2.get("logged_in_user")):
                success = True
            # Also accept presence of sessionid cookie set in session
            cookie_dict_after = s.cookies.get_dict()
            if not success and any(label_cookie_name(n) == "session" for n in cookie_dict_after.keys()):
                success = True

            if success:
                print("\n\n[+] Logged In Success (2FA).")
            else:
                # Helpful debug output for failure
                if isinstance(j2, dict) and j2.get("status") == "fail":
                    print("\n\n[!] 2FA submission failed:", j2.get("message", text2))
                else:
                    print("\n\n[!] 2FA response did not indicate success. Response (truncated):")
                    displayed = text2[:1500] + ("..." if len(text2) > 1500 else "")
                    print(displayed)
                input("[+] Press Enter to exit...")
                return None, None

        else:
            # Not 2FA required; check if login success
            if 'logged_in_user' in text or (isinstance(j, dict) and j.get("status") == "ok" and j.get("logged_in_user")):
                print("\n\n[+] Logged In Success.")
            else:
                # unknown response
                print("\n\n[!] Login response (truncated):")
                displayed = text[:1500] + ("..." if len(text) > 1500 else "")
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
                # Attempt to get more cookie metadata if available in cookiejar
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

    Shows the broker animation while performing the network calls for scraping.
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
        return
    user = result.get("user")
    if not user:
        print("[!] No user data returned.")
        return

    # Pretty-print results similar to the provided script
    print("\nInformations about     : " + user.get("username", ""))
    print("userID                 : " + str(user.get("userID", "")))
    print("Full Name              : " + user.get("full_name", ""))
    print("Verified               : " + str(user.get('is_verified', False)) + " | Is business Account : " + str(user.get("is_business", False)))
    print("Is private Account     : " + str(user.get("is_private", False)))
    print("Follower               : " + str(user.get("follower_count", 0)) + " | Following : " + str(user.get("following_count", 0)))
    print("Number of posts        : " + str(user.get("media_count", 0)))
    if user.get("external_url"):
        print("External url           : " + user.get("external_url"))
    print("IGTV posts             : " + str(user.get("total_igtv_videos", 0)))
    bio = user.get("biography", "")
    if bio:
        # keep formatting on multi-line biography
        print("Biography              : " + (f"""\n{" " * 25}""").join(bio.split("\n")))
    print("Linked WhatsApp        : " + str(user.get("is_whatsapp_linked", False)))
    print("Memorial Account       : " + str(user.get("is_memorialized", False)))
    print("New Instagram user     : " + str(user.get("is_new_to_instagram", False)))

    if "public_email" in user.keys() and user["public_email"]:
        print("Public Email           : " + user["public_email"])

    if "public_phone_number" in user.keys() and str(user["public_phone_number"]):
        phonenr = "+" + str(user.get("public_phone_country_code", "")) + " " + str(user.get("public_phone_number", ""))
        if HAS_PHONE:
            try:
                pn = phonenumbers.parse(phonenr)
                countrycode = region_code_for_country_code(pn.country_code)
                country = pycountry.countries.get(alpha_2=countrycode)
                phonenr = phonenr + " ({}) ".format(country.name)
            except Exception:
                pass
        print("Public Phone number    : " + phonenr)

    # advanced lookup with animation
    print("\n[*] Performing advanced lookup (may reveal obfuscated email/phone)...")
    stop_event = threading.Event()
    anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
    stop_event.clear()
    anim_thread.start()

    other_infos = advanced_lookup(user.get("username", ""))

    stop_event.set()
    anim_thread.join(timeout=0.5)

    if other_infos.get("error") == "rate limit":
        print("Rate limit: please wait a few minutes before you try again")
    elif other_infos.get("user") and isinstance(other_infos["user"], dict) and "message" in other_infos["user"].keys():
        msg = other_infos["user"]["message"]
        print("Lookup message         : " + str(msg))
    else:
        obf = other_infos.get("user", {})
        if isinstance(obf, dict):
            if obf.get("obfuscated_email"):
                print("Obfuscated email       : " + str(obf.get("obfuscated_email")))
            else:
                print("No obfuscated email found")
            if obf.get("obfuscated_phone"):
                print("Obfuscated phone       : " + str(obf.get("obfuscated_phone")))
            else:
                print("No obfuscated phone found")
        else:
            # If API returned JSON not in expected dict format, just print a short note
            print("Advanced lookup returned unexpected data (possibly rate-limited or blocked).")

    print("-" * 24)
    print("Profile Picture        : " + str(user.get("hd_profile_pic_url_info", {}).get("url", "")))


def main():
    s, cookies = do_login_interactive()
    if s is None:
        return

    # Ask whether to scrape using obtained cookies
    prompt_and_scrape(cookies)

    input("\n[+] Done. Press Enter to exit...")


if __name__ == "__main__":
    main()
