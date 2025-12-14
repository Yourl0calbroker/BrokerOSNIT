#!/usr/bin/env python3
import requests
import os
import stdiomask
import sys
import threading
import time
import queue
import re
from uuid import uuid4

# ------------ Config ------------
OTP_TIMEOUT = 60  # seconds to wait for 2FA code
ANIM_BAR_LEN = 30
ANIM_STEP_DELAY = 0.12
REVEAL_DELAY = 0.12
MESSAGE = "Your_l0cal_broker"
LOGIN_URL = "https://i.instagram.com/api/v1/accounts/login/"
TWO_FACTOR_URL = "https://i.instagram.com/api/v1/accounts/login_two_factor/"
# ---------------------------------

os.system('title  ')
os.system('cls||clear')

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

def animate_loading(stop_event, message=MESSAGE, bar_len=ANIM_BAR_LEN, step_delay=ANIM_STEP_DELAY, reveal_delay=REVEAL_DELAY):
    """
    Animate a moving green bar and reveal `message` one letter at a time beneath it.
    Runs until stop_event is set.
    """
    pos = 0
    width = max(3, bar_len // 4)
    revealed = 0
    try:
        while not stop_event.is_set():
            # build moving segment
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
            # print and move cursor up 2 lines so next overwrite works
            sys.stdout.write("\r" + CLEAR_LINE + line1 + "\n" + CLEAR_LINE + line2 + "\n")
            sys.stdout.flush()
            sys.stdout.write("\033[2A")
            time.sleep(step_delay)
        # when stopping, clear and print final message fully revealed
        sys.stdout.write("\r" + CLEAR_LINE + " " * (bar_len + 2) + "\n" + CLEAR_LINE + message + "\n")
        sys.stdout.flush()
    except KeyboardInterrupt:
        stop_event.set()
        return

def input_with_timeout(prompt, timeout, stop_event):
    """
    Get input from user with timeout seconds.
    Returns None if timed out. If stopped by stop_event, returns None.
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
        stop_event.set()  # signal animation or other waiters
        return None

def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}

def main():
    print(f"[*] Session ID Grabber 2FA")
    print("")

    username = input(f"[+] Enter Username: ")
    password = stdiomask.getpass(f"[+] Enter Password: ")

    # Create a persistent session so cookies are stored across requests
    s = requests.Session()

    # sensible headers for Instagram mobile API; avoid hardcoding content-length
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
        # Start animation while we make the initial login request
        stop_event.clear()
        anim_thread.start()
        try:
            r = s.post(LOGIN_URL, headers=headers, data=data, timeout=30)
        except Exception as e:
            stop_event.set()
            print("\n\n[!] Network error during login request:", e)
            return
        stop_event.set()
        anim_thread.join(timeout=0.5)

        text = r.text or ""
        j = safe_json(r)

        # Common checks
        if 'The password you entered is incorrect' in text or 'bad_password' in text.lower() or j.get('status') == 'fail' and j.get('message', '').lower().find('password') != -1:
            print("\n\n[!] Wrong password.")
            input("[+] Press Enter to exit...")
            return

        # Detect two-factor required
        two_factor_required = False
        two_factor_identifier = None
        if j.get("two_factor_required") or j.get("two_factor_info"):
            two_factor_required = True
            info = j.get("two_factor_info") or {}
            two_factor_identifier = info.get("two_factor_identifier") or j.get("two_factor_identifier")
        # Some responses include 'two_factor_required' as string or in text
        elif "two_factor_required" in text or "two_factor" in text:
            # try to extract identifier with regex as fallback
            m = re.search(r'"two_factor_identifier"\s*:\s*"([^"]+)"', text)
            if m:
                two_factor_required = True
                two_factor_identifier = m.group(1)

        if two_factor_required:
            print("\n\n[+] Two-factor authentication required.")
            if two_factor_identifier:
                print(f"    two_factor_identifier: {two_factor_identifier}")
            else:
                print("    (no two_factor_identifier found; the code prompt will still be attempted)")

            # Prompt for 2FA code with timeout while showing animation
            stop_event.clear()
            anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
            anim_thread.start()

            code = input_with_timeout(f"\nEnter 2FA code (you have {OTP_TIMEOUT} seconds): ", OTP_TIMEOUT, stop_event)

            stop_event.set()
            anim_thread.join(timeout=0.5)

            if not code:
                print("\n\n[!] No 2FA code entered (timed out). Exiting.")
                input("[+] Press Enter to exit...")
                return

            # Prepare payload for two-factor submission - include a couple of possible field names to be safe
            two_data = {
                "username": username,
                "verificationCode": code,
                "verification_code": code,
                "device_id": device_id,
                "two_factor_identifier": two_factor_identifier or "",
                "trust_this_device": "1",
            }
            # start animation while posting 2fa
            stop_event.clear()
            anim_thread = threading.Thread(target=animate_loading, args=(stop_event,), daemon=True)
            anim_thread.start()
            try:
                r2 = s.post(TWO_FACTOR_URL, headers=headers, data=two_data, timeout=30)
            except Exception as e:
                stop_event.set()
                print("\n\n[!] Network error during 2FA request:", e)
                return
            stop_event.set()
            anim_thread.join(timeout=0.5)

            j2 = safe_json(r2)
            text2 = r2.text or ""

            if 'logged_in_user' in text2 or j2.get("status") == "ok" and j2.get("logged_in_user"):
                print("\n\n[+] Logged In Success (2FA).")
            else:
                # Instagram may return 'challenge_required' or 'fail' messages
                if j2.get("status") == "fail":
                    print("\n\n[!] 2FA submission failed:", j2.get("message", text2))
                else:
                    print("\n\n[!] 2FA response did not indicate success. Response:")
                    print(text2)
                input("[+] Press Enter to exit...")
                return

            # after successful 2FA login, session cookies should be set in s.cookies

        else:
            # Not 2FA required; check if login success
            if 'logged_in_user' in text or j.get("status") == "ok" and j.get("logged_in_user"):
                print("\n\n[+] Logged In Success.")
            else:
                # unknown response
                print("\n\n[!] Login response:")
                # print raw text truncated to reasonable length
                displayed = text[:1500] + ("..." if len(text) > 1500 else "")
                print(displayed)
                input("[+] Press Enter to exit...")
                return

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

        input("\n[+] Done. Press Enter to exit...")

    finally:
        # Ensure any running animation is stopped
        try:
            stop_event.set()
        except Exception:
            pass

if __name__ == "__main__":
    main()