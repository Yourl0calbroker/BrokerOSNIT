# Define colors and formatting codes
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
LIGHT_YELLOW_EX = '\033[93m'
LIGHT_BLUE_EX = '\033[94m'
ITALIC = '\033[3m'
ITALIC_OFF = '\033[23m'

def colorPrint(*args):
    output = ''.join(args)
    print(output + '\033[0m') 

import requests
from datetime import datetime
from requests.exceptions import RequestException
import os
import time
import threading 

def get_time_str():
    return datetime.now().strftime("%H:%M:%S")

is_video = None
media_url = None
file_name = None
stop_animation = False 

def animated_loading_bar(duration_seconds=15, message="Your_l0cal_broker"):
    
    global stop_animation
    
    bar_length = 30
    steps = 100
    interval = duration_seconds / steps

    print_style = "\r\033[92m" 
    
    for i in range(steps + 1):
        if stop_animation:
            break
            
        progress = i / steps
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        print(f"{print_style}[{bar}] {int(progress * 100)}% {message}\033[0m", end='', flush=True)
        time.sleep(interval)

    print("\r" + " " * (bar_length + 20) + "\r", end='', flush=True)
    

def fetch_data(username):
    global stop_animation
    current_time = get_time_str()
    colorPrint(
        CYAN, f"[{current_time}] \t",
        GREEN, "[INFO] \t\t\b", 
        LIGHT_YELLOW_EX, "Fetching profile info and posts..."
    )
    
    response = None
    
    loading_thread = threading.Thread(target=animated_loading_bar, args=(30, "Your_l0cal_broker")) 
    loading_thread.start()
    
    try:
        url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        headers = {
            "X-IG-App-ID": "936619743392459",
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        stop_animation = True
        loading_thread.join() 

        if response.status_code != 200:
            error_handler(response)
            return 

        user_data = response.json()["data"]["user"]
        
        account_type(user_data)
        posts_found = get_posts(user_data)
        
        if posts_found:
            ask_to_download()
        
    except RequestException as e:
        stop_animation = True
        loading_thread.join()
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, "[REQUEST] \t\b",
            YELLOW, "[WARNING] \t",
            RED, f"Network or connection error: {e}"
        )
    except Exception as e:
        stop_animation = True
        loading_thread.join()
        status_code = response.status_code if response is not None else "N/A"
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, f"[{status_code}] \t\t\b",
            YELLOW, "[WARNING] \t",
            RED, f"Failed to fetch account data: {e}"
        )


def error_handler(response):
    current_time = get_time_str()
    if response.status_code == 404:
        colorPrint(
            CYAN, f"[{current_time}] \t",
            RED, "[404] \t\t\b",
            RED, "[ERROR] \t\t",
            RED, "User not found"
        )
    elif response.status_code == 401:
        colorPrint(
            CYAN, f"[{current_time}] \t",
            RED, "[401] \t\t\b",
            YELLOW, "[WARNING] \t",
            RED, "Instagram added rate limit to your IP. Try again later"
        )
    else:
        colorPrint(
            CYAN, f"[{current_time}] \t",
            RED, f"[{response.status_code}] \t\t\b",
            RED, "[ERROR] \t\t",
            RED, "Something went wrong"
        )


def account_type(user_data):
    current_time = get_time_str()
    if user_data.get("is_private"):
        colorPrint(
            CYAN, f"[{current_time}] \t",
            GREEN, "[TYPE]  \t\b",
            RED, "Private profile\n"
        )
    else:
        colorPrint(
            CYAN, f"[{current_time}] \t",
            GREEN, "[TYPE]  \t\b",
            RED, "Public profile\n"
        )


def get_posts(user_data):
    current_time = get_time_str()
    edges = user_data["edge_owner_to_timeline_media
