import requests
from utils.colorPrinter import *
from datetime import datetime
from requests.exceptions import RequestException
import os
import time # Import standard time for sleep function

# --- Helper Function for Time String ---
def get_time_str():
    """Returns the formatted current time string."""
    return datetime.now().strftime("%H:%M:%S")

# --- Global Variables for Download ---
is_video = None
media_url = None
file_name = None

# --- New: Animated Loading Function ---
def animated_loading_bar(duration_seconds=15, message="Your_l0cal_broker"):
    """Displays a green animated loading bar for the given duration."""
    
    # We will use this flag to stop the animation gracefully
    global stop_animation
    stop_animation = False
    
    bar_length = 30
    steps = 100
    interval = duration_seconds / steps

    print_style = "\r\033[92m" # \r for carriage return, \033[92m for light green
    
    for i in range(steps + 1):
        if stop_animation:
            break
            
        progress = i / steps
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        # Print the bar and the message, then flush to ensure immediate update
        print(f"{print_style}[{bar}] {int(progress * 100)}% {message}\033[0m", end='', flush=True)
        time.sleep(interval)

    # Clear the loading bar line once finished or stopped
    print("\r" + " " * (bar_length + 20) + "\r", end='', flush=True)
    

# --- Main Fetch and Display Logic ---

def fetch_data(username):
    current_time = get_time_str()
    colorPrint(
        CYAN, f"[{current_time}] \t",
        GREEN, "[INFO] \t\t\b", 
        LIGHT_YELLOW_EX, "Fetching profile info and posts..."
    )
    
    response = None
    
    # Setup for concurrent loading and fetching
    import threading
    loading_thread = threading.Thread(target=animated_loading_bar, args=(30, "Your_l0cal_broker")) # Max 30s loading
    loading_thread.start()
    
    try:
        url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        headers = {
            "X-IG-App-ID": "936619743392459",
        }
        # The loading bar will run until the request completes or times out (15s)
        response = requests.get(url, headers=headers, timeout=15)
        
        # Signal the loading bar to stop immediately after the request
        global stop_animation
        stop_animation = True
        loading_thread.join() # Wait for the loading thread to finish clearing the line

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
    edges = user_data["edge_owner_to_timeline_media"]["edges"]

    if not edges:
        colorPrint(
            CYAN, f"[{current_time}] \t",
            GREEN, "[POST]  \t\b",
            RED, "No posts found"
        )
        return False
    else:
        for i, post_item in enumerate(edges, 1):
            post_data = post_item["node"]
            post_shortcode = post_data["shortcode"]
            is_video_flag = post_data["is_video"]
            post_owner = user_data["username"]

            post_url = f"https://www.instagram.com/p/{post_shortcode}/"
            
            colorPrint(YELLOW, f"+--------------------------------------------------------[{i}]-------------------------------------------------------+\n")

            if is_video_flag:
                colorPrint(
                    CYAN, f"[{current_time}] \t",
                    GREEN, "[VIDEO]  \t\b",
                    LIGHT_BLUE_EX, post_url
                )
            else:
                colorPrint(
                    CYAN, f"[{current_time}] \t",
                    GREEN, "[IMAGE]  \t\b",
                    LIGHT_BLUE_EX, post_url
                )

            colorPrint(
                CYAN, f"[{current_time}] \t",
                GREEN, "[OWNER] \t\b",
                LIGHT_BLUE_EX, f"https://www.instagram.com/{post_owner}"
            )

            tagged_edges = post_data.get("edge_media_to_tagged_user", {}).get("edges", [])
            for collaborator_item in tagged_edges:
                collaborator_username = collaborator_item["node"]["user"]["username"]
                colorPrint(
                    CYAN, f"[{current_time}] \t",
                    GREEN, "[COLLAB] \t\b",
                    LIGHT_BLUE_EX, f"https://www.instagram.com/{collaborator_username}"
                )
            
            print()
        return True

# --- Download Prompt ---

def ask_to_download():
    print()
    download_choice = input(
        f"[{get_time_str()}] \t [PROMPT] \t Would you like to download any of the posts listed? (y/n): "
    ).lower().strip()
    
    if download_choice in ('y', 'yes'):
        post_url = input(
            f"[{get_time_str()}] \t [PROMPT] \t Enter the full post URL to download: "
        ).strip()
        download_media(post_url)
    else:
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            GREEN, "[INFO] \t\t", 
            LIGHT_YELLOW_EX, "Download skipped. Exiting."
        )

# --- Media Fetch Details ---

def fetch_media_details(url):
    global is_video, media_url, file_name
    
    is_video, media_url, file_name = None, None, None

    parts = url.strip('/').split("/")
    
    if len(parts) < 6 or parts[4] not in ("p", "reel"):
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, "[ERROR] \t",
            RED, "Invalid URL format. Check if the URL is complete."
        )
        return False

    user_name = parts[3]
    shortcode = parts[5]
    
    is_reel = parts[4] == 'reel'
    file_name = f"{user_name}-{'reel' if is_reel else 'post'}-{shortcode.replace('-', '')[:10]}{'.mp4' if is_reel else '.jpg'}"
    
    colorPrint(
        CYAN, f"[{get_time_str()}] \t",
        GREEN, "[INFO] \t\t", 
        LIGHT_YELLOW_EX, "Fetching media link..."
    )
    
    response = None
    try:
        r = requests.get(
            f"https://www.instagram.com/api/v1/users/web_profile_info/?username={user_name}",
            headers={"X-IG-App-ID": "936619743392459"},
            timeout=15
        )
        response = r

        if r.status_code != 200:
            error_handler(r)
            return False

        edges = r.json()["data"]["user"]["edge_owner_to_timeline_media"]["edges"]
        found = False
        for edge in edges:
            node = edge["node"]
            if node["shortcode"] == shortcode:
                is_video = node["is_video"]
                media_url = node["video_url"] if is_video else node["display_url"]
                
                # Correct the file extension
                if is_video and not file_name.endswith('.mp4'):
                    file_name = file_name[:-4] + '.mp4'
                elif not is_video and not file_name.endswith('.jpg'):
                    file_name = file_name[:-4] + '.jpg'
                
                found = True
                break
        
        if not found:
            colorPrint(
                CYAN, f"[{get_time_str()}] \t",
                RED, "[ERROR] \t",
                RED, "Post not found in the user's latest feed. (Instagram API limitation)"
            )
            return False

        return True

    except RequestException as e:
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, "[REQUEST] \t\b",
            YELLOW, "[WARNING] \t",
            RED, f"Network error during media link fetch: {e}"
        )
        return False
    except Exception as e:
        status_code = response.status_code if response is not None else "N/A"
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, f"[{status_code}] \t\t",
            YELLOW, "[WARNING] \t",
            RED, f"Failed to fetch media data: {e}"
        )
        return False


def download_media(post_url):
    global is_video, media_url, file_name
    
    if not fetch_media_details(post_url):
        return

    if not media_url:
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, "[ERROR] \t",
            RED, "Could not extract media URL."
        )
        return

    download_dir = "InstaDownloads"
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    colorPrint(
        CYAN, f"[{get_time_str()}] \t",
        GREEN, "[INFO] \t\t",
        LIGHT_YELLOW_EX, "Starting download..."
    )
    
    try:
        r = requests.get(
            media_url, 
            headers={"X-IG-App-ID": "936619743392459"},
            stream=True,
            timeout=30
        )

        if r.status_code == 200:
            file_path = os.path.join(download_dir, file_name)
            with open(file_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

            colorPrint(
                CYAN, f"[{get_time_str()}] \t",
                GREEN, "[SUCCESS] \t",
                LIGHT_YELLOW_EX, "Downloaded ",
                LIGHT_BLUE_EX, ITALIC, f"{file_name} ", ITALIC_OFF,
                LIGHT_YELLOW_EX, f"to {ITALIC}'{download_dir}'{ITALIC_OFF} folder"
            )
        else:
            colorPrint(
                CYAN, f"[{get_time_str()}] \t",
                RED, f"[{r.status_code}] \t\t\b",
                YELLOW, "[WARNING] \t",
                RED, f"Failed to download media from {media_url}"
            )
    except RequestException as e:
        colorPrint(
            CYAN, f"[{get_time_str()}] \t",
            RED, "[DOWNLOAD ERR] \t\b",
            YELLOW, "[WARNING] \t",
            RED, f"Error during media download: {e}"
        )


# --- Wrapper function to maintain original function name ---
def time():
    return get_time_str()

# --- Example usage ---
# if __name__ == "__main__":
#     username = input("Enter Instagram username: ")
#     fetch_data(username)
