#!/usr/bin/env python3
import requests
from datetime import datetime
from requests.exceptions import RequestException
import os
import time
import threading 
import sys # Import sys for clean exit

# --- Color and Formatting Definitions ---
class Color:
    """Class to hold ANSI color and formatting codes."""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m' # Renamed LIGHT_BLUE_EX for simplicity
    ITALIC = '\033[3m'
    ITALIC_OFF = '\033[23m'
    RESET = '\033[0m' # Important: Explicit reset code

def colorPrint(*args):
    """Prints colored output using the defined Color class codes."""
    # Ensure all arguments are treated as strings
    output = ''.join(str(arg) for arg in args)
    # The RESET code is automatically added to the end for a clean line break
    print(output + Color.RESET) 

# --- Global State and Utility Functions ---
_is_video = None
_media_url = None
_file_name = None
_stop_animation = False 

def get_time_str():
    """Returns the current time formatted as HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")

def animated_loading_bar(duration_seconds=15, message="Your_l0cal_broker"):
    """Displays a simple animated loading bar in a separate thread."""
    global _stop_animation
    
    bar_length = 30
    steps = 100
    # Set a minimum interval to prevent excessive CPU usage
    interval = max(0.01, duration_seconds / steps) 

    # Use GREEN color for the bar
    print_style = f"\r{Color.GREEN}" 
    
    for i in range(steps + 1):
        if _stop_animation:
            # Clear the current line before breaking
            sys.stdout.write("\r" + " " * (bar_length + 20) + "\r")
            sys.stdout.flush()
            break
            
        progress = i / steps
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        sys.stdout.write(f"{print_style}[{bar}] {int(progress * 100)}% {message}{Color.RESET}")
        sys.stdout.flush()
        time.sleep(interval)
    
    # Final clear if the loop finishes without the stop signal
    if not _stop_animation:
        sys.stdout.write("\r" + " " * (bar_length + 20) + "\r")
        sys.stdout.flush()
    

def fetch_data(username):
    """Initiates the fetching of profile information and posts."""
    global _stop_animation
    current_time = get_time_str()
    colorPrint(
        Color.CYAN, f"[{current_time}] \t",
        Color.GREEN, "[INFO] \t\t\b", 
        Color.YELLOW, "Fetching profile info and posts..."
    )
    
    response = None
    
    # Start loading animation
    _stop_animation = False
    loading_thread = threading.Thread(
        target=animated_loading_bar, 
        args=(30, "Your_l0cal_broker"),
        daemon=True # Make it a daemon thread so it exits if the main program crashes
    ) 
    loading_thread.start()
    
    try:
        url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
        headers = {
            "X-IG-App-ID": "936619743392459",
            # Adding a basic User-Agent to mimic a real browser request
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=15)
        
        # Stop animation upon receiving response
        _stop_animation = True
        loading_thread.join(timeout=1) # Wait briefly for the thread to clean up

        if response.status_code != 200:
            error_handler(response)
            return 

        user_data = response.json().get("data", {}).get("user")
        if not user_data:
            colorPrint(
                Color.CYAN, f"[{get_time_str()}] \t",
                Color.RED, "[API ERROR] \t",
                Color.RED, "Could not find 'user' data in API response."
            )
            return

        account_type(user_data)
        posts_found = get_posts(user_data)
        
        if posts_found:
            ask_to_download()
        
    except RequestException as e:
        _stop_animation = True
        loading_thread.join(timeout=1)
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, "[REQUEST] \t\b",
            Color.YELLOW, "[WARNING] \t",
            Color.RED, f"Network or connection error: {e}"
        )
    except Exception as e:
        _stop_animation = True
        loading_thread.join(timeout=1)
        status_code = response.status_code if response is not None else "N/A"
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, f"[{status_code}] \t\t\b",
            Color.YELLOW, "[WARNING] \t",
            Color.RED, f"Failed to fetch account data: {type(e).__name__}: {e}"
        )


def error_handler(response):
    """Handles and prints API response errors."""
    current_time = get_time_str()
    status_code = response.status_code
    
    if status_code == 404:
        msg = "User not found"
    elif status_code == 401:
        msg = "Instagram added rate limit to your IP. Try again later"
    else:
        msg = "Something went wrong"

    # Try to parse JSON for a more specific error message if available
    try:
        data = response.json()
        if 'message' in data:
            msg = f"{data['message']} ({msg})"
    except requests.JSONDecodeError:
        pass # Ignore if it's not JSON
    
    colorPrint(
        Color.CYAN, f"[{current_time}] \t",
        Color.RED, f"[{status_code}] \t\t\b",
        Color.RED, "[ERROR] \t\t",
        Color.RED, msg
    )


def account_type(user_data):
    """Prints whether the profile is public or private."""
    current_time = get_time_str()
    is_private = user_data.get("is_private")
    type_color = Color.RED if is_private else Color.GREEN
    type_msg = "Private profile" if is_private else "Public profile"
    
    colorPrint(
        Color.CYAN, f"[{current_time}] \t",
        Color.GREEN, "[TYPE]  \t\b",
        type_color, f"{type_msg}\n"
    )


def get_posts(user_data):
    """Parses and prints a summary of the user's latest posts."""
    current_time = get_time_str()
    edges = user_data.get("edge_owner_to_timeline_media", {}).get("edges", [])

    if not edges:
        colorPrint(
            Color.CYAN, f"[{current_time}] \t",
            Color.GREEN, "[POST]  \t\b",
            Color.RED, "No posts found in the visible feed."
        )
        return False
    else:
        for i, post_item in enumerate(edges, 1):
            post_data = post_item["node"]
            post_shortcode = post_data["shortcode"]
            is_video_flag = post_data["is_video"]
            post_owner = user_data["username"]

            post_url = f"https://www.instagram.com/p/{post_shortcode}/"
            
            # Use a print/sys.stdout.write for the separator to avoid colorPrint's automatic reset
            print(f"{Color.YELLOW}+--------------------------------------------------------[{i}]-------------------------------------------------------+{Color.RESET}\n", end='')

            media_type_msg = "[VIDEO]" if is_video_flag else "[IMAGE]"
            
            colorPrint(
                Color.CYAN, f"[{current_time}] \t",
                Color.GREEN, f"{media_type_msg} \t\b",
                Color.BLUE, post_url
            )

            colorPrint(
                Color.CYAN, f"[{current_time}] \t",
                Color.GREEN, "[OWNER] \t\b",
                Color.BLUE, f"https://www.instagram.com/{post_owner}"
            )

            tagged_edges = post_data.get("edge_media_to_tagged_user", {}).get("edges", [])
            for collaborator_item in tagged_edges:
                collaborator_username = collaborator_item["node"]["user"]["username"]
                colorPrint(
                    Color.CYAN, f"[{current_time}] \t",
                    Color.GREEN, "[COLLAB] \t\b",
                    Color.BLUE, f"https://www.instagram.com/{collaborator_username}"
                )
            
            print()
        return True

def ask_to_download():
    """Prompts the user to download a listed post."""
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
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.GREEN, "[INFO] \t\t", 
            Color.YELLOW, "Download skipped. Exiting."
        )

def fetch_media_details(url):
    """Extracts the direct media URL and filename from a post URL."""
    global _is_video, _media_url, _file_name
    
    _is_video, _media_url, _file_name = None, None, None

    # Basic URL validation and parsing
    url = url.strip().strip('/')
    parts = url.split("/")
    
    if len(parts) < 6 or parts[2] != "www.instagram.com":
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, "[ERROR] \t",
            Color.RED, "Invalid URL format. Check if the URL is complete."
        )
        return False
    
    # Parts: [0]https:, [1], [2]www.instagram.com, [3]username, [4]p/reel, [5]shortcode
    try:
        user_name = parts[3]
        media_type = parts[4] # 'p' or 'reel'
        shortcode = parts[5]
    except IndexError:
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, "[ERROR] \t",
            Color.RED, "Incomplete URL detected."
        )
        return False
    
    is_reel = media_type == 'reel'
    
    # Construct a base filename
    base_name = f"{user_name}-{media_type}-{shortcode[:10].replace('-', '')}"
    _file_name = f"{base_name}{'.mp4' if is_reel else '.jpg'}" # Default file extension

    colorPrint(
        Color.CYAN, f"[{get_time_str()}] \t",
        Color.GREEN, "[INFO] \t\t", 
        Color.YELLOW, "Fetching media link..."
    )
    
    response = None
    try:
        # Re-using the logic to fetch user's feed for post details
        r = requests.get(
            f"https://www.instagram.com/api/v1/users/web_profile_info/?username={user_name}",
            headers={"X-IG-App-ID": "936619743392459"},
            timeout=15
        )
        response = r

        if r.status_code != 200:
            error_handler(r)
            return False

        # Drill down to the edges array safely
        edges = r.json().get("data", {}).get("user", {}).get("edge_owner_to_timeline_media", {}).get("edges", [])
        found = False
        for edge in edges:
            node = edge.get("node", {})
            if node.get("shortcode") == shortcode:
                _is_video = node.get("is_video", False)
                _media_url = node.get("video_url") or node.get("display_url")
                
                # Adjust file extension based on what the API actually returned
                if _is_video and not _file_name.endswith('.mp4'):
                    _file_name = _file_name.rsplit('.', 1)[0] + '.mp4'
                elif not _is_video and not _file_name.endswith('.jpg'):
                    _file_name = _file_name.rsplit('.', 1)[0] + '.jpg'
                
                found = True
                break
        
        if not found:
            colorPrint(
                Color.CYAN, f"[{get_time_str()}] \t",
                Color.RED, "[ERROR] \t",
                Color.RED, "Post not found in the user's latest feed. (API limitation)"
            )
            return False

        return True

    except RequestException as e:
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, "[REQUEST] \t\b",
            Color.YELLOW, "[WARNING] \t",
            Color.RED, f"Network error during media link fetch: {e}"
        )
        return False
    except Exception as e:
        status_code = response.status_code if response is not None else "N/A"
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, f"[{status_code}] \t\t",
            Color.YELLOW, "[WARNING] \t",
            Color.RED, f"Failed to fetch media data: {type(e).__name__}: {e}"
        )
        return False


def download_media(post_url):
    """Downloads the media file to the 'InstaDownloads' directory."""
    global _is_video, _media_url, _file_name
    
    if not fetch_media_details(post_url):
        return

    if not _media_url:
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, "[ERROR] \t",
            Color.RED, "Could not extract media URL."
        )
        return

    download_dir = "InstaDownloads"
    # Create directory if it doesn't exist
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    colorPrint(
        Color.CYAN, f"[{get_time_str()}] \t",
        Color.GREEN, "[INFO] \t\t",
        Color.YELLOW, "Starting download..."
    )
    
    try:
        r = requests.get(
            _media_url, 
            headers={"X-IG-App-ID": "936619743392459"},
            stream=True, # Essential for downloading large files efficiently
            timeout=60 # Increased timeout for download
        )

        if r.status_code == 200:
            file_path = os.path.join(download_dir, _file_name)
            total_size = int(r.headers.get('content-length', 0))
            downloaded_size = 0
            
            colorPrint(
                Color.CYAN, f"[{get_time_str()}] \t",
                Color.GREEN, "[INFO] \t\t",
                Color.YELLOW, f"Saving as: {Color.ITALIC}{_file_name}{Color.ITALIC_OFF}"
            )

            # Basic download progress bar
            with open(file_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    
                    # Update progress every few chunks
                    if total_size > 0 and downloaded_size % (8192 * 50) == 0:
                        percent = (downloaded_size / total_size) * 100
                        sys.stdout.write(f"\r[{get_time_str()}] \t [PROGRESS] \t {percent:.2f}% downloaded...")
                        sys.stdout.flush()
            
            # Clear progress bar line
            sys.stdout.write("\r" + " " * 80 + "\r")
            sys.stdout.flush()
            
            colorPrint(
                Color.CYAN, f"[{get_time_str()}] \t",
                Color.GREEN, "[SUCCESS] \t",
                Color.YELLOW, "Downloaded ",
                Color.BLUE, Color.ITALIC, f"{_file_name} ", Color.ITALIC_OFF,
                Color.YELLOW, f"to {Color.ITALIC}'{download_dir}'{Color.ITALIC_OFF} folder"
            )
        else:
            colorPrint(
                Color.CYAN, f"[{get_time_str()}] \t",
                Color.RED, f"[{r.status_code}] \t\t\b",
                Color.YELLOW, "[WARNING] \t",
                Color.RED, f"Failed to download media from {_media_url}"
            )
    except RequestException as e:
        colorPrint(
            Color.CYAN, f"[{get_time_str()}] \t",
            Color.RED, "[DOWNLOAD ERR] \t\b",
            Color.YELLOW, "[WARNING] \t",
            Color.RED, f"Error during media download: {e}"
        )

def main():
    """Main function to run the script."""
    print(f"\n{Color.GREEN}--- Instagram Post Fetcher ---{Color.RESET}")
    username = input("Enter Instagram username to check: ").strip()
    if not username:
        print("Username cannot be empty. Exiting.")
        sys.exit(1)
    fetch_data(username)

if __name__ == "__main__":
    main()
