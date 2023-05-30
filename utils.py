import os
from tkinter import messagebox
import shutil
import ipapi
import requests


def exported_path():
    return os.path.join(os.getcwd(), "Attachments")


def clear_exported_path():
    if os.path.exists(exported_path()):
        shutil.rmtree(exported_path())
        show_info("Path was cleared successfully.")


def show_info(message):
    messagebox.showinfo("Information", message)


def show_warning(message):
    messagebox.showwarning("Warning", message)


def show_error(message):
    messagebox.showerror("Error", message)


def check_ip(ip_address):
    url = f"https://api.threatintelligenceplatform.com/v1/ip/{ip_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            ip_data = response.json()
            if 'is_threat' in ip_data:
                threat_level = ip_data['is_threat']
                if threat_level:
                    return "Unsafe IP address"
            return "Safe IP address"
        else:
            return "IP information not available"
    except requests.exceptions.RequestException:
        return "Error occurred during IP reputation check"


UNSAFE_IPS = [
    '2.56.119.93', '24.165.207.194', '45.61.185.249', '50.203.7.250', '162.247.74.216',
    '78.142.18.219', '107.189.4.83', '141.98.11.195', '146.71.0.48', '185.243.218.46'
]


def check_ip_reputation(ip_address):

    if ip_address in UNSAFE_IPS:
        return "Unsafe IP address"
    else:
        return "Safe IP address"



