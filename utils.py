import os
from tkinter import messagebox
import shutil

import ipapi


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


def check_ip_reputation(ip_address):
    try:
        ip_data = ipapi.location(ip_address, output='json')
        if 'threat' in ip_data:
            threat_level = ip_data['threat']['is_threat']
            if threat_level:
                return "Unsafe IP address"
        return "Safe IP address"
    except ipapi.exceptions.PageNotFound:
        return "IP information not available"
