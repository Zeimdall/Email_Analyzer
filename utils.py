import os
import messagebox
import shutil


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
