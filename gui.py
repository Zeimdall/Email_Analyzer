import traceback
import email
import re
import tkinter as tk
from email import policy
from tkinter import filedialog, messagebox, ttk
import os

import chardet
import extract_msg

from utils import (
    clear_exported_path,
    show_error,
    show_info,
    exported_path,
    check_ip_reputation,
)

global tb
tb = traceback.format_exc()


class gui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Email Message Verifier")

        self.root.geometry("800x1000")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        style = self.create_custom_button_style()

        self.result_label = ttk.LabelFrame(text="Email info", width=80, height=7)
        self.result_label.pack(pady=10)
        self.result_text = tk.Text(self.result_label, width=80, height=7, wrap="word")
        self.result_text.pack()

        self.content_label = ttk.LabelFrame(text="Message content", width=80, height=12)
        self.content_label.pack(pady=10)
        self.content_text = tk.Text(
            self.content_label, width=80, height=12, wrap="word"
        )
        self.content_text.pack()

        middle_frame = tk.Frame(self.root)
        middle_frame.pack()

        self.attachment_frame = ttk.LabelFrame(middle_frame, text="Attachments")
        self.attachment_frame.pack(side=tk.LEFT, padx=10, pady=10)
        self.attachment_text = tk.Text(
            self.attachment_frame, width=38, height=7, wrap="word"
        )
        self.attachment_text.pack()

        self.emails_frame = ttk.LabelFrame(middle_frame, text="Email addresses")
        self.emails_frame.pack(side=tk.RIGHT, padx=10, pady=10)
        self.emails_text = tk.Text(self.emails_frame, width=38, height=7, wrap="word")
        self.emails_text.pack()

        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack()

        url_ip_frame = tk.Frame(bottom_frame)
        url_ip_frame.pack(side=tk.LEFT, padx=10, pady=10)

        self.url_frame = ttk.LabelFrame(url_ip_frame, text="URLs")
        self.url_frame.pack(side=tk.LEFT, pady=10, padx=10)
        self.url_text = tk.Text(self.url_frame, width=38, height=7, wrap="word")
        self.url_text.pack()

        self.ip_frame = ttk.LabelFrame(url_ip_frame, text="IPs")
        self.ip_frame.pack(side=tk.RIGHT, pady=10, padx=10)
        self.ip_text = tk.Text(self.ip_frame, width=38, height=7, wrap="word")
        self.ip_text.pack()

        self.xheaders_label = ttk.LabelFrame(text="X Headers", width=80, height=7)
        self.xheaders_label.pack(pady=10)
        self.xheaders_text = tk.Text(
            self.xheaders_label, width=80, height=7, wrap="word"
        )
        self.xheaders_text.pack()

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        browse_btn = ttk.Button(
            button_frame,
            text="Choose Email File",
            command=self.browse_file,
            style="Custom.TButton",
        )
        browse_btn.pack(side=tk.LEFT, padx=5)

        clear_txt_btn = ttk.Button(
            button_frame,
            text="Clear Text",
            command=self.clear_text,
            style="Custom.TButton",
        )
        clear_txt_btn.pack(side=tk.LEFT, padx=5)

        clear_path_btn = ttk.Button(
            button_frame,
            text="Clear Path",
            command=clear_exported_path,
            style="Custom.TButton",
        )
        clear_path_btn.pack(side=tk.LEFT, padx=5)

        self.email_name = None
        self.email_processed = False

        self.root.mainloop()

    @staticmethod
    def create_custom_button_style():
        style = ttk.Style()
        style.configure(
            "Custom.TButton",
            background="#FAEBD7",
            foreground="black",
            font=("Calibri", 10),
            padding=5,
        )
        return style

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit application?"):
            clear_exported_path()
            self.root.destroy()

    def browse_file(self, gui):
        filetypes = [("Email Files", "*.msg;*.eml"), ("All Files", "*.*")]
        self.gui.email_name = tk.filedialog.askopenfilename(filetypes=filetypes)
        if self.gui.email_name:
            self.gui.file_verifier()

    def clear_text(self):
        self.result_text.delete(1.0, tk.END)
        self.attachment_text.delete(1.0, tk.END)
        self.url_text.delete(1.0, tk.END)
        self.content_text.delete(1.0, tk.END)
        self.ip_text.delete(1.0, tk.END)
        self.emails_text.delete(1.0, tk.END)
        self.xheaders_text.delete(1.0, tk.END)
