import tkinter as tk
from tkinter import ttk


class EmailViewer(tk.Toplevel):
    def __init__(self, message_file):
        super().__init__()
        self.title("Email Viewer")

        self.from_label = ttk.Label(self, text="From: " + str(message_file.sender))
        self.from_label.pack()
        self.to_label = ttk.Label(self, text="To: " + str(message_file.to))
        self.to_label.pack()
        self.subject_label = ttk.Label(self, text="Subject: " + str(message_file.subject))
        self.subject_label.pack()
        self.cc_label = ttk.Label(self, text="CC: " + str(message_file.cc))
        self.cc_label.pack()
        self.bcc_label = ttk.Label(self, text="BCC: " + str(message_file.bcc))
        self.bcc_label.pack()
        self.time_label = ttk.Label(self, text="Email time: " + str(message_file.receivedTime))
        self.time_label.pack()
