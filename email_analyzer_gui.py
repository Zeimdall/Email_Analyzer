import traceback
import email
import re
import tkinter as tk
from email import policy
from tkinter import filedialog, messagebox, ttk
import os

import chardet
import extract_msg

from utils import clear_exported_path, show_error, show_info, exported_path, check_ip_reputation

global tb
tb = traceback.format_exc()


class EmailAnalyzerGui:
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
        self.content_text = tk.Text(self.content_label, width=80, height=12, wrap="word")
        self.content_text.pack()

        middle_frame = tk.Frame(self.root)
        middle_frame.pack()

        self.attachment_frame = ttk.LabelFrame(middle_frame, text="Attachments")
        self.attachment_frame.pack(side=tk.LEFT, padx=10, pady=10)
        self.attachment_text = tk.Text(self.attachment_frame, width=38, height=7, wrap="word")
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
        self.xheaders_text = tk.Text(self.xheaders_label, width=80, height=7, wrap="word")
        self.xheaders_text.pack()

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        browse_btn = ttk.Button(button_frame, text="Choose Email File", command=self.browse_file,
                                style='Custom.TButton')
        browse_btn.pack(side=tk.LEFT, padx=5)

        clear_txt_btn = ttk.Button(button_frame, text="Clear Text", command=self.clear_text,
                                   style='Custom.TButton')
        clear_txt_btn.pack(side=tk.LEFT, padx=5)

        clear_path_btn = ttk.Button(button_frame, text="Clear Path", command=clear_exported_path,
                                    style='Custom.TButton')
        clear_path_btn.pack(side=tk.LEFT, padx=5)

        self.email_name = None
        self.email_processed = False

        self.root.mainloop()

    @staticmethod
    def create_custom_button_style():
        style = ttk.Style()
        style.configure('Custom.TButton', background='#FAEBD7', foreground='black', font=('Calibri', 10),
                        padding=5)
        return style

    def browse_file(self):
        filetypes = [("Email Files", "*.msg;*.eml"), ("All Files", "*.*")]
        self.email_name = tk.filedialog.askopenfilename(filetypes=filetypes)
        if self.email_name:
            self.file_verifier()

    def file_verifier(self):
        try:
            if os.path.exists(exported_path()):
                messagebox.showwarning("Warning", "Path already exists")
                self.process_email()
            else:
                os.mkdir(exported_path())
                self.process_email()
        except Exception as e:
            messagebox.showerror("Error", "Something went wrong during creating path. ")
            print(str(e) + "\n" + tb)

    def process_email(self):
        if self.email_name.endswith('.msg'):
            try:
                self.msg_checker(self.email_name)
            except Exception as e:
                messagebox.showerror("Error", "Something went wrong with msg_checker! " + str(e))
                print(str(e))
        elif self.email_name.endswith('.eml') and not self.email_processed:
            try:
                self.eml_checker(self.email_name)
                self.email_processed = True
            except Exception as e:
                messagebox.showerror("Error", "Something went wrong with eml_checker! " + str(e))
                print(str(e) + "\n" + tb)
        else:
            messagebox.showerror("Error", "Email file has wrong format.")

    def msg_checker(self, file):
        try:
            with open(file, "rb") as msg_file:
                message = extract_msg.Message(msg_file)

                self.append_text("From: " + str(message.sender))
                self.append_text("To: " + str(message.to))
                self.append_text("Subject: " + str(message.subject))
                self.append_text("CC: " + str(message.cc))
                self.append_text("BCC: " + str(message.bcc))
                self.append_text("Email time: " + str(message.receivedTime))

                payload = message.body
                if isinstance(payload, bytes):
                    encoding = chardet.detect(payload)["encoding"] or "utf-8"
                    payload = payload.decode(encoding)
                    self.append_content_message_text(payload)

                for attachment in message.attachments:
                    if hasattr(attachment, "longFilename"):
                        attachment_name = attachment.longFilename
                    elif hasattr(attachment, "filenameLong"):
                        attachment_name = attachment.filenameLong
                    else:
                        attachment_name = "Unknown Filename"
                    self.append_attachment_text(attachment_name + "\n")

                body = str(payload).replace('\r', ' ')

                self.msg_ip_grabber(body)
                self.msg_url_grabber(body)
                self.msg_email_grabber(body)
                self.embed_attachments()

        except Exception as e:
            show_error("Something went wrong verifying .msg file!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def msg_ip_grabber(self, body_well):

        IP = []
        IP_COUNT = 0
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body_well)

        try:
            if regex is not None:
                for match in regex:
                    if match not in IP:
                        IP.append(match)
                        IP_COUNT += 1
                        self.append_ip_text("\n" + str(IP_COUNT) + " - IP Address: " + match)
        except:
            print("Something Goes Wrong In Grabbing MSG IPs")

    def msg_email_grabber(self, email_body):

        EMAIL = []
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', email_body)

        try:
            if regex is not None:
                for match in regex:
                    if match not in EMAIL:
                        EMAIL.append(match)
                        self.append_email_addresses_text(match)
            print("\n")
        except Exception as e:
            print("Something went wrong in grabbing MSG emails")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def msg_url_grabber(self, url_file):

        try:
            regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', url_file)
            if regex is not None:
                for match in regex:
                    urlFound = str(match)
                    urlFound = re.sub("[(\']", "", urlFound)
                    urlFound = re.sub(">", "", urlFound)
                    urlFound = re.sub("<", "", urlFound)
                    self.append_url(urlFound.strip())
        except Exception as e:
            print("Something went wrong in MSG URL")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def eml_checker(self, file):
        try:
            with open(file, 'rb') as eml_file:
                message = email.message_from_binary_file(eml_file)
                self.append_text("From: " + str(message['From']))
                self.append_text("To: " + str(message['To']))
                self.append_text("Subject: " + str(message['Subject']))
                self.append_text("CC: " + str(message['CC']))
                self.append_text("BCC: " + str(message['BCC']))
                self.append_text("Email time: " + str(message['Date']))

                for part in message.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        encoding = part.get_content_charset()
                        if encoding:
                            payload = payload.decode(encoding)
                        else:
                            result = chardet.detect(payload)
                            encoding = result["encoding"]
                            if encoding:
                                payload = payload.decode(encoding)

                        self.append_content_message_text(payload)

                    if part.get("Content-Disposition"):
                        attachment_name = part.get_filename()
                        if attachment_name:
                            self.append_attachment_text(attachment_name + "\n")

                self.ip_grabber()
                self.email_grabber()
                self.url_grabber()
                self.xHunter()
                self.embed_attachments()

        except Exception as e:
            messagebox.showerror("Error", "Something went wrong verifying .eml file!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def email_grabber(self):
        email = []
        try:
            file_open = open(self.email_name, 'r', encoding='utf-8')
            read_text = file_open.read()
            regex = re.findall(r'\b[A-Za-z0-9._%+-]{1,20}@[^=]+?\.[A-Za-z]{2,6}\b', read_text)
            if regex is not None:
                for match in regex:
                    if match not in email:
                        email.append(match)
                        self.append_email_addresses_text(match + "\n")

        except Exception as e:
            show_error("Something went wrong in email grabber!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()
            exit()

    def ip_grabber(self):
        ip = []
        ip_count = 0
        try:
            file_open = open(self.email_name, 'r', encoding='utf-8')
            read_text = file_open.read()
            regex = re.findall(r'(?!.)\b(?:\d{1,3}\.){3}\d{1,3}\b', read_text)
            if regex is not None:
                for match in regex:
                    if match not in ip:
                        ip.append(match)
                        ip_count += 1
                        self.append_ip_text(match + " - " + check_ip_reputation(match) + "\n")

        except Exception as e:
            show_error("Something went wrong IP Grabber!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()
            exit()

    def url_grabber(self):
        file_open = open(self.email_name, 'r', encoding='utf-8')
        read_text = file_open.read()
        url = []

        regex = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
                           read_text)

        try:
            if regex is not None:
                for match in regex:
                    if match not in url:
                        self.append_url(match)
                        url.append(match)
            if not url:
                show_info("No URLs Found!")
        except Exception as e:
            show_error("Something went wrong in url Grabber")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def xHunter(self):
        print("\n")
        try:
            with open(self.email_name, 'r', encoding='utf-8') as sample:
                for line in sample:
                    if line.startswith("X-"):
                        self.append_xheader_text(line)
        except Exception as e:
            show_info("No X Headers observed")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    @staticmethod
    def verify_attachment_extension(attachment_name):
        unsafe_extensions = ['exe', 'js', 'vbs', 'bat']
        filename, file_extension = os.path.splitext(attachment_name)

        if '.' in filename and file_extension.lstrip('.').lower() in unsafe_extensions:
            return False, "Attachment has unsafe and double extension."
        elif '.' in filename:
            return False, "Attachment has double extension."
        elif file_extension.lstrip('.').lower() in unsafe_extensions:
            return False, "Attachment has unsafe extension."
        else:
            return True, ""

    def embed_attachments(self):
        try:
            with open(self.email_name, "r", encoding='utf-8') as f:
                attach_file = email.message_from_file(f, policy=policy.default)
                for attachment in attach_file.iter_attachments():
                    att_name = attachment.get_filename()
                    valid, message = self.verify_attachment_extension(att_name)
                    if valid:
                        show_info("File Found & Written In Attachments: " + att_name)
                        with open(os.path.join(exported_path(), att_name), "wb") as fileWrite:
                            fileWrite.write(attachment.get_payload(decode=True))
                    else:
                        show_error("Attachment " + att_name + " could not be written in Attachments. " + message)

        except Exception as e:
            show_error("Something went wrong in embed attachments")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def append_url(self, urls):
        urls_info = "".join(urls) + "\n"
        self.url_text.insert(tk.END, urls_info)

    def append_text(self, text):
        self.result_text.insert(tk.END, text + "\n")

    def append_attachment_text(self, text):
        self.attachment_text.insert(tk.END, text)

    def append_email_addresses_text(self, text):
        self.emails_text.insert(tk.END, text)

    def append_content_message_text(self, text):
        self.content_text.insert(tk.END, text)

    def append_ip_text(self, text):
        self.ip_text.insert(tk.END, text)

    def append_xheader_text(self, text):
        self.xheaders_text.insert(tk.END, text)

    def clear_text(self):
        self.result_text.delete(1.0, tk.END)
        self.attachment_text.delete(1.0, tk.END)
        self.url_text.delete(1.0, tk.END)
        self.content_text.delete(1.0, tk.END)
        self.ip_text.delete(1.0, tk.END)
        self.emails_text.delete(1.0, tk.END)
        self.xheaders_text.delete(1.0, tk.END)

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit application?"):
            clear_exported_path()
            self.root.destroy()
