import traceback
import email
import re
import sys
import tkinter as tk
from email import policy
from tkinter import filedialog, messagebox, ttk

import extract_msg

from attachment_viewer import AttachmentViewer
from utils import *

tb = traceback.format_exc()


def show_attachment_viewer(self, attachments):
    AttachmentViewer(attachments, self.attachment_text)


class EmailAnalyzerGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Email Verification Program")

        self.root.geometry("800x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        style = self.create_custom_button_style()

        self.result_label = ttk.LabelFrame(text="Email info", width=80, height=10)
        self.result_label.pack(pady=10)
        self.result_text = tk.Text(self.result_label, width=80, height=7)
        self.result_text.pack()

        self.attachment_frame = ttk.LabelFrame(self.root, text="Attachments")
        self.attachment_frame.pack(pady=10)
        self.attachment_text = tk.Text(self.attachment_frame, width=80, height=7)
        self.attachment_text.pack()

        self.url_frame = ttk.LabelFrame(self.root, text="URLs")
        self.url_frame.pack(pady=10)
        self.url_text = tk.Text(self.url_frame, width=80, height=7)
        self.url_text.pack()

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        browse_btn = ttk.Button(button_frame, text="Choose email file", command=self.browse_file,
                                style='Custom.TButton')
        browse_btn.pack(side=tk.LEFT, padx=5)

        clear_txt_btn = ttk.Button(button_frame, text="Clear Text", command=self.clear_text,
                                   style='Custom.TButton')
        clear_txt_btn.pack(side=tk.LEFT, padx=5)

        clear_path_btn = ttk.Button(button_frame, text="Clear Path", command=clear_exported_path,
                                    style='Custom.TButton')
        clear_path_btn.pack(side=tk.LEFT, padx=5)

        self.email_name = None

        self.root.mainloop()

    @staticmethod
    def create_custom_button_style():
        style = ttk.Style()
        style.configure('Custom.TButton', background='#FAEBD7', foreground='black', font=('Calibri', 10),
                        padding=5)
        return style

    def append_url(self, urls):
        urls_info = "".join(urls) + "\n"
        self.url_text.insert(tk.END, urls_info)

    def append_text(self, text):
        self.result_text.insert(tk.END, text + "\n")
        self.result_text.configure(state='disabled')
        self.result_text.yview(tk.END)
        self.result_text.configure(state='normal')

    def browse_file(self):
        global email_name
        filetypes = [("Email Files", "*.msg;*.eml"), ("All Files", "*.*")]
        email_name = filedialog.askopenfilename(filetypes=filetypes)
        if email_name:
            self.file_verifier()

    def file_verifier(self):
        try:
            if os.path.exists(exported_path()):
                show_warning("Path already exists")
                self.process_email()
            else:
                os.mkdir(exported_path())
                self.process_email()
        except Exception as e:
            show_error("Something went wrong during creating path.")
            print(str(e) + "\n" + tb)

    def process_email(self):
        if email_name.endswith('.msg'):
            try:
                self.msg_checker(email_name)
            except Exception as e:
                show_error("Something went wrong with msg_checker!")
                print(str(e) + "\n" + tb)
        elif email_name.endswith('.eml'):
            try:
                self.eml_checker(email_name)
            except Exception as e:
                show_error("Something went wrong with msg_checker!")
                print(str(e) + "\n" + tb)
        else:
            show_error("Email file has wrong format.")

    def eml_checker(self, file):
        try:
            with open(file, "rb") as eml_file:
                message = email.message_from_binary_file(eml_file, policy=policy.default)

                from_value = message["From"]
                to_value = message["To"]
                subject_value = message["Subject"]
                cc_value = message["Cc"]
                bcc_value = message["Bcc"]
                received_time = message["Date"]

                self.append_text("From: " + str(from_value) +
                                 "\nTo: " + str(to_value) +
                                 "\nSubject: " + str(subject_value) +
                                 "\nCC: " + str(cc_value) +
                                 "\nBCC: " + str(bcc_value) +
                                 "\nEmail time: " + str(received_time) + "\n")

                if message.get_content_maintype() == "multipart":
                    attachments = []
                    for part in message.walk():
                        attachments.append(part)
                    show_attachment_viewer(self, attachments)
                else:
                    show_info("No attachments found")

                message_body = None
                for part in message.walk():
                    if part.get_content_type() == "text/plain":
                        message_body = part.get_payload(decode=True)
                        break

                if message_body:
                    # message_body = message_body.decode("utf-8")
                    self.ip_grabber()
                    self.email_grabber()
                    self.url_grabber()
                else:
                    show_info("No message body found in the email.")

        except Exception as e:
            show_error("Something went wrong verifying .eml file!")
            print(str(e) + "\n" + tb)

    def msg_checker(self, file):
        try:
            with extract_msg.openMsg(file) as message_file:
                self.append_text("From: " + str(message_file.sender) +
                                 "\nTo: " + str(message_file.to) +
                                 "\nSubject: " + str(message_file.subject) +
                                 "\nCC: " + str(message_file.cc) +
                                 "\nBCC: " + str(message_file.bcc) +
                                 "\nEmail time: " + str(message_file.receivedTime))

                if len(message_file.attachments) > 0:
                    attachments_info = "Attachments:\n"
                    for attachment in message_file.attachments:
                        if hasattr(attachment, "long_filename") and attachment.long_filename:
                            attachment_name = attachment.long_filename
                        elif hasattr(attachment, "filename") and attachment.filename:
                            attachment_name = attachment.filename
                        else:
                            attachment_name = "Unknown Filename"

                    attachments_info += attachment_name + "\n"
                    attachment_path = os.path.join(exported_path(), attachment_name)
                    with open(attachment_path, "wb") as fileWrite:
                        fileWrite.write(attachment.as_bytes())
                        self.append_text(attachments_info)
                else:
                    show_info("No attachments found")

                message_body = str(message_file.body)
                truncated_body = message_body.replace("\r", " ")
                self.msg_ip_checker(truncated_body)
                self.msg_email_checker(truncated_body)
                self.msg_url_checker(truncated_body)
                message_file.close()
        except Exception as e:
            show_error("Something went wrong verifying .msg file!")
            print(str(e) + "\n" + tb)

    def msg_email_checker(self, email_body):
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', email_body)
        email = []
        try:
            if regex is not None:
                show_info("Found emails in email body!\n")
                for match in regex:
                    if match not in email:
                        email.append(match)
            print('\n')
            self.append_text(email)
        except Exception as e:
            show_error("Something went wrong with msg_email_checker!")
            print(str(e) + "\n" + tb)

    def msg_ip_checker(self, body):
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
        ip = []
        ip_count = 0

        try:
            if regex is not None:
                for match in regex:
                    if match not in ip:
                        ip.append(match)
                        ip_count += 1
                        self.append_text("\n" + str(ip_count) + " - IP Address: " + match)
        except:
            show_error("Something went wrong with msg_ip_checker!")

    def msg_url_checker(self, url_file):
        try:
            messagebox.showinfo("URL Information", "URLs found\n")
            regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', url_file)
            if regex is not None:
                for match in regex:
                    url_found = str(match)
                    url_found = re.sub("[(\']", "", url_found)
                    url_found = re.sub(">", "", url_found)
                    url_found = re.sub("<", "", url_found)
                    self.append_url(url_found)
        except Exception as e:
            show_error("Something went wrong with msg_url_checker!")
            print(str(e) + "\n" + tb)

    def email_grabber(self):
        email = []
        try:
            file_open = open(sys.argv[1], 'r', encoding='utf-8')
            read_text = file_open.read()
            regex = re.findall(r'[\w\.-]+@[\w\.-]+', read_text)
            if regex is not None:
                for match in regex:
                    if match not in email:
                        email.append(match)
                        print(match + "\n")

        except Exception as e:
            show_error("Something went wrong in email grabber!")
            print(str(e) + "\n" + tb)
            exit()

        finally:
            self.ip_grabber()

    def ip_grabber(self):
        ip = []
        ip_count = 0
        try:
            file_open = open(sys.argv[1], 'r', encoding='utf-8')
            read_text = file_open.read()
            regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', read_text)
            if regex is not None:
                for match in regex:
                    if match not in ip:
                        ip.append(match)
                        ip_count += 1
                        self.append_text("\n" + str(ip_count) + " - IP Address: " + match)

        except Exception as e:
            show_error("Something went wrong IP Grabber!")
            print(str(e) + "\n" + tb)
            exit()

        finally:
            self.url_grabber()

    def url_grabber(self):
        file_open = open(sys.argv[1], 'r', encoding='utf-8')
        read_text = file_open.read()
        show_info(re.search("(?P<url>https?://[^\s]+)", read_text).group("url"))
        url = []

        regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', read_text)

        try:
            if regex is not None:
                for match in regex:
                    if match not in url:
                        print(match)
                        url.append(match)
            if not url:
                show_info("No URLs Found!")
        except Exception as e:
            show_error("Something went wrong in url Grabber")
            print(str(e) + "\n" + tb)

        finally:
            self.xHunter()

    def xHunter(self):
        print("\n")

        try:
            with open(sys.argv[1], 'r', encoding='utf-8') as sample:
                for line in sample:
                    if line.startswith("X-"):
                        print(line)
        except Exception as e:
            show_info("No X Headers observed")
            print(str(e) + "\n" + tb)

        finally:
            self.embed_attachments()

    def embed_attachments(self):
        show_info("Checking if there are any attachments")

        try:
            with open(sys.argv[1], "r") as f:
                attach_file = email.message_from_file(f, policy=policy.default)
                for attachment in attach_file.iter_attachments():
                    att_name = attachment.get_long_filename()
                    show_info("\nFile Found & Written In Attachments: " + att_name)
                    with open(os.path.join(exported_path(), att_name), "wb") as fileWrite:
                        fileWrite.write(attachment.get_payload(decode=True))

        except Exception as e:
            show_error("Something went wrong in embed attachments")
            print(str(e) + "\n" + tb)

    def clear_text(self):
        self.result_text.delete(1.0, tk.END)
        self.attachment_text.delete(1.0, tk.END)
        self.url_text.delete(1.0, tk.END)

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit application?"):
            clear_exported_path()
            self.root.destroy()
