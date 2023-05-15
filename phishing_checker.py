import email
import os
import re
import sys
from email import policy
from tkinter import filedialog, messagebox
import extract_msg
import tkinter as tk


class EmailAnalyzerGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Email Verification Program")

        self.root.geometry("800x800")

        browse_btn = tk.Button(self.root, text="Choose email file", command=self.browse_file)
        browse_btn.pack(pady=10)

        self.root.mainloop()

    def browse_file(self):
        global email_name
        filetypes = [("Email Files", "*.msg;*.eml"), ("All Files", "*.*")]
        email_name = filedialog.askopenfile(filetypes=filetypes)
        if email_name:
            self.file_verifier()

    def file_verifier(self):
        global exported_path
        exported_path = exported_path = os.path.join(os.getcwd(), "Attachments")
        try:
            if os.path.exists(exported_path):
                messagebox.showerror()
            else:
                os.mkdir(exported_path)
                self.process_email()
        except:
            messagebox.showerror("Error", "Something went wrong during creating path.")

    def process_email(self):
        if email_name.endswith('.msg'):
            self.msg_checker(email_name)
        elif email_name.endswith('.eml'):
            self.base_grabber()
        else:
            messagebox.showerror("Error", "Email file has wrong format.")

    def msg_checker(self, file):
        try:
            with extract_msg.openMsg(file) as message_file:
                messagebox.showinfo("From: " + str(message_file.sender) +
                                    "\nTo: " + str(message_file.to) +
                                    "\nSubject: " + str(message_file.subject) +
                                    "\nCC: " + str(message_file.cc) +
                                    "\nBCC: " + str(message_file.bcc) +
                                    "\nEmail time: " + str(message_file.receivedTime))

                if len(message_file.attachments) > 0:
                    attachments_info = "Attachments:\n"
                    for attachment in message_file.attachments:
                        attachment_name = attachment.getFileName()
                        attachments_info += attachment_name + "\n"
                        attachment_path = os.path.join(exported_path, attachment_name)
                        with open(attachment_path, "wb") as fileWrite:
                            fileWrite.write(attachment.get_payload(decode=True))
                    messagebox.showinfo("Attachments", attachments_info)
                else:
                    messagebox.showinfo("Attachments", "No attachments found")

                message_body = str(message_file.body)
                truncated_body = message_body.replace("\r", " ")
                self.msg_ip_checker(truncated_body)
                self.msg_email_checker(truncated_body)
                self.msg_url_checker(truncated_body)
                message_file.close()
        except:
            messagebox.showerror("Something went wrong verifying .msg file!")

    def msg_email_checker(self, email_body):
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', email_body)
        email = []
        try:
            if regex is not None:
                print("Found emails in email body!\n")
                for match in regex:
                    if match not in email:
                        email.append(match)
            print('\n')
        except:
            messagebox.showerror("Something went wrong with msg_email_checker!")

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
                        print("\n" + str(ip_count) + " - IP Address: " + match)
        except:
            messagebox.showerror("Something went wrong with msg_ip_checker!")

    def msg_url_checker(self, url_file):
        try:
            print("URLs found\n")
            regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', url_file)
            if regex is not None:
                for match in regex:
                    url_found = str(match)
                    url_found = re.sub("[(\']", "", url_found)
                    url_found = re.sub(">", "", url_found)
                    url_found = re.sub("<", "", url_found)
                    print(url_found.strip())
        except:
            messagebox.showerror("Something went wrong with msg_url_checker!")

    # noinspection PyBroadException
    def base_grabber(self):
        try:
            count = 0
            with open(sys.argv[1], "r", encoding="utf-8") as sample:
                for line in sample:
                    if line.startswith("From: "):
                        print(line)
                    if line.startswith("To: "):
                        print(line)
                    if line.startswith("Subject: "):
                        print(line)
                    if line.startswith("Date: "):
                        print(line)
                    if line.startswith("Message-ID: "):
                        print(line)
                    if line.startswith("Return-Path:"):
                        print(line)
                    if line.startswith("Return-To:"):
                        print(line)
                    if line.startswith("List-Unsubscribe:"):
                        print(line)
                    if line.startswith("Message Body: "):
                        print(line)
                    if line.startswith("Received: "):
                        count += 1

            print("Total HOPS Count: " + str(count) + "\n")

        except Exception:
            messagebox.showerror("Something Went Wrong in Base Grabber!")
            exit()

        finally:
            self.email_grabber()

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

        except:
            messagebox.showerror("Something Went Wrong in Email Grabber!")
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
                        print("\n" + str(ip_count) + " - IP Address: " + match)

        except:
            messagebox.showerror("Something Went Wrong IP Grabber!")
            exit()

        finally:
            self.url_grabber()

    def url_grabber(self):
        file_open = open(sys.argv[1], 'r', encoding='utf-8')
        read_text = file_open.read()
        print(re.search("(?P<url>https?://[^\s]+)", read_text).group("url"))
        url = []

        regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', read_text)

        try:
            if regex is not None:
                for match in regex:
                    if match not in url:
                        print(match)
                        url.append(match)
            if not url:
                print("No URLs Found!")
        except:
            messagebox.showerror("Something Went Wrong In url Grabber")

        finally:
            self.xHunter()

    def xHunter(self):
        print("\n")

        try:
            with open(sys.argv[1], 'r', encoding='utf-8') as sample:
                for line in sample:
                    if line.startswith("X-"):
                        print(line)
        except:
            messagebox.showinfo("No X Headers Observed")

        finally:
            self.embed_attachments()

    def embed_attachments(self):
        print("Checking If There Is Are Any Attachments")

        try:
            with open(sys.argv[1], "r") as f:
                attach_file = email.message_from_file(f, policy=policy.default)
                for attachment in attach_file.iter_attachments():
                    att_name = attachment.get_filename()
                    print("\nFile Found & Written In Attachments: " + att_name)
                    with open(os.path.join(exported_path, att_name), "wb") as fileWrite:
                        fileWrite.write(attachment.get_payload(decode=True))

        except:
            messagebox.showerror("Something Went Wrong In Embed Attachments")


if __name__ == "__main__":
    gui = EmailAnalyzerGui()
    gui.root.mainloop()
