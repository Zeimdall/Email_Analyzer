class logic:
    def __init__(self, gui):
        self.gui.gui = gui

    def file_verifier(self):
        try:
            if os.path.exists(exported_path()):
                messagebox.showwarning("Warning", "Path already exists")
                self.gui.gui.process_email()
            else:
                os.mkdir(exported_path())
                self.gui.process_email()
        except Exception as e:
            messagebox.showerror("Error", "Something went wrong during creating path. ")
            print(str(e) + "\n" + tb)

    def process_email(self):
        if self.gui.email_name.endswith(".msg"):
            try:
                self.gui.msg_checker(self.gui.email_name)
            except Exception as e:
                messagebox.showerror(
                    "Error", "Something went wrong with msg_checker! " + str(e)
                )
                print(str(e))
        elif self.gui.email_name.endswith(".eml") and not self.gui.email_processed:
            try:
                self.gui.eml_checker(self.gui.email_name)
                self.gui.email_processed = True
            except Exception as e:
                messagebox.showerror(
                    "Error", "Something went wrong with eml_checker! " + str(e)
                )
                print(str(e) + "\n" + tb)
        else:
            messagebox.showerror("Error", "Email file has wrong format.")

    def msg_checker(self, file):
        try:
            with open(file, "rb") as msg_file:
                message = extract_msg.Message(msg_file)

                self.gui.append_text("From: " + str(message.sender))
                self.gui.append_text("To: " + str(message.to))
                self.gui.append_text("Subject: " + str(message.subject))
                self.gui.append_text("CC: " + str(message.cc))
                self.gui.append_text("BCC: " + str(message.bcc))
                self.gui.append_text("Email time: " + str(message.receivedTime))

                payload = message.body
                if isinstance(payload, bytes):
                    encoding = chardet.detect(payload)["encoding"] or "utf-8"
                    payload = payload.decode(encoding)
                    self.gui.append_content_message_text(payload)

                for attachment in message.attachments:
                    if hasattr(attachment, "longFilename"):
                        attachment_name = attachment.longFilename
                    elif hasattr(attachment, "filenameLong"):
                        attachment_name = attachment.filenameLong
                    else:
                        attachment_name = "Unknown Filename"
                    self.gui.append_attachment_text(attachment_name + "\n")

                body = str(payload).replace("\r", " ")

                self.gui.msg_ip_grabber(body)
                self.gui.msg_url_grabber(body)
                self.gui.msg_email_grabber(body)
                self.gui.embed_attachments()

        except Exception as e:
            show_error("Something went wrong verifying .msg file!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def msg_ip_grabber(self, body_well):
        IP = []
        IP_COUNT = 0
        regex = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body_well)

        try:
            if regex is not None:
                for match in regex:
                    if match not in IP:
                        IP.append(match)
                        IP_COUNT += 1
                        self.gui.append_ip_text(
                            "\n" + str(IP_COUNT) + " - IP Address: " + match
                        )
        except:
            print("Something Goes Wrong In Grabbing MSG IPs")

    def msg_email_grabber(self, email_body):
        EMAIL = []
        regex = re.findall(r"[\w\.-]+@[\w\.-]+", email_body)

        try:
            if regex is not None:
                for match in regex:
                    if match not in EMAIL:
                        EMAIL.append(match)
                        self.gui.append_email_addresses_text(match)
            print("\n")
        except Exception as e:
            print("Something went wrong in grabbing MSG emails")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def msg_url_grabber(self, url_file):
        try:
            regex = re.findall(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
                url_file,
            )
            if regex is not None:
                for match in regex:
                    urlFound = str(match)
                    urlFound = re.sub("[(']", "", urlFound)
                    urlFound = re.sub(">", "", urlFound)
                    urlFound = re.sub("<", "", urlFound)
                    self.gui.append_url(urlFound.strip())
        except Exception as e:
            print("Something went wrong in MSG URL")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def eml_checker(self, file):
        try:
            with open(file, "rb") as eml_file:
                message = email.message_from_binary_file(eml_file)
                self.gui.append_text("From: " + str(message["From"]))
                self.gui.append_text("To: " + str(message["To"]))
                self.gui.append_text("Subject: " + str(message["Subject"]))
                self.gui.append_text("CC: " + str(message["CC"]))
                self.gui.append_text("BCC: " + str(message["BCC"]))
                self.gui.append_text("Email time: " + str(message["Date"]))

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

                        self.gui.append_content_message_text(payload)

                    if part.get("Content-Disposition"):
                        attachment_name = part.get_filename()
                        if attachment_name:
                            self.gui.append_attachment_text(attachment_name + "\n")

                self.gui.ip_grabber()
                self.gui.email_grabber()
                self.gui.url_grabber()
                self.gui.xHunter()
                self.gui.embed_attachments()

        except Exception as e:
            messagebox.showerror("Error", "Something went wrong verifying .eml file!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    def email_grabber(self):
        email = []
        try:
            file_open = open(self.gui.email_name, "r", encoding="utf-8")
            read_text = file_open.read()
            regex = re.findall(
                r"\b[A-Za-z0-9._%+-]{1,20}@[^=]+?\.[A-Za-z]{2,6}\b", read_text
            )
            if regex is not None:
                for match in regex:
                    if match not in email:
                        email.append(match)
                        self.gui.append_email_addresses_text(match + "\n")

        except Exception as e:
            show_error("Something went wrong in email grabber!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()
            exit()

    def ip_grabber(self):
        ip = []
        ip_count = 0
        try:
            file_open = open(self.gui.email_name, "r", encoding="utf-8")
            read_text = file_open.read()
            regex = re.findall(r"(?!.)\b(?:\d{1,3}\.){3}\d{1,3}\b", read_text)
            if regex is not None:
                for match in regex:
                    if match not in ip:
                        ip.append(match)
                        ip_count += 1
                        self.gui.append_ip_text(
                            match + " - " + check_ip_reputation(match) + "\n"
                        )

        except Exception as e:
            show_error("Something went wrong IP Grabber!")
            print(str(e) + "\n" + tb)
            traceback.print_exc()
            exit()

    def url_grabber(self):
        file_open = open(self.gui.email_name, "r", encoding="utf-8")
        read_text = file_open.read()
        url = []

        regex = re.findall(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            read_text,
        )

        try:
            if regex is not None:
                for match in regex:
                    if match not in url:
                        self.gui.append_url(match)
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
            with open(self.gui.email_name, "r", encoding="utf-8") as sample:
                for line in sample:
                    if line.startswith("X-"):
                        self.gui.append_xheader_text(line)
        except Exception as e:
            show_info("No X Headers observed")
            print(str(e) + "\n" + tb)
            traceback.print_exc()

    @staticmethod
    def verify_attachment_extension(attachment_name):
        unsafe_extensions = ["exe", "js", "vbs", "bat"]
        filename, file_extension = os.path.splitext(attachment_name)

        if "." in filename and file_extension.lstrip(".").lower() in unsafe_extensions:
            return False, "Attachment has unsafe and double extension."
        elif "." in filename:
            return False, "Attachment has double extension."
        elif file_extension.lstrip(".").lower() in unsafe_extensions:
            return False, "Attachment has unsafe extension."
        else:
            return True, ""

    def embed_attachments(self):
        try:
            with open(self.gui.email_name, "r", encoding="utf-8") as f:
                attach_file = email.message_from_file(f, policy=policy.default)
                for attachment in attach_file.iter_attachments():
                    att_name = attachment.get_filename()
                    valid, message = self.gui.verify_attachment_extension(att_name)
                    if valid:
                        show_info("File Found & Written In Attachments: " + att_name)
                        with open(
                            os.path.join(exported_path(), att_name), "wb"
                        ) as fileWrite:
                            fileWrite.write(attachment.get_payload(decode=True))
                    else:
                        show_error(
                            "Attachment "
                            + att_name
                            + " could not be written in Attachments. "
                            + message
                        )

        except Exception as e:
            show_error("Something went wrong in embed attachments")
            print(str(e) + "\n" + tb)
            traceback.print_exc()
