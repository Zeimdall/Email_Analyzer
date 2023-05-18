import re


class AttachmentViewer:
    def __init__(self, attachments, attachment_text):
        self.attachment_text = attachment_text
        self.attachment_names = []
        for attachment in attachments:
            attachment_name = self.get_attachment_name(attachment)
            self.attachment_names.append(attachment_name)

    @staticmethod
    def get_attachment_name(attachment):
        if isinstance(attachment, tuple):
            attachment_name = attachment[0]
        else:
            content_disposition = attachment.get("Content-Disposition")
            if content_disposition:
                match = re.search(r'filename="(.+)"', content_disposition)
                if match:
                    attachment_name = match.group(1)
                else:
                    attachment_name = "Unknown Filename"
            else:
                attachment_name = "Unknown Filename"

        return attachment_name
