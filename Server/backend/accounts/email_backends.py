import os
from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail.message import EmailMessage
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class FileEmailBackend(BaseEmailBackend):
    """
    A custom email backend that logs email messages to a file (email/msg.txt)
    instead of sending them via SMTP.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Define the file path for logging emails
        self.file_path = os.path.join(settings.BASE_DIR, 'email', 'msg.txt')
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

    def send_messages(self, email_messages):
        """
        Write email messages to the specified file instead of sending them.
        
        Args:
            email_messages: List of EmailMessage objects to "send".
        
        Returns:
            Number of messages successfully written to the file.
        """
        if not email_messages:
            return 0

        num_sent = 0
        try:
            with open(self.file_path, 'a', encoding='utf-8') as f:
                for message in email_messages:
                    # Format the email message
                    email_content = (
                        f"--- Email ---\n"
                        f"From: {message.from_email}\n"
                        f"To: {', '.join(message.to)}\n"
                        f"Subject: {message.subject}\n"
                        f"Body:\n{message.body}\n"
                        f"{'-' * 50}\n\n"
                    )
                    f.write(email_content)
                    num_sent += 1
                    logger.info(f"Logged email to {self.file_path}: Subject={message.subject}")
        except Exception as e:
            logger.error(f"Failed to log email to {self.file_path}: {e}")
            if not self.fail_silently: # type: ignore
                raise

        return num_sent
    
