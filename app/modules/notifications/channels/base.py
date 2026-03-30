from abc import ABC, abstractmethod
from app.modules.notifications.schemas import AlertPayload


class BaseChannel(ABC):
    """
    Abstract base class for notification channels.
    
    To add a new channel (e.g., Slack):
    1. Create channels/slack.py
    2. Inherit from BaseChannel
    3. Implement send()
    4. Register in NotificationService
    """

    @abstractmethod
    async def send(self, payload: AlertPayload, recipients: list[str]) -> bool:
        """
        Send an alert notification.
        Returns True if sent successfully, False otherwise.
        """
        pass
