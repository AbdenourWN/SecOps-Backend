from app.core.database import get_database
from app.core.config import settings
from app.modules.notifications.schemas import AlertPayload, NotificationChannel
from app.modules.notifications.channels.email import EmailChannel


# Severity ranking for min_severity filtering
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class NotificationService:
    """
    Central notification service that:
    1. Looks up notification config from DB (or falls back to .env)
    2. Filters by min_severity
    3. Dispatches to the correct channel (email, future: slack/teams)
    """

    async def send_alert(self, payload: AlertPayload):
        """
        Called by the analysis engine when a Level 2/3 incident is created.
        Looks up all enabled notification configs and dispatches.
        """
        db = get_database()

        # 1. Get all enabled notification configs
        configs = await db["notification_configs"].find(
            {"enabled": True}
        ).to_list(length=50)

        # If no DB config exists, fall back to .env recipients
        if not configs:
            env_recipients = [
                r.strip() for r in settings.ALERT_RECIPIENTS.split(",")
                if r.strip()
            ]
            if env_recipients and settings.SMTP_HOST:
                configs = [{
                    "channel": "email",
                    "recipients": env_recipients,
                    "min_severity": "medium",
                }]
            else:
                return  # No notification config at all

        # 2. Dispatch to each config
        for config in configs:
            # Check severity threshold
            min_sev = config.get("min_severity", "medium")
            if SEVERITY_RANK.get(payload.severity, 0) < SEVERITY_RANK.get(min_sev, 0):
                continue  # Severity too low for this config

            channel_type = config.get("channel", "email")
            recipients = config.get("recipients", [])

            if not recipients:
                continue

            # 3. Pick the channel
            if channel_type == NotificationChannel.EMAIL:
                channel = EmailChannel(
                    smtp_host=config.get("smtp_host"),
                    smtp_port=config.get("smtp_port"),
                    smtp_user=config.get("smtp_user"),
                    smtp_password=config.get("smtp_password"),
                )
                await channel.send(payload, recipients)

    async def get_configs(self):
        """Returns all notification configs."""
        db = get_database()
        configs = await db["notification_configs"].find().to_list(length=50)
        for c in configs:
            c["_id"] = str(c["_id"])
            # Never expose SMTP password
            if "smtp_password" in c:
                c["smtp_password"] = "***"
        return configs

    async def save_config(self, config_data: dict):
        """Creates or updates a notification config."""
        db = get_database()

        # Check if a config for this channel already exists
        existing = await db["notification_configs"].find_one(
            {"channel": config_data.get("channel", "email")}
        )

        if existing:
            # Build update payload: omit None values so we never wipe fields
            # the user didn't touch. smtp_password additionally skips empty
            # strings — a blank field means "leave the stored password as-is."
            update_payload = {
                k: v for k, v in config_data.items()
                if v is not None and not (k == "smtp_password" and v == "")
            }
            await db["notification_configs"].update_one(
                {"_id": existing["_id"]},
                {"$set": update_payload},
            )
            return {"status": "updated", "channel": config_data.get("channel")}
        else:
            # Create new
            await db["notification_configs"].insert_one(config_data)
            return {"status": "created", "channel": config_data.get("channel")}

    async def delete_config(self, channel: str):
        """Deletes a notification config by channel name."""
        db = get_database()
        result = await db["notification_configs"].delete_one({"channel": channel})
        return {"deleted": result.deleted_count > 0}

    async def test_alert(self):
        """Sends a test alert to verify the notification pipeline."""
        payload = AlertPayload(
            incident_id="test-000",
            server_id="test",
            server_hostname="test-server",
            server_ip="127.0.0.1",
            rule_name="Test Alert",
            severity="medium",
            description="This is a test alert to verify your notification setup is working.",
            context={"test": "true"},
            action_level=3,
        )
        await self.send_alert(payload)
        return {"status": "test_sent"}
