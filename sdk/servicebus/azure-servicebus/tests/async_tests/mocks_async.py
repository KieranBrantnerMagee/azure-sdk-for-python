from datetime import timedelta

from azure.servicebus._common.utils import utc_now

class MockReceivedMessage:
    def __init__(self, prevent_renew_lock=False, exception_on_renew_lock=False):
        self._lock_duration = 2

        self.received_timestamp_utc = utc_now()
        self.locked_until_utc = self.received_timestamp_utc + timedelta(seconds=self._lock_duration)
        self.settled = False

        self._prevent_renew_lock = prevent_renew_lock
        self._exception_on_renew_lock = exception_on_renew_lock


    async def renew_lock(self):
        if self._exception_on_renew_lock:
            raise Exception("Generated exception via MockReceivedMessage exception_on_renew_lock")
        if not self._prevent_renew_lock:
            self.locked_until_utc = self.locked_until_utc + timedelta(seconds=self._lock_duration)

    @property
    def expired(self):
        if self.locked_until_utc and self.locked_until_utc <= utc_now():
            return True
        return False