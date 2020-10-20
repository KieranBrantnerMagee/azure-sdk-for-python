# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from typing import Any, TYPE_CHECKING, Union

from azure.core.credentials import AccessToken

from .._credentials import _generate_sas_token, _AccessToken
from .._common.constants import TOKEN_TYPE_SASTOKEN

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential

class ServiceBusSharedTokenCredential(object):
    """The shared access token credential used for authentication.
    :param str token: The shared access token string
    :param int expiry: The epoch timestamp
    """
    def __init__(self, token: str, expiry: int) -> None:
        """
        :param str token: The shared access token string
        :param int expiry: The epoch timestamp
        """
        self.token = token
        self.expiry = expiry
        self.token_type = b"servicebus.windows.net:sastoken"

    async def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:  # pylint:disable=unused-argument
        """
        This method is automatically called when token is about to expire.
        """
        return AccessToken(self.token, self.expiry)


class ServiceBusSharedKeyCredential(object):
    """The shared access key credential used for authentication.

    :param str policy: The name of the shared access policy.
    :param str key: The shared access key.
    """

    def __init__(self, policy: str, key: str) -> None:
        self.policy = policy
        self.key = key
        self.token_type = TOKEN_TYPE_SASTOKEN

    async def get_token(self, *scopes: str, **kwargs: Any) -> _AccessToken:  # pylint:disable=unused-argument
        if not scopes:
            raise ValueError("No token scope provided.")
        return _generate_sas_token(scopes[0], self.policy, self.key)

ServiceBusValidAsyncCredentialTypes = Union[
    "AsyncTokenCredential", ServiceBusSharedKeyCredential, ServiceBusSharedTokenCredential]
