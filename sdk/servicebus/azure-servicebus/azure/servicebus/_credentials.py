# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import collections
import time
from datetime import timedelta
from typing import Optional, Any, Union, TYPE_CHECKING

try:
    from urllib import quote_plus  # type: ignore
except ImportError:
    from urllib.parse import quote_plus

from uamqp import utils

from azure.core.credentials import AccessToken

from ._common.constants import TOKEN_TYPE_SASTOKEN

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

_AccessToken = collections.namedtuple("AccessToken", "token expires_on")

def _generate_sas_token(uri, policy, key, expiry=None):
    # type: (str, str, str, Optional[timedelta]) -> _AccessToken
    """Create a shared access signiture token as a string literal.
    :returns: SAS token as string literal.
    :rtype: str
    """
    if not expiry:
        expiry = timedelta(hours=1)  # Default to 1 hour.

    abs_expiry = int(time.time()) + expiry.seconds
    encoded_uri = quote_plus(uri).encode("utf-8")  # pylint: disable=no-member
    encoded_policy = quote_plus(policy).encode("utf-8")  # pylint: disable=no-member
    encoded_key = key.encode("utf-8")

    token = utils.create_sas_token(encoded_policy, encoded_key, encoded_uri, expiry)
    return _AccessToken(token=token, expires_on=abs_expiry)


class ServiceBusSharedTokenCredential(object):
    """The shared access token credential used for authentication.
    :param str token: The shared access token string
    :param int expiry: The epoch timestamp
    """
    def __init__(self, token, expiry):
        # type: (str, int) -> None
        """
        :param str token: The shared access token string
        :param float expiry: The epoch timestamp
        """
        self.token = token
        self.expiry = expiry
        self.token_type = b"servicebus.windows.net:sastoken"

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (str, Any) -> AccessToken
        """
        This method is automatically called when token is about to expire.
        """
        return AccessToken(self.token, self.expiry)


class ServiceBusSharedKeyCredential(object):
    """The shared access key credential used for authentication.

    :param str policy: The name of the shared access policy.
    :param str key: The shared access key.
    """

    def __init__(self, policy, key):
        # type: (str, str) -> None
        self.policy = policy
        self.key = key
        self.token_type = TOKEN_TYPE_SASTOKEN

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (str, Any) -> _AccessToken
        if not scopes:
            raise ValueError("No token scope provided.")
        return _generate_sas_token(scopes[0], self.policy, self.key)

ServiceBusValidCredentialTypes = Union[
    "TokenCredential", ServiceBusSharedKeyCredential, ServiceBusSharedTokenCredential]
