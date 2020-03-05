# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from typing import Any, TYPE_CHECKING

from .._base_handler import _parse_conn_str
from ._base_handler_async import ServiceBusSharedKeyCredential
from ._servicebus_sender_async import ServiceBusSender
from ._servicebus_receiver_async import ServiceBusReceiver
from ..common._configuration import Configuration

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential


class ServiceBusClient(object):
    """The ServiceBusClient class defines a high level interface for
    getting ServiceBusSender and ServiceBusReceiver.

    :param str fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
     The namespace format is: `<yournamespace>.servicebus.windows.net`.
    :param ~azure.core.credentials.TokenCredential credential: The credential object used for authentication which
     implements a particular interface for getting tokens. It accepts
     :class:`ServiceBusSharedKeyCredential<azure.servicebus.ServiceBusSharedKeyCredential>`, or credential objects
     generated by the azure-identity library and objects that implement the `get_token(self, *scopes)` method.
    :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
    :keyword transport_type: The type of transport protocol that will be used for communicating with
     the Service Bus service. Default is `TransportType.Amqp`.
    :paramtype transport_type: ~azure.servicebus.TransportType
    :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
     keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
     Additionally the following keys may also be present: `'username', 'password'`.
    """
    def __init__(
        self,
        fully_qualified_namespace,
        credential,
        **kwargs
    ):
        # type: (str, TokenCredential, Any) -> None
        self.fully_qualified_namespace = fully_qualified_namespace
        self._credential = credential
        self._config = Configuration(**kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    @classmethod
    def from_connection_string(
        cls,
        conn_str,
        **kwargs
    ):
        # type: (str, Any) -> ServiceBusClient
        host, policy, key, _ = _parse_conn_str(conn_str)
        return cls(
            fully_qualified_namespace=host,
            credential=ServiceBusSharedKeyCredential(policy, key),
            **kwargs
        )

    async def close(self):
        pass

    def get_queue_sender(self, queue_name, **kwargs):
        """Get ServiceBusSender for the specific queue.

        :param str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        """
        return ServiceBusSender(
            fully_qualified_namespace=self.fully_qualified_namespace,
            queue_name=queue_name,
            credential=self._credential,
            logging_enable=self._config.logging_enable,
            **kwargs
        )

    def get_queue_receiver(self, queue_name, **kwargs):
        """Get ServiceBusReceiver for the specific queue.

        :param str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        """
        return ServiceBusReceiver(
            fully_qualified_namespace=self.fully_qualified_namespace,
            queue_name=queue_name,
            credential=self._credential,
            logging_enable=self._config.logging_enable,
            **kwargs
        )
