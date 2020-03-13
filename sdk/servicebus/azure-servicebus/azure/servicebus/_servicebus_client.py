# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from typing import Any, TYPE_CHECKING

import uamqp

from ._base_handler import _parse_conn_str, ServiceBusSharedKeyCredential
from ._servicebus_sender import ServiceBusSender
from ._servicebus_receiver import ServiceBusReceiver
from .common._configuration import Configuration
from .common.utils import create_authentication

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

    .. admonition:: Example:

        .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
            :start-after: [START create_sb_client_sync]
            :end-before: [END create_sb_client_sync]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the ServiceBusClient.

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
        self._connection = None
        self._auth_uri = "sb://{}".format(self.fully_qualified_namespace)

    def __enter__(self):
        self._create_uamqp_connection()
        return self

    def __exit__(self, *args):
        self.close()
        pass

    def _create_uamqp_connection(self):
        auth = create_authentication(self)
        self._connection = uamqp.Connection(
            hostname=self.fully_qualified_namespace,
            sasl=auth,
            debug=self._config.logging_enable
        )

    def close(self) -> None:
        """
        Close down the ServiceBus client.

        :return: None
        """
        self._connection.destroy()

    @classmethod
    def from_connection_string(
        cls,
        conn_str,
        **kwargs
    ):
        # type: (str, Any) -> ServiceBusClient
        """
        Create a ServiceBusClient from a connection string.

        :param conn_str: The connection string of a Service Bus.
        :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
        :keyword transport_type: The type of transport protocol that will be used for communicating with
         the Service Bus service. Default is `TransportType.Amqp`.
        :paramtype transport_type: ~azure.servicebus.TransportType
        :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
         Additionally the following keys may also be present: `'username', 'password'`.
        :rtype: ~azure.servicebus.ServiceBusClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START create_sb_client_from_conn_str_sync]
                :end-before: [END create_sb_client_from_conn_str_sync]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusClient from connection string.

        """
        host, policy, key, _ = _parse_conn_str(conn_str)
        return cls(
            fully_qualified_namespace=host,
            credential=ServiceBusSharedKeyCredential(policy, key),
            **kwargs
        )

    def get_queue_sender(self, queue_name, **kwargs):
        # type: (str, Any) -> ServiceBusSender
        """Get ServiceBusSender for the specific queue.

        :param str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        :rtype: ~azure.servicebus.ServiceBusSender
        :raises: :class:`ServiceBusConnectionError`
         :class:`ServiceBusAuthorizationError`

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START create_servicebus_sender_from_sb_client_sync]
                :end-before: [END create_servicebus_sender_from_sb_client_sync]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusSender from ServiceBusClient.

        """
        sender = ServiceBusSender(
            fully_qualified_namespace=self.fully_qualified_namespace,
            queue_name=queue_name,
            credential=self._credential,
            logging_enable=self._config.logging_enable,
            connection=self._connection,
            **kwargs
        )
        sender._open_with_retry()  # pylint: disable=protected-access
        return sender

    def get_queue_receiver(self, queue_name, **kwargs):
        # type: (str, Any) -> ServiceBusReceiver
        """Get ServiceBusReceiver for the specific queue.

        :param str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        :rtype: ~azure.servicebus.ServiceBusReceiver
        :raises: :class:`ServiceBusConnectionError`
         :class:`ServiceBusAuthorizationError`

        .. admonition:: Example:

            .. literalinclude:: ../samples/sync_samples/sample_code_servicebus.py
                :start-after: [START create_servicebus_receiver_from_sb_client_sync]
                :end-before: [END create_servicebus_receiver_from_sb_client_sync]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusReceiver from ServiceBusClient.


        """
        receiver = ServiceBusReceiver(
            fully_qualified_namespace=self.fully_qualified_namespace,
            queue_name=queue_name,
            credential=self._credential,
            logging_enable=self._config.logging_enable,
            connection=self._connection,
            **kwargs
        )
        receiver._open_with_retry()  # pylint: disable=protected-access
        return receiver
