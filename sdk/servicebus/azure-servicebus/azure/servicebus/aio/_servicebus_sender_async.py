# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import logging
import asyncio
from typing import Any, TYPE_CHECKING

from uamqp import SendClientAsync

from ..common.message import Message
from .._servicebus_sender import SenderMixin
from ._base_handler_async import BaseHandlerAsync
from ..common.errors import (
    MessageSendFailed
)
from ..common.utils import create_properties

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class ServiceBusSender(BaseHandlerAsync, SenderMixin):
    """The ServiceBusSender class defines a high level interface for
    sending messages to the Azure Service Bus Queue or Topic.

    :param str fully_qualified_namespace: The fully qualified host name for the Service Bus namespace.
     The namespace format is: `<yournamespace>.servicebus.windows.net`.
    :param ~azure.core.credentials.TokenCredential credential: The credential object used for authentication which
     implements a particular interface for getting tokens. It accepts
     :class:`ServiceBusSharedKeyCredential<azure.servicebus.ServiceBusSharedKeyCredential>`, or credential objects
     generated by the azure-identity library and objects that implement the `get_token(self, *scopes)` method.
    :keyword str queue_name: The path of specific Service Bus Queue the client connects to.
    :keyword str topic_name: The path of specific Service Bus Topic the client connects to.
    :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
    :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
     Default value is 3.
    :keyword transport_type: The type of transport protocol that will be used for communicating with
     the Service Bus service. Default is `TransportType.Amqp`.
    :paramtype transport_type: ~azure.servicebus.TransportType
    :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
     keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
     Additionally the following keys may also be present: `'username', 'password'`.

    .. admonition:: Example:

        .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
            :start-after: [START create_servicebus_sender_async]
            :end-before: [END create_servicebus_sender_async]
            :language: python
            :dedent: 4
            :caption: Create a new instance of the ServiceBusSender.

    """
    def __init__(
        self,
        fully_qualified_namespace: str,
        credential: "TokenCredential",
        **kwargs: Any
    ):
        if kwargs.get("from_connection_str", False):
            super(ServiceBusSender, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                **kwargs
            )
        else:
            queue_name = kwargs.get("queue_name")
            topic_name = kwargs.get("topic_name")
            if queue_name and topic_name:
                raise ValueError("Queue/Topic name can not be specified simultaneously.")
            if not (queue_name or topic_name):
                raise ValueError("Queue/Topic name is missing. Please specify queue_name/topic_name.")
            entity_name = queue_name or topic_name
            super(ServiceBusSender, self).__init__(
                fully_qualified_namespace=fully_qualified_namespace,
                credential=credential,
                entity_name=str(entity_name),
                **kwargs
            )

        self._create_attribute()

    def _create_handler(self, auth):
        properties = create_properties()
        self._handler = SendClientAsync(
            self._entity_uri,
            auth=auth,
            debug=self._config.logging_enable,
            properties=properties,
            error_policy=self._error_policy,
            client_name=self._name,
            encoding=self._config.encoding
        )

    async def _open(self):
        if self._running:
            return
        if self._handler:
            await self._handler.close_async()
        auth = await self._create_auth()
        self._create_handler(auth)
        await self._handler.open_async()
        while not await self._handler.client_ready_async():
            await asyncio.sleep(0.05)
        self._running = True

    async def _send(self, message, session_id=None, timeout=None, last_exception=None):
        await self._open()
        self._set_msg_timeout(timeout, last_exception)
        if session_id and not message.properties.group_id:
            message.properties.group_id = session_id
        try:
            await self._handler.send_message_async(message.message)
        except Exception as e:
            raise MessageSendFailed(e)

    @classmethod
    def from_connection_string(
        cls,
        conn_str: str,
        **kwargs: Any,
    ) -> "ServiceBusSender":
        """Create a ServiceBusSender from a connection string.

        :param conn_str: The connection string of a Service Bus.
        :keyword str queue_name: The path of specific Service Bus Queue the client connects to.
        :keyword str topic_name: The path of specific Service Bus Topic the client connects to.
        :keyword bool logging_enable: Whether to output network trace logs to the logger. Default is `False`.
        :keyword int retry_total: The total number of attempts to redo a failed operation when an error occurs.
         Default value is 3.
        :keyword transport_type: The type of transport protocol that will be used for communicating with
         the Service Bus service. Default is `TransportType.Amqp`.
        :paramtype transport_type: ~azure.servicebus.TransportType
        :keyword dict http_proxy: HTTP proxy settings. This must be a dictionary with the following
         keys: `'proxy_hostname'` (str value) and `'proxy_port'` (int value).
         Additionally the following keys may also be present: `'username', 'password'`.
        :rtype: ~azure.servicebus.aio.ServiceBusSender

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START create_servicebus_sender_from_conn_str_async]
                :end-before: [END create_servicebus_sender_from_conn_str_async]
                :language: python
                :dedent: 4
                :caption: Create a new instance of the ServiceBusSender from connection string.

        """
        constructor_args = cls._from_connection_string(
            conn_str,
            **kwargs
        )
        return cls(**constructor_args)

    async def send(self, message, session_id=None, message_timeout=None):
        # type: (Message, str, float) -> None
        """Sends message and blocks until acknowledgement is received or operation times out.

        :param message: The ServiceBus message to be sent.
        :type message: ~azure.servicebus.aio.Message
        :param session_id: An optional session ID. If supplied this session ID will be
         applied to every outgoing message sent with this Sender.
         If an individual message already has a session ID, that will be used instead.
        :param float message_timeout: The maximum wait time to send the event data.
        :rtype: None
        :raises: ~azure.servicebus.common.errors.MessageSendFailed if the message fails to
         send or ~azure.servicebus.common.errors.OperationTimeoutError if sending times out.

        .. admonition:: Example:

            .. literalinclude:: ../samples/async_samples/sample_code_servicebus_async.py
                :start-after: [START servicebus_sender_send_async]
                :end-before: [END servicebus_sender_send_async]
                :language: python
                :dedent: 4
                :caption: Send message.

        """
        await self._do_retryable_operation(
            self._send,
            message=message,
            session_id=session_id,
            timeout=message_timeout,
            require_timeout=True,
            require_last_exception=True
        )
