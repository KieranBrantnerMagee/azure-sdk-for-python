# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import logging
import asyncio
from typing import TYPE_CHECKING, Any

import uamqp
from uamqp import (
    constants,
    errors
)
from uamqp.message import MessageProperties

from .._base_handler import BaseHandler, _generate_sas_token
from ..common.errors import (
    InvalidHandlerState,
    ServiceBusError,
    ServiceBusConnectionError,
    ServiceBusAuthorizationError,
    MessageSendFailed
)

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

_LOGGER = logging.getLogger(__name__)


class ServiceBusSharedKeyCredential(object):
    """The shared access key credential used for authentication.

    :param str policy: The name of the shared access policy.
    :param str key: The shared access key.
    """

    def __init__(self, policy: str, key: str):
        self.policy = policy
        self.key = key
        self.token_type = b"servicebus.windows.net:sastoken"

    async def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        if not scopes:
            raise ValueError("No token scope provided.")
        return _generate_sas_token(scopes[0], self.policy, self.key)


class BaseHandlerAsync(BaseHandler):
    def __init__(
        self,
        fully_qualified_namespace: str,
        entity_name: str,
        credential: "TokenCredential",
        **kwargs: Any
    ) -> None:
        self._loop = kwargs.pop("loop", None)
        super(BaseHandlerAsync, self).__init__(
            fully_qualified_namespace=fully_qualified_namespace,
            entity_name=entity_name,
            credential=credential,
            **kwargs
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _handle_exception(self, exception):
        if isinstance(exception, (errors.LinkDetach, errors.ConnectionClose)):
            if exception.condition == constants.ErrorCodes.UnauthorizedAccess:
                _LOGGER.info("Async handler detached. Shutting down.")
                error = ServiceBusAuthorizationError(str(exception), exception)
                await self._close_handler()
                return error
            _LOGGER.info("Async handler detached. Shutting down.")
            error = ServiceBusConnectionError(str(exception), exception)
            await self._close_handler()
            return error
        if isinstance(exception, errors.MessageHandlerError):
            _LOGGER.info("Async handler error. Shutting down.")
            error = ServiceBusConnectionError(str(exception), exception)
            await self._close_handler()
            return error
        if isinstance(exception, errors.AMQPConnectionError):
            message = "Failed to open handler: {}".format(exception)
            await self._close_handler()
            return ServiceBusConnectionError(message, exception)
        if isinstance(exception, MessageSendFailed):
            _LOGGER.info("Message send error (%r)", exception)
            raise exception

        _LOGGER.info("Unexpected error occurred (%r). Shutting down.", exception)
        error = exception
        if not isinstance(exception, ServiceBusError):
            error = ServiceBusError("Handler failed: {}".format(exception), exception)
        await self._close_handler()
        raise error

    async def _backoff(
            self,
            retried_times,
            last_exception,
            timeout=None,
            entity_name=None
    ):
        entity_name = entity_name or self._container_id
        backoff = self._config.retry_backoff_factor * 2 ** retried_times
        if backoff <= self._config.retry_backoff_max and (
                timeout is None or backoff <= timeout
        ):
            await asyncio.sleep(backoff)
            _LOGGER.info(
                "%r has an exception (%r). Retrying...",
                entity_name,
                last_exception,
            )
        else:
            _LOGGER.info(
                "%r operation has timed out. Last exception before timeout is (%r)",
                entity_name,
                last_exception,
            )
            raise last_exception

    async def _do_retryable_operation(self, operation, timeout=None, **kwargs):
        require_last_exception = kwargs.pop("require_last_exception", False)
        require_timeout = kwargs.pop("require_timeout", False)
        retried_times = 0
        last_exception = None
        max_retries = self._config.retry_total

        while retried_times <= max_retries:
            try:
                if require_last_exception:
                    kwargs["last_exception"] = last_exception
                if require_timeout:
                    kwargs["timeout"] = timeout
                return await operation(**kwargs)
            except Exception as exception:  # pylint: disable=broad-except
                last_exception = await self._handle_exception(exception)
                retried_times += 1
                if retried_times > max_retries:
                    break
                await self._backoff(
                    retried_times=retried_times,
                    last_exception=last_exception,
                    timeout=timeout
                )

        _LOGGER.info(
            "%r operation has exhausted retry. Last exception: %r.",
            self._container_id,
            last_exception,
        )
        raise last_exception

    async def _mgmt_request_response(self, mgmt_operation, message, callback, **kwargs):
        await self._open()
        if not self._running:
            raise InvalidHandlerState("Client connection is closed.")

        mgmt_msg = uamqp.Message(
            body=message,
            properties=MessageProperties(
                reply_to=self._mgmt_target,
                encoding=self._config.encoding,
                **kwargs))
        try:
            return await self._handler.mgmt_request_async(
                mgmt_msg,
                mgmt_operation,
                op_type=b"entity-mgmt",
                node=self._mgmt_target.encode(self._config.encoding),
                timeout=5000,
                callback=callback)
        except Exception as exp:  # pylint: disable=broad-except
            raise ServiceBusError("Management request failed: {}".format(exp), exp)

    async def _mgmt_request_response_with_retry(self, mgmt_operation, message, callback, **kwargs):
        return await self._do_retryable_operation(
            self._mgmt_request_response,
            mgmt_operation=mgmt_operation,
            message=message,
            callback=callback,
            **kwargs
        )

    @staticmethod
    def _from_connection_string(conn_str, **kwargs):
        kwargs = BaseHandler._from_connection_string(conn_str, **kwargs)
        kwargs["credential"] = ServiceBusSharedKeyCredential(kwargs["credential"].policy, kwargs["credential"].key)
        return kwargs

    async def _open(self):  # pylint: disable=no-self-use
        raise ValueError("Subclass should override the method.")

    async def _open_with_retry(self):
        return await self._do_retryable_operation(self._open)

    async def _close_handler(self):
        if self._handler:
            await self._handler.close_async()
            self._handler = None
        self._running = False

    async def close(self, exception=None):
        # type: (Exception) -> None
        """Close down the handler connection.

        If the handler has already closed, this operation will do nothing. An optional exception can be passed in to
        indicate that the handler was shutdown due to error.

        :param Exception exception: An optional exception if the handler is closing
         due to an error.
        :rtype: None
        """
        if self._error:
            return
        if isinstance(exception, ServiceBusError):
            self._error = exception
        elif exception:
            self._error = ServiceBusError(str(exception))
        else:
            self._error = ServiceBusError("This message handler is now closed.")

        await self._close_handler()
