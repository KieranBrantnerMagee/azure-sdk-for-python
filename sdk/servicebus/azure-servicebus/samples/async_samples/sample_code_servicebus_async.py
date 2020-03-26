# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""
Examples to show basic async use case of python azure-servicebus SDK, including:
    - Create ServiceBusClient
    - Create ServiceBusSender/ServiceBusReceiver
    - Send single message
    - Receive and settle messages
    - Receive and settle deferred messages
"""
import asyncio
from azure.servicebus.aio import Message


def example_create_servicebus_client_async():
    # [START create_sb_client_from_conn_str_async]
    import os
    from azure.servicebus.aio import ServiceBusClient
    servicebus_connection_str = os.environ['SERVICE_BUS_CONNECTION_STR']
    servicebus_client = ServiceBusClient.from_connection_string(conn_str=servicebus_connection_str)
    # [END create_sb_client_from_conn_str_async]

    # [START create_sb_client_async]
    import os
    from azure.servicebus.aio import ServiceBusClient, ServiceBusSharedKeyCredential
    fully_qualified_namespace = os.environ['SERVICE_BUS_CONNECTION_STR']
    shared_access_policy = os.environ['SERVICE_BUS_SAS_POLICY']
    shared_access_key = os.environ['SERVICE_BUS_SAS_KEY']
    servicebus_client = ServiceBusClient(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=ServiceBusSharedKeyCredential(
            shared_access_policy,
            shared_access_key
        )
    )
    # [END create_sb_client_async]
    return servicebus_client


async def example_create_servicebus_sender_async():
    servicebus_client = example_create_servicebus_client_async()
    # [START create_servicebus_sender_from_conn_str_async]
    import os
    from azure.servicebus.aio import ServiceBusSender
    servicebus_connection_str = os.environ['SERVICE_BUS_CONNECTION_STR']
    queue_name = os.environ['SERVICE_BUS_QUEUE_NAME']
    queue_sender = ServiceBusSender.from_connection_string(
        conn_str=servicebus_connection_str,
        queue_name=queue_name
    )
    # [END create_servicebus_sender_from_conn_str_async]

    # [START create_servicebus_sender_async]
    import os
    from azure.servicebus.aio import ServiceBusSender, ServiceBusSharedKeyCredential
    fully_qualified_namespace = os.environ['SERVICE_BUS_CONNECTION_STR']
    shared_access_policy = os.environ['SERVICE_BUS_SAS_POLICY']
    shared_access_key = os.environ['SERVICE_BUS_SAS_KEY']
    queue_name = os.environ['SERVICE_BUS_QUEUE_NAME']
    queue_sender = ServiceBusSender(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=ServiceBusSharedKeyCredential(
            shared_access_policy,
            shared_access_key
        ),
        queue_name=queue_name
    )
    # [END create_servicebus_sender_async]

    # [START create_servicebus_sender_from_sb_client_async]
    import os
    from azure.servicebus.aio import ServiceBusClient
    servicebus_connection_str = os.environ['SERVICE_BUS_CONNECTION_STR']
    queue_name = os.environ['SERVICE_BUS_QUEUE_NAME']
    servicebus_client = ServiceBusClient.from_connection_string(conn_str=servicebus_connection_str)
    async with servicebus_client:
        queue_sender = servicebus_client.get_queue_sender(queue_name=queue_name)
    # [END create_servicebus_sender_from_sb_client_async]
    return queue_sender


async def example_create_servicebus_receiver_async():
    servicebus_client = example_create_servicebus_client_async()

    # [START create_servicebus_receiver_from_conn_str_async]
    import os
    from azure.servicebus.aio import ServiceBusReceiver
    servicebus_connection_str = os.environ['SERVICE_BUS_CONNECTION_STR']
    queue_name = os.environ['SERVICE_BUS_QUEUE_NAME']
    queue_receiver = ServiceBusReceiver.from_connection_string(
        conn_str=servicebus_connection_str,
        queue_name=queue_name
    )
    # [END create_servicebus_receiver_from_conn_str_async]

    # [START create_servicebus_receiver_async]
    import os
    from azure.servicebus.aio import ServiceBusReceiver, ServiceBusSharedKeyCredential
    fully_qualified_namespace = os.environ['SERVICE_BUS_CONNECTION_STR']
    shared_access_policy = os.environ['SERVICE_BUS_SAS_POLICY']
    shared_access_key = os.environ['SERVICE_BUS_SAS_KEY']
    queue_name = os.environ['SERVICE_BUS_QUEUE_NAME']
    queue_receiver = ServiceBusReceiver(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=ServiceBusSharedKeyCredential(
            shared_access_policy,
            shared_access_key
        ),
        queue_name=queue_name
    )
    # [END create_servicebus_receiver_async]

    # [START create_servicebus_receiver_from_sb_client_async]
    import os
    from azure.servicebus.aio import ServiceBusClient
    servicebus_connection_str = os.environ['SERVICE_BUS_CONNECTION_STR']
    queue_name = os.environ['SERVICE_BUS_QUEUE_NAME']
    servicebus_client = ServiceBusClient.from_connection_string(conn_str=servicebus_connection_str)
    async with servicebus_client:
        queue_receiver = servicebus_client.get_queue_receiver(queue_name=queue_name)
    # [END create_servicebus_receiver_from_sb_client_async]

    return queue_receiver


async def example_send_and_receive_async():
    servicebus_sender = await example_create_servicebus_sender_async()
    servicebus_receiver = await example_create_servicebus_receiver_async()

    from azure.servicebus.aio import Message
    # [START servicebus_sender_send_async]
    async with servicebus_sender:
        message = Message("Hello World")
        await servicebus_sender.send(message)
    # [END servicebus_sender_send_async]

    # [START servicebus_receiver_receive_async]
    async with servicebus_receiver:
        messages = await servicebus_receiver.receive(timeout=5)
        for message in messages:
            print(message)
            await message.complete()
    # [END servicebus_receiver_receive_async]


async def example_receive_deferred_async():
    servicebus_sender = await example_create_servicebus_sender_async()
    servicebus_receiver = await example_create_servicebus_receiver_async()
    async with servicebus_sender:
        await servicebus_sender.send(Message("Hello World"))
    # [START servicebus_receiver_receive_defer_async]
    async with servicebus_receiver:
        deferred_sequenced_numbers = []
        messages = await servicebus_receiver.receive(timeout=5)
        for message in messages:
            deferred_sequenced_numbers.append(message.sequence_number)
            print(message)
            await message.defer()

        received_deferred_msg = await servicebus_receiver.receive_deferred_messages(
            sequence_numbers=deferred_sequenced_numbers
        )

        for msg in received_deferred_msg:
            await msg.complete()
    # [END servicebus_receiver_receive_defer_async]


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(example_send_and_receive_async())
    loop.run_until_complete(example_receive_deferred_async())
