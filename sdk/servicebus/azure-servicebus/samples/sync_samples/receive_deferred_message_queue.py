#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Example to show receiving deferred message from a Service Bus Queue.
"""

# pylint: disable=C0111

import os
from azure.servicebus import ServiceBusClient

CONNECTION_STR = os.environ['SERVICE_BUS_CONNECTION_STR']
QUEUE_NAME = os.environ["SERVICE_BUS_QUEUE_NAME"]

servicebus_client = ServiceBusClient.from_connection_string(
    conn_str=CONNECTION_STR,
)

receiver = servicebus_client.get_queue_receiver(
    queue_name=QUEUE_NAME
)

with servicebus_client:
    with receiver:
        received_msgs = receiver.receive(max_batch_size=10, timeout=5)
        deferred_sequenced_numbers = []
        for msg in received_msgs:
            print("Deferring msg: {}".format(str(msg)))
            deferred_sequenced_numbers.append(msg.sequence_number)
            msg.defer()

        received_deferred_msg = receiver.receive_deferred_messages(
            sequence_numbers=deferred_sequenced_numbers
        )

        for msg in received_deferred_msg:
            print("Completing deferred msg: {}".format(str(msg)))
            msg.complete()

print("Receive is done.")
