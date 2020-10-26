# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import os
import sys
import logging
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import HttpResponseError
from azure.digitaltwins.core import DigitalTwinsClient

# Simple example of how to:
# - create a DigitalTwins Service Client using the DigitalTwinsClient constructor
# - get digital twin
#
# Preconditions:
# - Environment variables have to be set
# - DigitalTwins enabled device must exist on the ADT hub
try:
    # DefaultAzureCredential supports different authentication mechanisms and determines
    # the appropriate credential type based of the environment it is executing in.
    # It attempts to use multiple credential types in an order until it finds a working credential.

    # - AZURE_URL: The tenant ID in Azure Active Directory
    url = os.getenv("AZURE_URL")

    # DefaultAzureCredential expects the following three environment variables:
    # - AZURE_TENANT_ID: The tenant ID in Azure Active Directory
    # - AZURE_CLIENT_ID: The application (client) ID registered in the AAD tenant
    # - AZURE_CLIENT_SECRET: The client secret for the registered application
    credential = DefaultAzureCredential()

    # Create logger
    logger = logging.getLogger('azure')
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(stream=sys.stdout)
    logger.addHandler(handler)

    # Create service client and enable logging for all operations
    service_client = DigitalTwinsClient(url, credential, logging_enable=True)

    # DigitalTwinId from the samples: 
    #   BuildingTwin
    #   FloorTwin
    #   HVACTwin
    #   RoomTwin
    digital_twint_id = "<DIGITAL_TWIN_ID>"

    # Get twin
    digital_twin = service_client.get_digital_twin(digital_twint_id)

    print(digital_twin)

except HttpResponseError as e:
    print("\nThis sample has caught an error. {0}".format(e.message))
