# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from ._bare_metal_infrastructure_client import BareMetalInfrastructureClient
from ._version import VERSION

__version__ = VERSION
__all__ = ['BareMetalInfrastructureClient']

try:
    from ._patch import patch_sdk  # type: ignore
    patch_sdk()
except ImportError:
    pass
