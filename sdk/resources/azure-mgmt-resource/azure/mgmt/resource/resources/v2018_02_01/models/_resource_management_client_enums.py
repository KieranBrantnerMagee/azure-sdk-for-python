# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum

class DeploymentMode(str, Enum):
    """The mode that is used to deploy resources. This value can be either Incremental or Complete. In
    Incremental mode, resources are deployed without deleting existing resources that are not
    included in the template. In Complete mode, resources are deployed and existing resources in
    the resource group that are not included in the template are deleted. Be careful when using
    Complete mode as you may unintentionally delete resources.
    """

    incremental = "Incremental"
    complete = "Complete"

class OnErrorDeploymentType(str, Enum):
    """The deployment on error behavior type. Possible values are LastSuccessful and
    SpecificDeployment.
    """

    last_successful = "LastSuccessful"
    specific_deployment = "SpecificDeployment"

class ResourceIdentityType(str, Enum):
    """The identity type.
    """

    system_assigned = "SystemAssigned"
    user_assigned = "UserAssigned"
    system_assigned_user_assigned = "SystemAssigned, UserAssigned"
    none = "None"
