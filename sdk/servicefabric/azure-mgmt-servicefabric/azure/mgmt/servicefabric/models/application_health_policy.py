# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ApplicationHealthPolicy(Model):
    """Defines a health policy used to evaluate the health of an application or
    one of its children entities.
    .

    :param default_service_type_health_policy: The health policy used by
     default to evaluate the health of a service type.
    :type default_service_type_health_policy:
     ~azure.mgmt.servicefabric.models.ServiceTypeHealthPolicy
    :param service_type_health_policies: The map with service type health
     policy per service type name. The map is empty by default.
    :type service_type_health_policies: dict[str,
     ~azure.mgmt.servicefabric.models.ServiceTypeHealthPolicy]
    """

    _attribute_map = {
        'default_service_type_health_policy': {'key': 'defaultServiceTypeHealthPolicy', 'type': 'ServiceTypeHealthPolicy'},
        'service_type_health_policies': {'key': 'serviceTypeHealthPolicies', 'type': '{ServiceTypeHealthPolicy}'},
    }

    def __init__(self, **kwargs):
        super(ApplicationHealthPolicy, self).__init__(**kwargs)
        self.default_service_type_health_policy = kwargs.get('default_service_type_health_policy', None)
        self.service_type_health_policies = kwargs.get('service_type_health_policies', None)