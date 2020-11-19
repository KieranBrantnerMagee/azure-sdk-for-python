# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import LogicManagementClientConfiguration
from .operations import WorkflowsOperations
from .operations import WorkflowVersionsOperations
from .operations import WorkflowTriggersOperations
from .operations import WorkflowVersionTriggersOperations
from .operations import WorkflowTriggerHistoriesOperations
from .operations import WorkflowRunsOperations
from .operations import WorkflowRunActionsOperations
from .operations import WorkflowRunActionRepetitionsOperations
from .operations import WorkflowRunActionRepetitionsRequestHistoriesOperations
from .operations import WorkflowRunActionRequestHistoriesOperations
from .operations import WorkflowRunActionScopeRepetitionsOperations
from .operations import WorkflowRunOperationsOperations
from .operations import IntegrationAccountsOperations
from .operations import IntegrationAccountAssembliesOperations
from .operations import IntegrationAccountBatchConfigurationsOperations
from .operations import IntegrationAccountSchemasOperations
from .operations import IntegrationAccountMapsOperations
from .operations import IntegrationAccountPartnersOperations
from .operations import IntegrationAccountAgreementsOperations
from .operations import IntegrationAccountCertificatesOperations
from .operations import IntegrationAccountSessionsOperations
from .operations import IntegrationServiceEnvironmentsOperations
from .operations import IntegrationServiceEnvironmentSkusOperations
from .operations import IntegrationServiceEnvironmentNetworkHealthOperations
from .operations import IntegrationServiceEnvironmentManagedApisOperations
from .operations import IntegrationServiceEnvironmentManagedApiOperationsOperations
from .operations import Operations
from .. import models


class LogicManagementClient(object):
    """REST API for Azure Logic Apps.

    :ivar workflows: WorkflowsOperations operations
    :vartype workflows: azure.mgmt.logic.aio.operations.WorkflowsOperations
    :ivar workflow_versions: WorkflowVersionsOperations operations
    :vartype workflow_versions: azure.mgmt.logic.aio.operations.WorkflowVersionsOperations
    :ivar workflow_triggers: WorkflowTriggersOperations operations
    :vartype workflow_triggers: azure.mgmt.logic.aio.operations.WorkflowTriggersOperations
    :ivar workflow_version_triggers: WorkflowVersionTriggersOperations operations
    :vartype workflow_version_triggers: azure.mgmt.logic.aio.operations.WorkflowVersionTriggersOperations
    :ivar workflow_trigger_histories: WorkflowTriggerHistoriesOperations operations
    :vartype workflow_trigger_histories: azure.mgmt.logic.aio.operations.WorkflowTriggerHistoriesOperations
    :ivar workflow_runs: WorkflowRunsOperations operations
    :vartype workflow_runs: azure.mgmt.logic.aio.operations.WorkflowRunsOperations
    :ivar workflow_run_actions: WorkflowRunActionsOperations operations
    :vartype workflow_run_actions: azure.mgmt.logic.aio.operations.WorkflowRunActionsOperations
    :ivar workflow_run_action_repetitions: WorkflowRunActionRepetitionsOperations operations
    :vartype workflow_run_action_repetitions: azure.mgmt.logic.aio.operations.WorkflowRunActionRepetitionsOperations
    :ivar workflow_run_action_repetitions_request_histories: WorkflowRunActionRepetitionsRequestHistoriesOperations operations
    :vartype workflow_run_action_repetitions_request_histories: azure.mgmt.logic.aio.operations.WorkflowRunActionRepetitionsRequestHistoriesOperations
    :ivar workflow_run_action_request_histories: WorkflowRunActionRequestHistoriesOperations operations
    :vartype workflow_run_action_request_histories: azure.mgmt.logic.aio.operations.WorkflowRunActionRequestHistoriesOperations
    :ivar workflow_run_action_scope_repetitions: WorkflowRunActionScopeRepetitionsOperations operations
    :vartype workflow_run_action_scope_repetitions: azure.mgmt.logic.aio.operations.WorkflowRunActionScopeRepetitionsOperations
    :ivar workflow_run_operations: WorkflowRunOperationsOperations operations
    :vartype workflow_run_operations: azure.mgmt.logic.aio.operations.WorkflowRunOperationsOperations
    :ivar integration_accounts: IntegrationAccountsOperations operations
    :vartype integration_accounts: azure.mgmt.logic.aio.operations.IntegrationAccountsOperations
    :ivar integration_account_assemblies: IntegrationAccountAssembliesOperations operations
    :vartype integration_account_assemblies: azure.mgmt.logic.aio.operations.IntegrationAccountAssembliesOperations
    :ivar integration_account_batch_configurations: IntegrationAccountBatchConfigurationsOperations operations
    :vartype integration_account_batch_configurations: azure.mgmt.logic.aio.operations.IntegrationAccountBatchConfigurationsOperations
    :ivar integration_account_schemas: IntegrationAccountSchemasOperations operations
    :vartype integration_account_schemas: azure.mgmt.logic.aio.operations.IntegrationAccountSchemasOperations
    :ivar integration_account_maps: IntegrationAccountMapsOperations operations
    :vartype integration_account_maps: azure.mgmt.logic.aio.operations.IntegrationAccountMapsOperations
    :ivar integration_account_partners: IntegrationAccountPartnersOperations operations
    :vartype integration_account_partners: azure.mgmt.logic.aio.operations.IntegrationAccountPartnersOperations
    :ivar integration_account_agreements: IntegrationAccountAgreementsOperations operations
    :vartype integration_account_agreements: azure.mgmt.logic.aio.operations.IntegrationAccountAgreementsOperations
    :ivar integration_account_certificates: IntegrationAccountCertificatesOperations operations
    :vartype integration_account_certificates: azure.mgmt.logic.aio.operations.IntegrationAccountCertificatesOperations
    :ivar integration_account_sessions: IntegrationAccountSessionsOperations operations
    :vartype integration_account_sessions: azure.mgmt.logic.aio.operations.IntegrationAccountSessionsOperations
    :ivar integration_service_environments: IntegrationServiceEnvironmentsOperations operations
    :vartype integration_service_environments: azure.mgmt.logic.aio.operations.IntegrationServiceEnvironmentsOperations
    :ivar integration_service_environment_skus: IntegrationServiceEnvironmentSkusOperations operations
    :vartype integration_service_environment_skus: azure.mgmt.logic.aio.operations.IntegrationServiceEnvironmentSkusOperations
    :ivar integration_service_environment_network_health: IntegrationServiceEnvironmentNetworkHealthOperations operations
    :vartype integration_service_environment_network_health: azure.mgmt.logic.aio.operations.IntegrationServiceEnvironmentNetworkHealthOperations
    :ivar integration_service_environment_managed_apis: IntegrationServiceEnvironmentManagedApisOperations operations
    :vartype integration_service_environment_managed_apis: azure.mgmt.logic.aio.operations.IntegrationServiceEnvironmentManagedApisOperations
    :ivar integration_service_environment_managed_api_operations: IntegrationServiceEnvironmentManagedApiOperationsOperations operations
    :vartype integration_service_environment_managed_api_operations: azure.mgmt.logic.aio.operations.IntegrationServiceEnvironmentManagedApiOperationsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.logic.aio.operations.Operations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The subscription id.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = LogicManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.workflows = WorkflowsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_versions = WorkflowVersionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_triggers = WorkflowTriggersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_version_triggers = WorkflowVersionTriggersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_trigger_histories = WorkflowTriggerHistoriesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_runs = WorkflowRunsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_run_actions = WorkflowRunActionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_run_action_repetitions = WorkflowRunActionRepetitionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_run_action_repetitions_request_histories = WorkflowRunActionRepetitionsRequestHistoriesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_run_action_request_histories = WorkflowRunActionRequestHistoriesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_run_action_scope_repetitions = WorkflowRunActionScopeRepetitionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.workflow_run_operations = WorkflowRunOperationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_accounts = IntegrationAccountsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_assemblies = IntegrationAccountAssembliesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_batch_configurations = IntegrationAccountBatchConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_schemas = IntegrationAccountSchemasOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_maps = IntegrationAccountMapsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_partners = IntegrationAccountPartnersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_agreements = IntegrationAccountAgreementsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_certificates = IntegrationAccountCertificatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_account_sessions = IntegrationAccountSessionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_service_environments = IntegrationServiceEnvironmentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_service_environment_skus = IntegrationServiceEnvironmentSkusOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_service_environment_network_health = IntegrationServiceEnvironmentNetworkHealthOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_service_environment_managed_apis = IntegrationServiceEnvironmentManagedApisOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.integration_service_environment_managed_api_operations = IntegrationServiceEnvironmentManagedApiOperationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "LogicManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
