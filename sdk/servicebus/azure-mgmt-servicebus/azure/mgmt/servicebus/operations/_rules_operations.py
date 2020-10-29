# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class RulesOperations(object):
    """RulesOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.servicebus.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def list_by_subscriptions(
        self,
        resource_group_name,  # type: str
        namespace_name,  # type: str
        topic_name,  # type: str
        subscription_name,  # type: str
        skip=None,  # type: Optional[int]
        top=None,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.RuleListResult"]
        """List all the rules within given topic-subscription.

        :param resource_group_name: Name of the Resource group within the Azure subscription.
        :type resource_group_name: str
        :param namespace_name: The namespace name.
        :type namespace_name: str
        :param topic_name: The topic name.
        :type topic_name: str
        :param subscription_name: The subscription name.
        :type subscription_name: str
        :param skip: Skip is only used if a previous operation returned a partial result. If a previous
         response contains a nextLink element, the value of the nextLink element will include a skip
         parameter that specifies a starting point to use for subsequent calls.
        :type skip: int
        :param top: May be used to limit the number of results to the most recent N usageDetails.
        :type top: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either RuleListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.servicebus.models.RuleListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.RuleListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2017-04-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_subscriptions.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
                    'namespaceName': self._serialize.url("namespace_name", namespace_name, 'str', max_length=50, min_length=6),
                    'topicName': self._serialize.url("topic_name", topic_name, 'str', min_length=1),
                    'subscriptionName': self._serialize.url("subscription_name", subscription_name, 'str', max_length=50, min_length=1),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if skip is not None:
                    query_parameters['$skip'] = self._serialize.query("skip", skip, 'int', maximum=1000, minimum=0)
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', maximum=1000, minimum=1)

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('RuleListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_by_subscriptions.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules'}  # type: ignore

    def create_or_update(
        self,
        resource_group_name,  # type: str
        namespace_name,  # type: str
        topic_name,  # type: str
        subscription_name,  # type: str
        rule_name,  # type: str
        parameters,  # type: "models.Rule"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.Rule"
        """Creates a new rule and updates an existing rule.

        :param resource_group_name: Name of the Resource group within the Azure subscription.
        :type resource_group_name: str
        :param namespace_name: The namespace name.
        :type namespace_name: str
        :param topic_name: The topic name.
        :type topic_name: str
        :param subscription_name: The subscription name.
        :type subscription_name: str
        :param rule_name: The rule name.
        :type rule_name: str
        :param parameters: Parameters supplied to create a rule.
        :type parameters: ~azure.mgmt.servicebus.models.Rule
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Rule, or the result of cls(response)
        :rtype: ~azure.mgmt.servicebus.models.Rule
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Rule"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2017-04-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'namespaceName': self._serialize.url("namespace_name", namespace_name, 'str', max_length=50, min_length=6),
            'topicName': self._serialize.url("topic_name", topic_name, 'str', min_length=1),
            'subscriptionName': self._serialize.url("subscription_name", subscription_name, 'str', max_length=50, min_length=1),
            'ruleName': self._serialize.url("rule_name", rule_name, 'str', max_length=50, min_length=1),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'Rule')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('Rule', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules/{ruleName}'}  # type: ignore

    def delete(
        self,
        resource_group_name,  # type: str
        namespace_name,  # type: str
        topic_name,  # type: str
        subscription_name,  # type: str
        rule_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Deletes an existing rule.

        :param resource_group_name: Name of the Resource group within the Azure subscription.
        :type resource_group_name: str
        :param namespace_name: The namespace name.
        :type namespace_name: str
        :param topic_name: The topic name.
        :type topic_name: str
        :param subscription_name: The subscription name.
        :type subscription_name: str
        :param rule_name: The rule name.
        :type rule_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2017-04-01"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'namespaceName': self._serialize.url("namespace_name", namespace_name, 'str', max_length=50, min_length=6),
            'topicName': self._serialize.url("topic_name", topic_name, 'str', min_length=1),
            'subscriptionName': self._serialize.url("subscription_name", subscription_name, 'str', max_length=50, min_length=1),
            'ruleName': self._serialize.url("rule_name", rule_name, 'str', max_length=50, min_length=1),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules/{ruleName}'}  # type: ignore

    def get(
        self,
        resource_group_name,  # type: str
        namespace_name,  # type: str
        topic_name,  # type: str
        subscription_name,  # type: str
        rule_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.Rule"
        """Retrieves the description for the specified rule.

        :param resource_group_name: Name of the Resource group within the Azure subscription.
        :type resource_group_name: str
        :param namespace_name: The namespace name.
        :type namespace_name: str
        :param topic_name: The topic name.
        :type topic_name: str
        :param subscription_name: The subscription name.
        :type subscription_name: str
        :param rule_name: The rule name.
        :type rule_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Rule, or the result of cls(response)
        :rtype: ~azure.mgmt.servicebus.models.Rule
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Rule"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2017-04-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'namespaceName': self._serialize.url("namespace_name", namespace_name, 'str', max_length=50, min_length=6),
            'topicName': self._serialize.url("topic_name", topic_name, 'str', min_length=1),
            'subscriptionName': self._serialize.url("subscription_name", subscription_name, 'str', max_length=50, min_length=1),
            'ruleName': self._serialize.url("rule_name", rule_name, 'str', max_length=50, min_length=1),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('Rule', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules/{ruleName}'}  # type: ignore
