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

import uuid
from msrest.pipeline import ClientRawResponse

from .. import models


class TransactionsOperations(object):
    """TransactionsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2019-10-01-preview. Constant value: "2019-10-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-10-01-preview"

        self.config = config

    def list_by_billing_account_name(
            self, billing_account_name, start_date, end_date, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists the transactions by billing account name for given start and end
        date.

        :param billing_account_name: billing Account Id.
        :type billing_account_name: str
        :param start_date: Start date
        :type start_date: str
        :param end_date: End date
        :type end_date: str
        :param filter: May be used to filter by transaction kind. The filter
         supports 'eq', 'lt', 'gt', 'le', 'ge', and 'and'. It does not
         currently support 'ne', 'or', or 'not'. Tag filter is a key value pair
         string where key and value is separated by a colon (:).
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Transaction
        :rtype:
         ~azure.mgmt.billing.models.TransactionPaged[~azure.mgmt.billing.models.Transaction]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.billing.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_billing_account_name.metadata['url']
                path_format_arguments = {
                    'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                query_parameters['startDate'] = self._serialize.query("start_date", start_date, 'str')
                query_parameters['endDate'] = self._serialize.query("end_date", end_date, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.TransactionPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.TransactionPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_billing_account_name.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/transactions'}

    def list_by_billing_profile_name(
            self, billing_account_name, billing_profile_name, start_date, end_date, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists the transactions by billing profile name for given start date and
        end date.

        :param billing_account_name: billing Account Id.
        :type billing_account_name: str
        :param billing_profile_name: Billing Profile Id.
        :type billing_profile_name: str
        :param start_date: Start date
        :type start_date: str
        :param end_date: End date
        :type end_date: str
        :param filter: May be used to filter by transaction kind. The filter
         supports 'eq', 'lt', 'gt', 'le', 'ge', and 'and'. It does not
         currently support 'ne', 'or', or 'not'. Tag filter is a key value pair
         string where key and value is separated by a colon (:).
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: TransactionListResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.billing.models.TransactionListResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.billing.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_by_billing_profile_name.metadata['url']
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
        query_parameters['startDate'] = self._serialize.query("start_date", start_date, 'str')
        query_parameters['endDate'] = self._serialize.query("end_date", end_date, 'str')
        if filter is not None:
            query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('TransactionListResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_by_billing_profile_name.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/transactions'}

    def list_by_invoice_section_name(
            self, billing_account_name, billing_profile_name, invoice_section_name, start_date, end_date, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists the transactions by invoice section name for given start date and
        end date.

        :param billing_account_name: billing Account Id.
        :type billing_account_name: str
        :param billing_profile_name: Billing Profile Id.
        :type billing_profile_name: str
        :param invoice_section_name: InvoiceSection Id.
        :type invoice_section_name: str
        :param start_date: Start date
        :type start_date: str
        :param end_date: End date
        :type end_date: str
        :param filter: May be used to filter by transaction kind. The filter
         supports 'eq', 'lt', 'gt', 'le', 'ge', and 'and'. It does not
         currently support 'ne', 'or', or 'not'. Tag filter is a key value pair
         string where key and value is separated by a colon (:).
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: TransactionListResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.billing.models.TransactionListResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.billing.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_by_invoice_section_name.metadata['url']
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
            'invoiceSectionName': self._serialize.url("invoice_section_name", invoice_section_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
        query_parameters['startDate'] = self._serialize.query("start_date", start_date, 'str')
        query_parameters['endDate'] = self._serialize.query("end_date", end_date, 'str')
        if filter is not None:
            query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('TransactionListResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_by_invoice_section_name.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/invoiceSections/{invoiceSectionName}/transactions'}

    def get(
            self, billing_account_name, billing_profile_name, transaction_name, start_date, end_date, custom_headers=None, raw=False, **operation_config):
        """Get the transaction.

        :param billing_account_name: billing Account Id.
        :type billing_account_name: str
        :param billing_profile_name: Billing Profile Id.
        :type billing_profile_name: str
        :param transaction_name: Transaction name.
        :type transaction_name: str
        :param start_date: Start date
        :type start_date: str
        :param end_date: End date
        :type end_date: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Transaction or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.billing.models.Transaction or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.billing.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
            'transactionName': self._serialize.url("transaction_name", transaction_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['startDate'] = self._serialize.query("start_date", start_date, 'str')
        query_parameters['endDate'] = self._serialize.query("end_date", end_date, 'str')
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Transaction', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/transactions/{transactionName}'}
