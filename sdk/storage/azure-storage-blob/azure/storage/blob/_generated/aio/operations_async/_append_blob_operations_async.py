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

from azure.core.exceptions import map_error

from ... import models


class AppendBlobOperations:
    """AppendBlobOperations async operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar x_ms_blob_type: Specifies the type of blob to create: block blob, page blob, or append blob. Constant value: "AppendBlob".
    :ivar comp: . Constant value: "appendblock".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self._config = config
        self.x_ms_blob_type = "AppendBlob"
        self.comp = "appendblock"

    async def create(self, content_length, timeout=None, metadata=None, tags=None, x_ms_encryption_key=None, x_ms_encryption_key_sha256=None, x_ms_encryption_algorithm=None, request_id=None, blob_http_headers=None, lease_access_conditions=None, customer_provided_key_info=None, modified_access_conditions=None, *, cls=None, **kwargs):
        """The Create Append Blob operation creates a new append blob.

        :param content_length: The length of the request.
        :type content_length: long
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param metadata: Optional. Specifies a user-defined name-value pair
         associated with the blob. If no name-value pairs are specified, the
         operation will copy the metadata from the source blob or file to the
         destination blob. If one or more name-value pairs are specified, the
         destination blob is created with the specified metadata, and metadata
         is not copied from the source blob or file. Note that beginning with
         version 2009-09-19, metadata names must adhere to the naming rules for
         C# identifiers. See Naming and Referencing Containers, Blobs, and
         Metadata for more information.
        :type metadata: str
        :param tags: Optional. A URL encoded query param string which
         specifies the tags to be created with the Blob object. e.g.
         TagName1=TagValue1&TagName2=TagValue2. The x-ms-tags header may
         contain up to 2kb of tags.
        :type tags: str
        :param x_ms_encryption_key: Optional. Specifies the encryption key to
         use to encrypt the data provided in the request. If not specified,
         encryption is performed with the root account encryption key.  For
         more information, see Encryption at Rest for Azure Storage Services.
        :type x_ms_encryption_key: str
        :param x_ms_encryption_key_sha256: The SHA-256 hash of the provided
         encryption key. Must be provided if the x-ms-encryption-key header is
         provided.
        :type x_ms_encryption_key_sha256: str
        :param x_ms_encryption_algorithm: The algorithm used to produce the
         encryption key hash. Currently, the only accepted value is "AES256".
         Must be provided if the x-ms-encryption-key header is provided.
         Possible values include: 'AES256'
        :type x_ms_encryption_algorithm: str or
         ~azure.storage.blob.models.EncryptionAlgorithmType
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param blob_http_headers: Additional parameters for the operation
        :type blob_http_headers: ~azure.storage.blob.models.BlobHTTPHeaders
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions:
         ~azure.storage.blob.models.LeaseAccessConditions
        :param customer_provided_key_info: Additional parameters for the
         operation
        :type customer_provided_key_info:
         ~azure.storage.blob.models.CustomerProvidedKeyInfo
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~azure.storage.blob.models.ModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`StorageErrorException<azure.storage.blob.models.StorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        blob_content_type = None
        if blob_http_headers is not None:
            blob_content_type = blob_http_headers.blob_content_type
        blob_content_encoding = None
        if blob_http_headers is not None:
            blob_content_encoding = blob_http_headers.blob_content_encoding
        blob_content_language = None
        if blob_http_headers is not None:
            blob_content_language = blob_http_headers.blob_content_language
        blob_content_md5 = None
        if blob_http_headers is not None:
            blob_content_md5 = blob_http_headers.blob_content_md5
        blob_cache_control = None
        if blob_http_headers is not None:
            blob_cache_control = blob_http_headers.blob_cache_control
        blob_content_disposition = None
        if blob_http_headers is not None:
            blob_content_disposition = blob_http_headers.blob_content_disposition
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        encryption_scope = None
        if customer_provided_key_info is not None:
            encryption_scope = customer_provided_key_info.encryption_scope
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match

        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        if x_ms_encryption_key is not None:
            query_parameters['x-ms-encryption-key'] = self._serialize.query("x_ms_encryption_key", x_ms_encryption_key, 'str')
        if x_ms_encryption_key_sha256 is not None:
            query_parameters['x-ms-encryption-key-sha256'] = self._serialize.query("x_ms_encryption_key_sha256", x_ms_encryption_key_sha256, 'str')
        if x_ms_encryption_algorithm is not None:
            query_parameters['x-ms-encryption-algorithm'] = self._serialize.query("x_ms_encryption_algorithm", x_ms_encryption_algorithm, 'EncryptionAlgorithmType')
        if encryption_scope is not None:
            query_parameters['x-ms-encryption-scope'] = self._serialize.query("encryption_scope", encryption_scope, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        if metadata is not None:
            header_parameters['x-ms-meta'] = self._serialize.header("metadata", metadata, 'str')
        if tags is not None:
            header_parameters['x-ms-tags'] = self._serialize.header("tags", tags, 'str')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        header_parameters['x-ms-blob-type'] = self._serialize.header("self.x_ms_blob_type", self.x_ms_blob_type, 'str')
        if blob_content_type is not None:
            header_parameters['x-ms-blob-content-type'] = self._serialize.header("blob_content_type", blob_content_type, 'str')
        if blob_content_encoding is not None:
            header_parameters['x-ms-blob-content-encoding'] = self._serialize.header("blob_content_encoding", blob_content_encoding, 'str')
        if blob_content_language is not None:
            header_parameters['x-ms-blob-content-language'] = self._serialize.header("blob_content_language", blob_content_language, 'str')
        if blob_content_md5 is not None:
            header_parameters['x-ms-blob-content-md5'] = self._serialize.header("blob_content_md5", blob_content_md5, 'bytearray')
        if blob_cache_control is not None:
            header_parameters['x-ms-blob-cache-control'] = self._serialize.header("blob_cache_control", blob_cache_control, 'str')
        if blob_content_disposition is not None:
            header_parameters['x-ms-blob-content-disposition'] = self._serialize.header("blob_content_disposition", blob_content_disposition, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-client-request-id': self._deserialize('str', response.headers.get('x-ms-client-request-id')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'x-ms-version-id': self._deserialize('str', response.headers.get('x-ms-version-id')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-request-server-encrypted': self._deserialize('bool', response.headers.get('x-ms-request-server-encrypted')),
                'x-ms-encryption-key-sha256': self._deserialize('str', response.headers.get('x-ms-encryption-key-sha256')),
                'x-ms-encryption-scope': self._deserialize('str', response.headers.get('x-ms-encryption-scope')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    create.metadata = {'url': '/{containerName}/{blob}'}

    async def append_block(self, body, content_length, timeout=None, transactional_content_md5=None, transactional_content_crc64=None, x_ms_encryption_key=None, x_ms_encryption_key_sha256=None, x_ms_encryption_algorithm=None, request_id=None, lease_access_conditions=None, append_position_access_conditions=None, customer_provided_key_info=None, modified_access_conditions=None, *, cls=None, **kwargs):
        """The Append Block operation commits a new block of data to the end of an
        existing append blob. The Append Block operation is permitted only if
        the blob was created with x-ms-blob-type set to AppendBlob. Append
        Block is supported only on version 2015-02-21 version or later.

        :param body: Initial data
        :type body: Generator
        :param content_length: The length of the request.
        :type content_length: long
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param transactional_content_md5: Specify the transactional md5 for
         the body, to be validated by the service.
        :type transactional_content_md5: bytearray
        :param transactional_content_crc64: Specify the transactional crc64
         for the body, to be validated by the service.
        :type transactional_content_crc64: bytearray
        :param x_ms_encryption_key: Optional. Specifies the encryption key to
         use to encrypt the data provided in the request. If not specified,
         encryption is performed with the root account encryption key.  For
         more information, see Encryption at Rest for Azure Storage Services.
        :type x_ms_encryption_key: str
        :param x_ms_encryption_key_sha256: The SHA-256 hash of the provided
         encryption key. Must be provided if the x-ms-encryption-key header is
         provided.
        :type x_ms_encryption_key_sha256: str
        :param x_ms_encryption_algorithm: The algorithm used to produce the
         encryption key hash. Currently, the only accepted value is "AES256".
         Must be provided if the x-ms-encryption-key header is provided.
         Possible values include: 'AES256'
        :type x_ms_encryption_algorithm: str or
         ~azure.storage.blob.models.EncryptionAlgorithmType
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions:
         ~azure.storage.blob.models.LeaseAccessConditions
        :param append_position_access_conditions: Additional parameters for
         the operation
        :type append_position_access_conditions:
         ~azure.storage.blob.models.AppendPositionAccessConditions
        :param customer_provided_key_info: Additional parameters for the
         operation
        :type customer_provided_key_info:
         ~azure.storage.blob.models.CustomerProvidedKeyInfo
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~azure.storage.blob.models.ModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`StorageErrorException<azure.storage.blob.models.StorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        max_size = None
        if append_position_access_conditions is not None:
            max_size = append_position_access_conditions.max_size
        append_position = None
        if append_position_access_conditions is not None:
            append_position = append_position_access_conditions.append_position
        encryption_scope = None
        if customer_provided_key_info is not None:
            encryption_scope = customer_provided_key_info.encryption_scope
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match

        # Construct URL
        url = self.append_block.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        if x_ms_encryption_key is not None:
            query_parameters['x-ms-encryption-key'] = self._serialize.query("x_ms_encryption_key", x_ms_encryption_key, 'str')
        if x_ms_encryption_key_sha256 is not None:
            query_parameters['x-ms-encryption-key-sha256'] = self._serialize.query("x_ms_encryption_key_sha256", x_ms_encryption_key_sha256, 'str')
        if x_ms_encryption_algorithm is not None:
            query_parameters['x-ms-encryption-algorithm'] = self._serialize.query("x_ms_encryption_algorithm", x_ms_encryption_algorithm, 'EncryptionAlgorithmType')
        query_parameters['comp'] = self._serialize.query("self.comp", self.comp, 'str')
        if encryption_scope is not None:
            query_parameters['x-ms-encryption-scope'] = self._serialize.query("encryption_scope", encryption_scope, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/xml; charset=utf-8'
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        if transactional_content_md5 is not None:
            header_parameters['Content-MD5'] = self._serialize.header("transactional_content_md5", transactional_content_md5, 'bytearray')
        if transactional_content_crc64 is not None:
            header_parameters['x-ms-content-crc64'] = self._serialize.header("transactional_content_crc64", transactional_content_crc64, 'bytearray')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if max_size is not None:
            header_parameters['x-ms-blob-condition-maxsize'] = self._serialize.header("max_size", max_size, 'long')
        if append_position is not None:
            header_parameters['x-ms-blob-condition-appendpos'] = self._serialize.header("append_position", append_position, 'long')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')

        # Construct body

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, stream_content=body)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-content-crc64': self._deserialize('bytearray', response.headers.get('x-ms-content-crc64')),
                'x-ms-client-request-id': self._deserialize('str', response.headers.get('x-ms-client-request-id')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-blob-append-offset': self._deserialize('str', response.headers.get('x-ms-blob-append-offset')),
                'x-ms-blob-committed-block-count': self._deserialize('int', response.headers.get('x-ms-blob-committed-block-count')),
                'x-ms-request-server-encrypted': self._deserialize('bool', response.headers.get('x-ms-request-server-encrypted')),
                'x-ms-encryption-key-sha256': self._deserialize('str', response.headers.get('x-ms-encryption-key-sha256')),
                'x-ms-encryption-scope': self._deserialize('str', response.headers.get('x-ms-encryption-scope')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    append_block.metadata = {'url': '/{containerName}/{blob}'}

    async def append_block_from_url(self, source_url, content_length, source_range=None, source_content_md5=None, source_contentcrc64=None, timeout=None, transactional_content_md5=None, request_id=None, lease_access_conditions=None, append_position_access_conditions=None, modified_access_conditions=None, source_modified_access_conditions=None, *, cls=None, **kwargs):
        """The Append Block operation commits a new block of data to the end of an
        existing append blob where the contents are read from a source url. The
        Append Block operation is permitted only if the blob was created with
        x-ms-blob-type set to AppendBlob. Append Block is supported only on
        version 2015-02-21 version or later.

        :param source_url: Specify a URL to the copy source.
        :type source_url: str
        :param content_length: The length of the request.
        :type content_length: long
        :param source_range: Bytes of source data in the specified range.
        :type source_range: str
        :param source_content_md5: Specify the md5 calculated for the range of
         bytes that must be read from the copy source.
        :type source_content_md5: bytearray
        :param source_contentcrc64: Specify the crc64 calculated for the range
         of bytes that must be read from the copy source.
        :type source_contentcrc64: bytearray
        :param timeout: The timeout parameter is expressed in seconds. For
         more information, see <a
         href="https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/setting-timeouts-for-blob-service-operations">Setting
         Timeouts for Blob Service Operations.</a>
        :type timeout: int
        :param transactional_content_md5: Specify the transactional md5 for
         the body, to be validated by the service.
        :type transactional_content_md5: bytearray
        :param request_id: Provides a client-generated, opaque value with a 1
         KB character limit that is recorded in the analytics logs when storage
         analytics logging is enabled.
        :type request_id: str
        :param lease_access_conditions: Additional parameters for the
         operation
        :type lease_access_conditions:
         ~azure.storage.blob.models.LeaseAccessConditions
        :param append_position_access_conditions: Additional parameters for
         the operation
        :type append_position_access_conditions:
         ~azure.storage.blob.models.AppendPositionAccessConditions
        :param modified_access_conditions: Additional parameters for the
         operation
        :type modified_access_conditions:
         ~azure.storage.blob.models.ModifiedAccessConditions
        :param source_modified_access_conditions: Additional parameters for
         the operation
        :type source_modified_access_conditions:
         ~azure.storage.blob.models.SourceModifiedAccessConditions
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises:
         :class:`StorageErrorException<azure.storage.blob.models.StorageErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        lease_id = None
        if lease_access_conditions is not None:
            lease_id = lease_access_conditions.lease_id
        max_size = None
        if append_position_access_conditions is not None:
            max_size = append_position_access_conditions.max_size
        append_position = None
        if append_position_access_conditions is not None:
            append_position = append_position_access_conditions.append_position
        if_modified_since = None
        if modified_access_conditions is not None:
            if_modified_since = modified_access_conditions.if_modified_since
        if_unmodified_since = None
        if modified_access_conditions is not None:
            if_unmodified_since = modified_access_conditions.if_unmodified_since
        if_match = None
        if modified_access_conditions is not None:
            if_match = modified_access_conditions.if_match
        if_none_match = None
        if modified_access_conditions is not None:
            if_none_match = modified_access_conditions.if_none_match
        source_if_modified_since = None
        if source_modified_access_conditions is not None:
            source_if_modified_since = source_modified_access_conditions.source_if_modified_since
        source_if_unmodified_since = None
        if source_modified_access_conditions is not None:
            source_if_unmodified_since = source_modified_access_conditions.source_if_unmodified_since
        source_if_match = None
        if source_modified_access_conditions is not None:
            source_if_match = source_modified_access_conditions.source_if_match
        source_if_none_match = None
        if source_modified_access_conditions is not None:
            source_if_none_match = source_modified_access_conditions.source_if_none_match

        # Construct URL
        url = self.append_block_from_url.metadata['url']
        path_format_arguments = {
            'url': self._serialize.url("self._config.url", self._config.url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if timeout is not None:
            query_parameters['timeout'] = self._serialize.query("timeout", timeout, 'int', minimum=0)
        query_parameters['comp'] = self._serialize.query("self.comp", self.comp, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['x-ms-copy-source'] = self._serialize.header("source_url", source_url, 'str')
        if source_range is not None:
            header_parameters['x-ms-source-range'] = self._serialize.header("source_range", source_range, 'str')
        if source_content_md5 is not None:
            header_parameters['x-ms-source-content-md5'] = self._serialize.header("source_content_md5", source_content_md5, 'bytearray')
        if source_contentcrc64 is not None:
            header_parameters['x-ms-source-content-crc64'] = self._serialize.header("source_contentcrc64", source_contentcrc64, 'bytearray')
        header_parameters['Content-Length'] = self._serialize.header("content_length", content_length, 'long')
        if transactional_content_md5 is not None:
            header_parameters['Content-MD5'] = self._serialize.header("transactional_content_md5", transactional_content_md5, 'bytearray')
        header_parameters['x-ms-version'] = self._serialize.header("self._config.version", self._config.version, 'str')
        if request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("request_id", request_id, 'str')
        if lease_id is not None:
            header_parameters['x-ms-lease-id'] = self._serialize.header("lease_id", lease_id, 'str')
        if max_size is not None:
            header_parameters['x-ms-blob-condition-maxsize'] = self._serialize.header("max_size", max_size, 'long')
        if append_position is not None:
            header_parameters['x-ms-blob-condition-appendpos'] = self._serialize.header("append_position", append_position, 'long')
        if if_modified_since is not None:
            header_parameters['If-Modified-Since'] = self._serialize.header("if_modified_since", if_modified_since, 'rfc-1123')
        if if_unmodified_since is not None:
            header_parameters['If-Unmodified-Since'] = self._serialize.header("if_unmodified_since", if_unmodified_since, 'rfc-1123')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        if source_if_modified_since is not None:
            header_parameters['x-ms-source-if-modified-since'] = self._serialize.header("source_if_modified_since", source_if_modified_since, 'rfc-1123')
        if source_if_unmodified_since is not None:
            header_parameters['x-ms-source-if-unmodified-since'] = self._serialize.header("source_if_unmodified_since", source_if_unmodified_since, 'rfc-1123')
        if source_if_match is not None:
            header_parameters['x-ms-source-if-match'] = self._serialize.header("source_if_match", source_if_match, 'str')
        if source_if_none_match is not None:
            header_parameters['x-ms-source-if-none-match'] = self._serialize.header("source_if_none_match", source_if_none_match, 'str')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.StorageErrorException(response, self._deserialize)

        if cls:
            response_headers = {
                'ETag': self._deserialize('str', response.headers.get('ETag')),
                'Last-Modified': self._deserialize('rfc-1123', response.headers.get('Last-Modified')),
                'Content-MD5': self._deserialize('bytearray', response.headers.get('Content-MD5')),
                'x-ms-content-crc64': self._deserialize('bytearray', response.headers.get('x-ms-content-crc64')),
                'x-ms-request-id': self._deserialize('str', response.headers.get('x-ms-request-id')),
                'x-ms-version': self._deserialize('str', response.headers.get('x-ms-version')),
                'Date': self._deserialize('rfc-1123', response.headers.get('Date')),
                'x-ms-blob-append-offset': self._deserialize('str', response.headers.get('x-ms-blob-append-offset')),
                'x-ms-blob-committed-block-count': self._deserialize('int', response.headers.get('x-ms-blob-committed-block-count')),
                'x-ms-error-code': self._deserialize('str', response.headers.get('x-ms-error-code')),
            }
            return cls(response, None, response_headers)
    append_block_from_url.metadata = {'url': '/{containerName}/{blob}'}
