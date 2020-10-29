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

from azure.mgmt.core import ARMPipelineClient
from msrest import Serializer, Deserializer

from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from ._configuration import WebSiteManagementClientConfiguration
from ._operations_mixin import WebSiteManagementClientOperationsMixin
class _SDKClient(object):
    def __init__(self, *args, **kwargs):
        """This is a fake class to support current implemetation of MultiApiClientMixin."
        Will be removed in final version of multiapi azure-core based client
        """
        pass

class WebSiteManagementClient(WebSiteManagementClientOperationsMixin, MultiApiClientMixin, _SDKClient):
    """WebSite Management Client.

    This ready contains multiple API versions, to help you deal with all of the Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, it uses the latest API version available on public Azure.
    For production, you should stick to a particular api-version and/or profile.
    The profile sets a mapping between an operation group and its API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: Your Azure subscription ID. This is a GUID-formatted string (e.g. 00000000-0000-0000-0000-000000000000).
    :type subscription_id: str
    :param str api_version: API version to use if no profile is provided, or if
     missing in profile.
    :param str base_url: Service URL
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    DEFAULT_API_VERSION = '2019-08-01'
    _PROFILE_TAG = "azure.mgmt.web.WebSiteManagementClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
            'billing_meters': '2016-03-01',
            'validate_container_settings': '2018-02-01',
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        api_version=None,
        base_url=None,
        profile=KnownProfiles.default,
        **kwargs  # type: Any
    ):
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = WebSiteManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)
        super(WebSiteManagementClient, self).__init__(
            api_version=api_version,
            profile=profile
        )

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2015-04-01: :mod:`v2015_04_01.models<azure.mgmt.web.v2015_04_01.models>`
           * 2015-08-01: :mod:`v2015_08_01.models<azure.mgmt.web.v2015_08_01.models>`
           * 2016-03-01: :mod:`v2016_03_01.models<azure.mgmt.web.v2016_03_01.models>`
           * 2016-08-01: :mod:`v2016_08_01.models<azure.mgmt.web.v2016_08_01.models>`
           * 2016-09-01: :mod:`v2016_09_01.models<azure.mgmt.web.v2016_09_01.models>`
           * 2018-02-01: :mod:`v2018_02_01.models<azure.mgmt.web.v2018_02_01.models>`
           * 2018-11-01: :mod:`v2018_11_01.models<azure.mgmt.web.v2018_11_01.models>`
           * 2019-08-01: :mod:`v2019_08_01.models<azure.mgmt.web.v2019_08_01.models>`
        """
        if api_version == '2015-04-01':
            from .v2015_04_01 import models
            return models
        elif api_version == '2015-08-01':
            from .v2015_08_01 import models
            return models
        elif api_version == '2016-03-01':
            from .v2016_03_01 import models
            return models
        elif api_version == '2016-08-01':
            from .v2016_08_01 import models
            return models
        elif api_version == '2016-09-01':
            from .v2016_09_01 import models
            return models
        elif api_version == '2018-02-01':
            from .v2018_02_01 import models
            return models
        elif api_version == '2018-11-01':
            from .v2018_11_01 import models
            return models
        elif api_version == '2019-08-01':
            from .v2019_08_01 import models
            return models
        raise ValueError("API version {} is not available".format(api_version))

    @property
    def app_service_certificate_orders(self):
        """Instance depends on the API version:

           * 2015-08-01: :class:`AppServiceCertificateOrdersOperations<azure.mgmt.web.v2015_08_01.operations.AppServiceCertificateOrdersOperations>`
           * 2018-02-01: :class:`AppServiceCertificateOrdersOperations<azure.mgmt.web.v2018_02_01.operations.AppServiceCertificateOrdersOperations>`
           * 2019-08-01: :class:`AppServiceCertificateOrdersOperations<azure.mgmt.web.v2019_08_01.operations.AppServiceCertificateOrdersOperations>`
        """
        api_version = self._get_api_version('app_service_certificate_orders')
        if api_version == '2015-08-01':
            from .v2015_08_01.operations import AppServiceCertificateOrdersOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import AppServiceCertificateOrdersOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import AppServiceCertificateOrdersOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'app_service_certificate_orders'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def app_service_environments(self):
        """Instance depends on the API version:

           * 2016-09-01: :class:`AppServiceEnvironmentsOperations<azure.mgmt.web.v2016_09_01.operations.AppServiceEnvironmentsOperations>`
           * 2018-02-01: :class:`AppServiceEnvironmentsOperations<azure.mgmt.web.v2018_02_01.operations.AppServiceEnvironmentsOperations>`
           * 2019-08-01: :class:`AppServiceEnvironmentsOperations<azure.mgmt.web.v2019_08_01.operations.AppServiceEnvironmentsOperations>`
        """
        api_version = self._get_api_version('app_service_environments')
        if api_version == '2016-09-01':
            from .v2016_09_01.operations import AppServiceEnvironmentsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import AppServiceEnvironmentsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import AppServiceEnvironmentsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'app_service_environments'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def app_service_plans(self):
        """Instance depends on the API version:

           * 2016-09-01: :class:`AppServicePlansOperations<azure.mgmt.web.v2016_09_01.operations.AppServicePlansOperations>`
           * 2018-02-01: :class:`AppServicePlansOperations<azure.mgmt.web.v2018_02_01.operations.AppServicePlansOperations>`
           * 2019-08-01: :class:`AppServicePlansOperations<azure.mgmt.web.v2019_08_01.operations.AppServicePlansOperations>`
        """
        api_version = self._get_api_version('app_service_plans')
        if api_version == '2016-09-01':
            from .v2016_09_01.operations import AppServicePlansOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import AppServicePlansOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import AppServicePlansOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'app_service_plans'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def billing_meters(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`BillingMetersOperations<azure.mgmt.web.v2016_03_01.operations.BillingMetersOperations>`
        """
        api_version = self._get_api_version('billing_meters')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import BillingMetersOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'billing_meters'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def certificate_registration_provider(self):
        """Instance depends on the API version:

           * 2015-08-01: :class:`CertificateRegistrationProviderOperations<azure.mgmt.web.v2015_08_01.operations.CertificateRegistrationProviderOperations>`
           * 2018-02-01: :class:`CertificateRegistrationProviderOperations<azure.mgmt.web.v2018_02_01.operations.CertificateRegistrationProviderOperations>`
           * 2019-08-01: :class:`CertificateRegistrationProviderOperations<azure.mgmt.web.v2019_08_01.operations.CertificateRegistrationProviderOperations>`
        """
        api_version = self._get_api_version('certificate_registration_provider')
        if api_version == '2015-08-01':
            from .v2015_08_01.operations import CertificateRegistrationProviderOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import CertificateRegistrationProviderOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import CertificateRegistrationProviderOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'certificate_registration_provider'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def certificates(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`CertificatesOperations<azure.mgmt.web.v2016_03_01.operations.CertificatesOperations>`
           * 2018-02-01: :class:`CertificatesOperations<azure.mgmt.web.v2018_02_01.operations.CertificatesOperations>`
           * 2018-11-01: :class:`CertificatesOperations<azure.mgmt.web.v2018_11_01.operations.CertificatesOperations>`
           * 2019-08-01: :class:`CertificatesOperations<azure.mgmt.web.v2019_08_01.operations.CertificatesOperations>`
        """
        api_version = self._get_api_version('certificates')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import CertificatesOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import CertificatesOperations as OperationClass
        elif api_version == '2018-11-01':
            from .v2018_11_01.operations import CertificatesOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import CertificatesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'certificates'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def deleted_web_apps(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`DeletedWebAppsOperations<azure.mgmt.web.v2016_03_01.operations.DeletedWebAppsOperations>`
           * 2018-02-01: :class:`DeletedWebAppsOperations<azure.mgmt.web.v2018_02_01.operations.DeletedWebAppsOperations>`
           * 2019-08-01: :class:`DeletedWebAppsOperations<azure.mgmt.web.v2019_08_01.operations.DeletedWebAppsOperations>`
        """
        api_version = self._get_api_version('deleted_web_apps')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import DeletedWebAppsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import DeletedWebAppsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import DeletedWebAppsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'deleted_web_apps'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def diagnostics(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`DiagnosticsOperations<azure.mgmt.web.v2016_03_01.operations.DiagnosticsOperations>`
           * 2018-02-01: :class:`DiagnosticsOperations<azure.mgmt.web.v2018_02_01.operations.DiagnosticsOperations>`
           * 2019-08-01: :class:`DiagnosticsOperations<azure.mgmt.web.v2019_08_01.operations.DiagnosticsOperations>`
        """
        api_version = self._get_api_version('diagnostics')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import DiagnosticsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import DiagnosticsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import DiagnosticsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'diagnostics'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def domain_registration_provider(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`DomainRegistrationProviderOperations<azure.mgmt.web.v2015_04_01.operations.DomainRegistrationProviderOperations>`
           * 2018-02-01: :class:`DomainRegistrationProviderOperations<azure.mgmt.web.v2018_02_01.operations.DomainRegistrationProviderOperations>`
           * 2019-08-01: :class:`DomainRegistrationProviderOperations<azure.mgmt.web.v2019_08_01.operations.DomainRegistrationProviderOperations>`
        """
        api_version = self._get_api_version('domain_registration_provider')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import DomainRegistrationProviderOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import DomainRegistrationProviderOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import DomainRegistrationProviderOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'domain_registration_provider'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def domains(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`DomainsOperations<azure.mgmt.web.v2015_04_01.operations.DomainsOperations>`
           * 2018-02-01: :class:`DomainsOperations<azure.mgmt.web.v2018_02_01.operations.DomainsOperations>`
           * 2019-08-01: :class:`DomainsOperations<azure.mgmt.web.v2019_08_01.operations.DomainsOperations>`
        """
        api_version = self._get_api_version('domains')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import DomainsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import DomainsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import DomainsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'domains'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def provider(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`ProviderOperations<azure.mgmt.web.v2016_03_01.operations.ProviderOperations>`
           * 2018-02-01: :class:`ProviderOperations<azure.mgmt.web.v2018_02_01.operations.ProviderOperations>`
           * 2019-08-01: :class:`ProviderOperations<azure.mgmt.web.v2019_08_01.operations.ProviderOperations>`
        """
        api_version = self._get_api_version('provider')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import ProviderOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import ProviderOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import ProviderOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'provider'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def recommendations(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`RecommendationsOperations<azure.mgmt.web.v2016_03_01.operations.RecommendationsOperations>`
           * 2018-02-01: :class:`RecommendationsOperations<azure.mgmt.web.v2018_02_01.operations.RecommendationsOperations>`
           * 2019-08-01: :class:`RecommendationsOperations<azure.mgmt.web.v2019_08_01.operations.RecommendationsOperations>`
        """
        api_version = self._get_api_version('recommendations')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import RecommendationsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import RecommendationsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import RecommendationsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'recommendations'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def resource_health_metadata(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`ResourceHealthMetadataOperations<azure.mgmt.web.v2016_03_01.operations.ResourceHealthMetadataOperations>`
           * 2018-02-01: :class:`ResourceHealthMetadataOperations<azure.mgmt.web.v2018_02_01.operations.ResourceHealthMetadataOperations>`
           * 2019-08-01: :class:`ResourceHealthMetadataOperations<azure.mgmt.web.v2019_08_01.operations.ResourceHealthMetadataOperations>`
        """
        api_version = self._get_api_version('resource_health_metadata')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import ResourceHealthMetadataOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import ResourceHealthMetadataOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import ResourceHealthMetadataOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'resource_health_metadata'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def static_sites(self):
        """Instance depends on the API version:

           * 2019-08-01: :class:`StaticSitesOperations<azure.mgmt.web.v2019_08_01.operations.StaticSitesOperations>`
        """
        api_version = self._get_api_version('static_sites')
        if api_version == '2019-08-01':
            from .v2019_08_01.operations import StaticSitesOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'static_sites'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def top_level_domains(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`TopLevelDomainsOperations<azure.mgmt.web.v2015_04_01.operations.TopLevelDomainsOperations>`
           * 2018-02-01: :class:`TopLevelDomainsOperations<azure.mgmt.web.v2018_02_01.operations.TopLevelDomainsOperations>`
           * 2019-08-01: :class:`TopLevelDomainsOperations<azure.mgmt.web.v2019_08_01.operations.TopLevelDomainsOperations>`
        """
        api_version = self._get_api_version('top_level_domains')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import TopLevelDomainsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import TopLevelDomainsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import TopLevelDomainsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'top_level_domains'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def web_apps(self):
        """Instance depends on the API version:

           * 2016-08-01: :class:`WebAppsOperations<azure.mgmt.web.v2016_08_01.operations.WebAppsOperations>`
           * 2018-02-01: :class:`WebAppsOperations<azure.mgmt.web.v2018_02_01.operations.WebAppsOperations>`
           * 2019-08-01: :class:`WebAppsOperations<azure.mgmt.web.v2019_08_01.operations.WebAppsOperations>`
        """
        api_version = self._get_api_version('web_apps')
        if api_version == '2016-08-01':
            from .v2016_08_01.operations import WebAppsOperations as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebAppsOperations as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebAppsOperations as OperationClass
        else:
            raise ValueError("API version {} does not have operation group 'web_apps'".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    def close(self):
        self._client.close()
    def __enter__(self):
        self._client.__enter__()
        return self
    def __exit__(self, *exc_details):
        self._client.__exit__(*exc_details)
