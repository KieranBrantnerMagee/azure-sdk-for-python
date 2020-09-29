# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class AccountStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status indicating whether the primary location of the storage account is available or
    unavailable.
    """

    AVAILABLE = "Available"
    UNAVAILABLE = "Unavailable"

class AccountType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The sku name. Required for account creation; optional for update. Note that in older versions,
    sku name was called accountType.
    """

    STANDARD_LRS = "Standard_LRS"
    STANDARD_ZRS = "Standard_ZRS"
    STANDARD_GRS = "Standard_GRS"
    STANDARD_RAGRS = "Standard_RAGRS"
    PREMIUM_LRS = "Premium_LRS"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the storage account at the time the operation was called.
    """

    CREATING = "Creating"
    RESOLVING_DNS = "ResolvingDNS"
    SUCCEEDED = "Succeeded"

class Reason(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The reason that a storage account name could not be used. The Reason element is only returned
    if NameAvailable is false.
    """

    ACCOUNT_NAME_INVALID = "AccountNameInvalid"
    ALREADY_EXISTS = "AlreadyExists"

class UsageUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The unit of measurement.
    """

    COUNT = "Count"
    BYTES = "Bytes"
    SECONDS = "Seconds"
    PERCENT = "Percent"
    COUNTS_PER_SECOND = "CountsPerSecond"
    BYTES_PER_SECOND = "BytesPerSecond"
