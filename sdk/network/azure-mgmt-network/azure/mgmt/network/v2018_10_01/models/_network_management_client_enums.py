# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum

class Access(str, Enum):
    """Indicates whether the traffic is allowed or denied.
    """

    allow = "Allow"
    deny = "Deny"

class ApplicationGatewayBackendHealthServerHealth(str, Enum):
    """Health of backend server.
    """

    unknown = "Unknown"
    up = "Up"
    down = "Down"
    partial = "Partial"
    draining = "Draining"

class ApplicationGatewayCookieBasedAffinity(str, Enum):
    """Cookie based affinity.
    """

    enabled = "Enabled"
    disabled = "Disabled"

class ApplicationGatewayCustomErrorStatusCode(str, Enum):
    """Status code of the application gateway customer error.
    """

    http_status403 = "HttpStatus403"
    http_status502 = "HttpStatus502"

class ApplicationGatewayFirewallMode(str, Enum):
    """Web application firewall mode.
    """

    detection = "Detection"
    prevention = "Prevention"

class ApplicationGatewayOperationalState(str, Enum):
    """Operational state of the application gateway resource.
    """

    stopped = "Stopped"
    starting = "Starting"
    running = "Running"
    stopping = "Stopping"

class ApplicationGatewayProtocol(str, Enum):
    """The protocol used to communicate with the backend. Possible values are 'Http' and 'Https'.
    """

    http = "Http"
    https = "Https"

class ApplicationGatewayRedirectType(str, Enum):

    permanent = "Permanent"
    found = "Found"
    see_other = "SeeOther"
    temporary = "Temporary"

class ApplicationGatewayRequestRoutingRuleType(str, Enum):
    """Rule type.
    """

    basic = "Basic"
    path_based_routing = "PathBasedRouting"

class ApplicationGatewaySkuName(str, Enum):
    """Name of an application gateway SKU.
    """

    standard_small = "Standard_Small"
    standard_medium = "Standard_Medium"
    standard_large = "Standard_Large"
    waf_medium = "WAF_Medium"
    waf_large = "WAF_Large"
    standard_v2 = "Standard_v2"
    waf_v2 = "WAF_v2"

class ApplicationGatewaySslCipherSuite(str, Enum):
    """Ssl cipher suites enums.
    """

    tls_ecdhe_rsa_with_aes256_cbc_sha384 = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    tls_ecdhe_rsa_with_aes128_cbc_sha256 = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    tls_ecdhe_rsa_with_aes256_cbc_sha = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    tls_ecdhe_rsa_with_aes128_cbc_sha = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    tls_dhe_rsa_with_aes256_gcm_sha384 = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    tls_dhe_rsa_with_aes128_gcm_sha256 = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    tls_dhe_rsa_with_aes256_cbc_sha = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    tls_dhe_rsa_with_aes128_cbc_sha = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    tls_rsa_with_aes256_gcm_sha384 = "TLS_RSA_WITH_AES_256_GCM_SHA384"
    tls_rsa_with_aes128_gcm_sha256 = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    tls_rsa_with_aes256_cbc_sha256 = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    tls_rsa_with_aes128_cbc_sha256 = "TLS_RSA_WITH_AES_128_CBC_SHA256"
    tls_rsa_with_aes256_cbc_sha = "TLS_RSA_WITH_AES_256_CBC_SHA"
    tls_rsa_with_aes128_cbc_sha = "TLS_RSA_WITH_AES_128_CBC_SHA"
    tls_ecdhe_ecdsa_with_aes256_gcm_sha384 = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    tls_ecdhe_ecdsa_with_aes128_gcm_sha256 = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    tls_ecdhe_ecdsa_with_aes256_cbc_sha384 = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    tls_ecdhe_ecdsa_with_aes128_cbc_sha256 = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    tls_ecdhe_ecdsa_with_aes256_cbc_sha = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    tls_ecdhe_ecdsa_with_aes128_cbc_sha = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    tls_dhe_dss_with_aes256_cbc_sha256 = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
    tls_dhe_dss_with_aes128_cbc_sha256 = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
    tls_dhe_dss_with_aes256_cbc_sha = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
    tls_dhe_dss_with_aes128_cbc_sha = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
    tls_rsa_with3_des_ede_cbc_sha = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    tls_dhe_dss_with3_des_ede_cbc_sha = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
    tls_ecdhe_rsa_with_aes128_gcm_sha256 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    tls_ecdhe_rsa_with_aes256_gcm_sha384 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

class ApplicationGatewaySslPolicyName(str, Enum):
    """Ssl predefined policy name enums.
    """

    app_gw_ssl_policy20150501 = "AppGwSslPolicy20150501"
    app_gw_ssl_policy20170401 = "AppGwSslPolicy20170401"
    app_gw_ssl_policy20170401_s = "AppGwSslPolicy20170401S"

class ApplicationGatewaySslPolicyType(str, Enum):
    """Type of Ssl Policy
    """

    predefined = "Predefined"
    custom = "Custom"

class ApplicationGatewaySslProtocol(str, Enum):
    """Ssl protocol enums.
    """

    tl_sv1_0 = "TLSv1_0"
    tl_sv1_1 = "TLSv1_1"
    tl_sv1_2 = "TLSv1_2"

class ApplicationGatewayTier(str, Enum):
    """Tier of an application gateway.
    """

    standard = "Standard"
    waf = "WAF"
    standard_v2 = "Standard_v2"
    waf_v2 = "WAF_v2"

class AssociationType(str, Enum):
    """The association type of the child resource to the parent resource.
    """

    associated = "Associated"
    contains = "Contains"

class AuthenticationMethod(str, Enum):
    """VPN client Authentication Method. Possible values are: 'EAPTLS' and 'EAPMSCHAPv2'.
    """

    eaptls = "EAPTLS"
    eapmscha_pv2 = "EAPMSCHAPv2"

class AuthorizationUseStatus(str, Enum):
    """AuthorizationUseStatus. Possible values are: 'Available' and 'InUse'.
    """

    available = "Available"
    in_use = "InUse"

class AzureFirewallApplicationRuleProtocolType(str, Enum):
    """The protocol type of a Application Rule resource
    """

    http = "Http"
    https = "Https"

class AzureFirewallNatRCActionType(str, Enum):
    """The action type of a NAT rule collection
    """

    snat = "Snat"
    dnat = "Dnat"

class AzureFirewallNetworkRuleProtocol(str, Enum):
    """The protocol of a Network Rule resource
    """

    tcp = "TCP"
    udp = "UDP"
    any = "Any"
    icmp = "ICMP"

class AzureFirewallRCActionType(str, Enum):
    """The action type of a rule collection
    """

    allow = "Allow"
    deny = "Deny"

class BgpPeerState(str, Enum):
    """The BGP peer state
    """

    unknown = "Unknown"
    stopped = "Stopped"
    idle = "Idle"
    connecting = "Connecting"
    connected = "Connected"

class CircuitConnectionStatus(str, Enum):
    """Express Route Circuit Connection State. Possible values are: 'Connected' and 'Disconnected'.
    """

    connected = "Connected"
    connecting = "Connecting"
    disconnected = "Disconnected"

class ConnectionMonitorSourceStatus(str, Enum):
    """Status of connection monitor source.
    """

    uknown = "Uknown"
    active = "Active"
    inactive = "Inactive"

class ConnectionState(str, Enum):
    """The connection state.
    """

    reachable = "Reachable"
    unreachable = "Unreachable"
    unknown = "Unknown"

class ConnectionStatus(str, Enum):
    """The connection status.
    """

    unknown = "Unknown"
    connected = "Connected"
    disconnected = "Disconnected"
    degraded = "Degraded"

class DhGroup(str, Enum):
    """The DH Groups used in IKE Phase 1 for initial SA.
    """

    none = "None"
    dh_group1 = "DHGroup1"
    dh_group2 = "DHGroup2"
    dh_group14 = "DHGroup14"
    dh_group2048 = "DHGroup2048"
    ecp256 = "ECP256"
    ecp384 = "ECP384"
    dh_group24 = "DHGroup24"

class Direction(str, Enum):
    """The direction of the packet represented as a 5-tuple.
    """

    inbound = "Inbound"
    outbound = "Outbound"

class EffectiveRouteSource(str, Enum):
    """Who created the route. Possible values are: 'Unknown', 'User', 'VirtualNetworkGateway', and
    'Default'.
    """

    unknown = "Unknown"
    user = "User"
    virtual_network_gateway = "VirtualNetworkGateway"
    default = "Default"

class EffectiveRouteState(str, Enum):
    """The value of effective route. Possible values are: 'Active' and 'Invalid'.
    """

    active = "Active"
    invalid = "Invalid"

class EffectiveSecurityRuleProtocol(str, Enum):
    """The network protocol this rule applies to. Possible values are: 'Tcp', 'Udp', and 'All'.
    """

    tcp = "Tcp"
    udp = "Udp"
    all = "All"

class EvaluationState(str, Enum):
    """Connectivity analysis evaluation state.
    """

    not_started = "NotStarted"
    in_progress = "InProgress"
    completed = "Completed"

class ExpressRouteCircuitPeeringAdvertisedPublicPrefixState(str, Enum):
    """AdvertisedPublicPrefixState of the Peering resource. Possible values are 'NotConfigured',
    'Configuring', 'Configured', and 'ValidationNeeded'.
    """

    not_configured = "NotConfigured"
    configuring = "Configuring"
    configured = "Configured"
    validation_needed = "ValidationNeeded"

class ExpressRouteCircuitPeeringState(str, Enum):
    """The state of peering. Possible values are: 'Disabled' and 'Enabled'
    """

    disabled = "Disabled"
    enabled = "Enabled"

class ExpressRouteCircuitSkuFamily(str, Enum):
    """The family of the SKU. Possible values are: 'UnlimitedData' and 'MeteredData'.
    """

    unlimited_data = "UnlimitedData"
    metered_data = "MeteredData"

class ExpressRouteCircuitSkuTier(str, Enum):
    """The tier of the SKU. Possible values are 'Standard', 'Premium' or 'Basic'.
    """

    standard = "Standard"
    premium = "Premium"
    basic = "Basic"

class ExpressRouteLinkAdminState(str, Enum):
    """Administrative state of the physical port
    """

    enabled = "Enabled"
    disabled = "Disabled"

class ExpressRouteLinkConnectorType(str, Enum):
    """Physical fiber port type.
    """

    lc = "LC"
    sc = "SC"

class ExpressRoutePeeringState(str, Enum):
    """The state of peering. Possible values are: 'Disabled' and 'Enabled'
    """

    disabled = "Disabled"
    enabled = "Enabled"

class ExpressRoutePeeringType(str, Enum):
    """The PeeringType. Possible values are: 'AzurePublicPeering', 'AzurePrivatePeering', and
    'MicrosoftPeering'.
    """

    azure_public_peering = "AzurePublicPeering"
    azure_private_peering = "AzurePrivatePeering"
    microsoft_peering = "MicrosoftPeering"

class ExpressRoutePortsEncapsulation(str, Enum):
    """Encapsulation method on physical ports.
    """

    dot1_q = "Dot1Q"
    qin_q = "QinQ"

class HubVirtualNetworkConnectionStatus(str, Enum):
    """The current state of the VirtualHub to vnet connection.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class IkeEncryption(str, Enum):
    """The IKE encryption algorithm (IKE phase 2).
    """

    des = "DES"
    des3 = "DES3"
    aes128 = "AES128"
    aes192 = "AES192"
    aes256 = "AES256"
    gcmaes256 = "GCMAES256"
    gcmaes128 = "GCMAES128"

class IkeIntegrity(str, Enum):
    """The IKE integrity algorithm (IKE phase 2).
    """

    md5 = "MD5"
    sha1 = "SHA1"
    sha256 = "SHA256"
    sha384 = "SHA384"
    gcmaes256 = "GCMAES256"
    gcmaes128 = "GCMAES128"

class IPAllocationMethod(str, Enum):
    """PrivateIP allocation method.
    """

    static = "Static"
    dynamic = "Dynamic"

class IpFlowProtocol(str, Enum):
    """Protocol to be verified on.
    """

    tcp = "TCP"
    udp = "UDP"

class IpsecEncryption(str, Enum):
    """The IPSec encryption algorithm (IKE phase 1).
    """

    none = "None"
    des = "DES"
    des3 = "DES3"
    aes128 = "AES128"
    aes192 = "AES192"
    aes256 = "AES256"
    gcmaes128 = "GCMAES128"
    gcmaes192 = "GCMAES192"
    gcmaes256 = "GCMAES256"

class IpsecIntegrity(str, Enum):
    """The IPSec integrity algorithm (IKE phase 1).
    """

    md5 = "MD5"
    sha1 = "SHA1"
    sha256 = "SHA256"
    gcmaes128 = "GCMAES128"
    gcmaes192 = "GCMAES192"
    gcmaes256 = "GCMAES256"

class IPVersion(str, Enum):
    """Available from Api-Version 2016-03-30 onwards, it represents whether the specific
    ipconfiguration is IPv4 or IPv6. Default is taken as IPv4.  Possible values are: 'IPv4' and
    'IPv6'.
    """

    i_pv4 = "IPv4"
    i_pv6 = "IPv6"

class IssueType(str, Enum):
    """The type of issue.
    """

    unknown = "Unknown"
    agent_stopped = "AgentStopped"
    guest_firewall = "GuestFirewall"
    dns_resolution = "DnsResolution"
    socket_bind = "SocketBind"
    network_security_rule = "NetworkSecurityRule"
    user_defined_route = "UserDefinedRoute"
    port_throttled = "PortThrottled"
    platform = "Platform"

class LoadBalancerSkuName(str, Enum):
    """Name of a load balancer SKU.
    """

    basic = "Basic"
    standard = "Standard"

class LoadDistribution(str, Enum):
    """The load distribution policy for this rule. Possible values are 'Default', 'SourceIP', and
    'SourceIPProtocol'.
    """

    default = "Default"
    source_ip = "SourceIP"
    source_ip_protocol = "SourceIPProtocol"

class NetworkOperationStatus(str, Enum):
    """Status of the Azure async operation. Possible values are: 'InProgress', 'Succeeded', and
    'Failed'.
    """

    in_progress = "InProgress"
    succeeded = "Succeeded"
    failed = "Failed"

class NextHopType(str, Enum):
    """Next hop type.
    """

    internet = "Internet"
    virtual_appliance = "VirtualAppliance"
    virtual_network_gateway = "VirtualNetworkGateway"
    vnet_local = "VnetLocal"
    hyper_net_gateway = "HyperNetGateway"
    none = "None"

class OfficeTrafficCategory(str, Enum):
    """The office traffic category.
    """

    optimize = "Optimize"
    optimize_and_allow = "OptimizeAndAllow"
    all = "All"
    none = "None"

class Origin(str, Enum):
    """The origin of the issue.
    """

    local = "Local"
    inbound = "Inbound"
    outbound = "Outbound"

class OutboundRulePropertiesFormatProtocol(str, Enum):
    """Protocol - TCP, UDP or All
    """

    tcp = "Tcp"
    udp = "Udp"
    all = "All"

class PcError(str, Enum):

    internal_error = "InternalError"
    agent_stopped = "AgentStopped"
    capture_failed = "CaptureFailed"
    local_file_failed = "LocalFileFailed"
    storage_failed = "StorageFailed"

class PcProtocol(str, Enum):
    """Protocol to be filtered on.
    """

    tcp = "TCP"
    udp = "UDP"
    any = "Any"

class PcStatus(str, Enum):
    """The status of the packet capture session.
    """

    not_started = "NotStarted"
    running = "Running"
    stopped = "Stopped"
    error = "Error"
    unknown = "Unknown"

class PfsGroup(str, Enum):
    """The Pfs Groups used in IKE Phase 2 for new child SA.
    """

    none = "None"
    pfs1 = "PFS1"
    pfs2 = "PFS2"
    pfs2048 = "PFS2048"
    ecp256 = "ECP256"
    ecp384 = "ECP384"
    pfs24 = "PFS24"
    pfs14 = "PFS14"
    pfsmm = "PFSMM"

class ProbeProtocol(str, Enum):
    """The protocol of the end point. Possible values are: 'Http', 'Tcp', or 'Https'. If 'Tcp' is
    specified, a received ACK is required for the probe to be successful. If 'Http' or 'Https' is
    specified, a 200 OK response from the specifies URI is required for the probe to be successful.
    """

    http = "Http"
    tcp = "Tcp"
    https = "Https"

class ProcessorArchitecture(str, Enum):
    """VPN client Processor Architecture. Possible values are: 'AMD64' and 'X86'.
    """

    amd64 = "Amd64"
    x86 = "X86"

class Protocol(str, Enum):
    """Network protocol.
    """

    tcp = "Tcp"
    http = "Http"
    https = "Https"
    icmp = "Icmp"

class ProvisioningState(str, Enum):
    """The current provisioning state.
    """

    succeeded = "Succeeded"
    updating = "Updating"
    deleting = "Deleting"
    failed = "Failed"

class PublicIPAddressSkuName(str, Enum):
    """Name of a public IP address SKU.
    """

    basic = "Basic"
    standard = "Standard"

class ResourceIdentityType(str, Enum):
    """The type of identity used for the resource. The type 'SystemAssigned, UserAssigned' includes
    both an implicitly created identity and a set of user assigned identities. The type 'None' will
    remove any identities from the virtual machine.
    """

    system_assigned = "SystemAssigned"
    user_assigned = "UserAssigned"
    system_assigned_user_assigned = "SystemAssigned, UserAssigned"
    none = "None"

class RouteNextHopType(str, Enum):
    """The type of Azure hop the packet should be sent to. Possible values are:
    'VirtualNetworkGateway', 'VnetLocal', 'Internet', 'VirtualAppliance', and 'None'.
    """

    virtual_network_gateway = "VirtualNetworkGateway"
    vnet_local = "VnetLocal"
    internet = "Internet"
    virtual_appliance = "VirtualAppliance"
    none = "None"

class SecurityRuleAccess(str, Enum):
    """Whether network traffic is allowed or denied. Possible values are: 'Allow' and 'Deny'.
    """

    allow = "Allow"
    deny = "Deny"

class SecurityRuleDirection(str, Enum):
    """The direction of the rule. Possible values are: 'Inbound and Outbound'.
    """

    inbound = "Inbound"
    outbound = "Outbound"

class SecurityRuleProtocol(str, Enum):
    """Network protocol this rule applies to. Possible values are 'Tcp', 'Udp', and '*'.
    """

    tcp = "Tcp"
    udp = "Udp"
    asterisk = "*"

class ServiceProviderProvisioningState(str, Enum):
    """The ServiceProviderProvisioningState state of the resource. Possible values are
    'NotProvisioned', 'Provisioning', 'Provisioned', and 'Deprovisioning'.
    """

    not_provisioned = "NotProvisioned"
    provisioning = "Provisioning"
    provisioned = "Provisioned"
    deprovisioning = "Deprovisioning"

class Severity(str, Enum):
    """The severity of the issue.
    """

    error = "Error"
    warning = "Warning"

class TransportProtocol(str, Enum):
    """The transport protocol for the endpoint. Possible values are 'Udp' or 'Tcp' or 'All'.
    """

    udp = "Udp"
    tcp = "Tcp"
    all = "All"

class TunnelConnectionStatus(str, Enum):
    """The current state of the tunnel.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class VerbosityLevel(str, Enum):
    """Verbosity level. Accepted values are 'Normal', 'Minimum', 'Full'.
    """

    normal = "Normal"
    minimum = "Minimum"
    full = "Full"

class VirtualNetworkGatewayConnectionProtocol(str, Enum):
    """Gateway connection protocol. Possible values are: 'IKEv2', 'IKEv1'.
    """

    ik_ev2 = "IKEv2"
    ik_ev1 = "IKEv1"

class VirtualNetworkGatewayConnectionStatus(str, Enum):
    """Virtual network Gateway connection status
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class VirtualNetworkGatewayConnectionType(str, Enum):
    """Gateway connection type. Possible values are: 'Ipsec','Vnet2Vnet','ExpressRoute', and
    'VPNClient.
    """

    i_psec = "IPsec"
    vnet2_vnet = "Vnet2Vnet"
    express_route = "ExpressRoute"
    vpn_client = "VPNClient"

class VirtualNetworkGatewaySkuName(str, Enum):
    """Gateway SKU name.
    """

    basic = "Basic"
    high_performance = "HighPerformance"
    standard = "Standard"
    ultra_performance = "UltraPerformance"
    vpn_gw1 = "VpnGw1"
    vpn_gw2 = "VpnGw2"
    vpn_gw3 = "VpnGw3"
    vpn_gw1_az = "VpnGw1AZ"
    vpn_gw2_az = "VpnGw2AZ"
    vpn_gw3_az = "VpnGw3AZ"
    er_gw1_az = "ErGw1AZ"
    er_gw2_az = "ErGw2AZ"
    er_gw3_az = "ErGw3AZ"

class VirtualNetworkGatewaySkuTier(str, Enum):
    """Gateway SKU tier.
    """

    basic = "Basic"
    high_performance = "HighPerformance"
    standard = "Standard"
    ultra_performance = "UltraPerformance"
    vpn_gw1 = "VpnGw1"
    vpn_gw2 = "VpnGw2"
    vpn_gw3 = "VpnGw3"
    vpn_gw1_az = "VpnGw1AZ"
    vpn_gw2_az = "VpnGw2AZ"
    vpn_gw3_az = "VpnGw3AZ"
    er_gw1_az = "ErGw1AZ"
    er_gw2_az = "ErGw2AZ"
    er_gw3_az = "ErGw3AZ"

class VirtualNetworkGatewayType(str, Enum):
    """The type of this virtual network gateway. Possible values are: 'Vpn' and 'ExpressRoute'.
    """

    vpn = "Vpn"
    express_route = "ExpressRoute"

class VirtualNetworkPeeringState(str, Enum):
    """The status of the virtual network peering. Possible values are 'Initiated', 'Connected', and
    'Disconnected'.
    """

    initiated = "Initiated"
    connected = "Connected"
    disconnected = "Disconnected"

class VirtualWanSecurityProviderType(str, Enum):
    """The virtual wan security provider type.
    """

    external = "External"
    native = "Native"

class VpnClientProtocol(str, Enum):
    """VPN client protocol enabled for the virtual network gateway.
    """

    ike_v2 = "IkeV2"
    sstp = "SSTP"
    open_vpn = "OpenVPN"

class VpnConnectionStatus(str, Enum):
    """The current state of the vpn connection.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class VpnGatewayTunnelingProtocol(str, Enum):
    """VPN protocol enabled for the P2SVpnServerConfiguration.
    """

    ike_v2 = "IkeV2"
    open_vpn = "OpenVPN"

class VpnType(str, Enum):
    """The type of this virtual network gateway. Possible values are: 'PolicyBased' and 'RouteBased'.
    """

    policy_based = "PolicyBased"
    route_based = "RouteBased"
