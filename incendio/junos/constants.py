"""Constants for the JunOS driver."""

# OpenConfig mapping
# ref: https://github.com/openconfig/public/blob/master/release/models/network-instance/openconfig-network-instance-types.yang  # noqa
OC_NETWORK_INSTANCE_TYPE_MAP = {
    "default": "DEFAULT_INSTANCE",
    "l2vpn": "L2VPN",
    "vrf": "L3VRF",
    "evpn": "BGP_EVPN",
    "vpls": "BGP_VPLS",
    "forwarding": "L2P2P",
}
