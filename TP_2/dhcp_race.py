from scapy.all import DHCP_am

dhcp_server = DHCP_am(
    iface='enp0s3',
    pool=['10.1.10.251'],
    network='10.1.10.0/24',
    gw='10.1.10.254'
)

dhcp_server()
