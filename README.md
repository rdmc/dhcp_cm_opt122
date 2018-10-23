# dhcp_cm_opt122

DHCP Opt 122 subopt 1 Packet Mangling for Cable Modems 

 "dhcp_cm_opt122" is a netfilter hock kernel module that
 changes option "122" (CableLabs Client Configuration, RFC3495), 
 sub-option "1", (TSP Primary DHCP Server) of a DHCP offer/ack for a docsis cable modem.
 The multimedia telephony adapter (MTA) portion of the device listens and acceps 
 DHCP apckets from this mangled IP address DHCP server.
 

 

