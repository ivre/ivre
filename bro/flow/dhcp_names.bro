@load base/protocols/dhcp

@load policy/frameworks/dpd/detect-protocols
@load policy/frameworks/intel/do_notice
@load policy/frameworks/intel/seen
@load policy/frameworks/software/windows-version-detection
@load policy/protocols/ftp/detect


@load policy/misc/known-devices

module IvreFlow;

export {
    redef record Known::DevicesInfo += {
            host:	addr		&log &optional;
            name:	string		&log &optional;
            source: string &log &optional;
    };

    global mac2name: table[string] of string &create_expire=1day &synchronized &redef;
}

event dhcp_inform(c: connection, msg: dhcp_msg, host_name: string)
{
    if (msg$h_addr == "")
        return;

    if (msg$h_addr !in Known::known_devices) {
        add Known::known_devices[msg$h_addr];
        mac2name[msg$h_addr] = host_name;
        Log::write(Known::DEVICES_LOG, [$ts=network_time(), $mac=msg$h_addr,
                                        $host=DHCP::reverse_ip(msg$ciaddr),
                                        $name=host_name,
                                        $source="dhcp_inform"]);
    }
}

event dhcp_request(c: connection, msg: dhcp_msg, req_addr: addr,
                   serv_addr: addr, host_name: string)
{
    if (msg$h_addr == "")
        return;

    mac2name[msg$h_addr] = host_name;
    local addr_ = req_addr;
    if (addr_ == 0.0.0.0)
        addr_ = DHCP::reverse_ip(msg$ciaddr);
    if (addr_ != 0.0.0.0)
        Log::write(Known::DEVICES_LOG, [$ts=network_time(), $mac=msg$h_addr,
                                        $host=addr_, $name=host_name,
                                        $source="dhcp_request"]);
}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr,
               router: dhcp_router_list, lease: interval, serv_addr: addr,
               host_name: string)
{
    local name = host_name;
    if (name == "" && msg$h_addr in mac2name)
        name = mac2name[msg$h_addr];

    local addr_ = DHCP::reverse_ip(msg$yiaddr);
    if (addr_ == 0.0.0.0)
        addr_ = DHCP::reverse_ip(msg$ciaddr);

    if (name != "")
        Log::write(Known::DEVICES_LOG, [$ts=network_time(), $mac=msg$h_addr,
                                        $host=addr_, $name=name,
                                        $source="dhcp_ack"]);
}
