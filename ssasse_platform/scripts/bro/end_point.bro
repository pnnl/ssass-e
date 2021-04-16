@load flow_level.bro
@load protocol_level.bro
@load data_level.bro
@load tcp_level.bro
@load service_level.bro

module EndPoint;

export {
    const broker_port: port = 9999/tcp &redef;
#    redef Broker::peer_counts_as_iosource=F;
    redef exit_only_after_terminate = F;
}

event zeek_init() &priority=5
{
    #suspend_processing();
#    print "broker port", broker_port;
    Broker::peer("127.0.0.1", broker_port, 1sec);
    Broker::auto_publish("bro_analyser/dnp3_packet", ProtocolLevel::dnp3_packet);
    Broker::auto_publish("bro_analyser/modbus_packet", ProtocolLevel::modbus_packet);
    Broker::auto_publish("bro_analyser/data_get", DataLevel::data_get);
    Broker::auto_publish("bro_analyser/tcp_packet_get", TcpLevel::tcp_packet_get);
    # new zeek events
    print fmt("adding new zeek events");
    Broker::auto_publish("bro_analyser/http_packet", ServiceLevel::http_packet);
    Broker::auto_publish("bro_analyser/ssh_packet", ServiceLevel::ssh_packet);
    Broker::auto_publish("bro_analyser/telnet_packet", ServiceLevel::telnet_packet);
    Broker::auto_publish("bro_analyser/rocplus_packet", TcpLevel::rocplus_packet_get);
    Broker::auto_publish("bro_analyser/bro_done", zeek_done);
}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
{
    print "peer added", endpoint;
    #continue_processing();
}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
{
    print "peer lost", endpoint;
    terminate();
}

event zeek_done()
{
    print "zeek_done!!!";
}
