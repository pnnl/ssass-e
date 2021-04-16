module FlowLevel;

export {
    ## Record for the flow item.
    type Info: record {
        ## Timestamp when the data is extracted
        ts: time;

        ## Connection
        conn: connection;

        ## Packet header 
        header: pkt_hdr;
    };

    global packet_get: event(info: Info);
}

global total_time: interval = 0sec;
global total_count: count = 1;

event new_packet(c: connection, p: pkt_hdr) &priority=5
{
    local start: time = current_time();
    local ts: time = network_time();
    print fmt("new packet: %s", ts);
    event FlowLevel::packet_get([$ts=ts, $conn=c, $header=p]);
    total_time += current_time() - start;
    total_count += 1;
}

event zeek_done()
{
    local flow_time: interval = total_time / total_count;
    print fmt("flow_bro: %s", flow_time); 
}
