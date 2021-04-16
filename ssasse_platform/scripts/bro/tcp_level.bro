module TcpLevel;

export {
    ## Record for the tcp item.
    type Info: record {
        ## Timestamp when the data is extracted
        ts: time;

        ## Connection
        conn: connection;

        ## TCP flags 
        flags: string;
        
	## sequence number
	seq: count;

	## ACK
	ack: count;
	
	## length
	len: count;
	
	## payload
#	payload: string;

	## True if the function is sent from the originator side
	is_orig: bool;
    };

    type ROCInfo: record {
        ## Timestamp when the data is extracted
        ts: time;

        ## Connection
        conn: connection;

        ## Protocol name
        protocol: string;

        ## payload
        payload: string;

        ## len
        len: count;

        ## True if the function is sent from the originator side
        is_orig: bool;
    };

    global tcp_packet_get: event(info: Info);
    global rocplus_packet_get: event(info: ROCInfo);
}

global total_time: interval = 0sec;
global total_count: count = 1;

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) &priority=5
{
    local start: time = current_time();
    local ts: time = network_time();
    if (c$id$resp_p == 4000/tcp) {
#        print fmt("tcp packet: %s, payload: %s, len: %d, pp: %f", ts, payload, len, payload[5]);
        event TcpLevel::rocplus_packet_get([$ts=ts, $conn=c, $protocol="ROCPLUS", $payload=payload, $len=len, $is_orig=is_orig]);
    }
    event TcpLevel::tcp_packet_get([$ts=ts, $conn=c, $flags=flags, $seq=seq, $ack=ack, $len=len, $is_orig=is_orig]);
#    event TcpLevel::tcp_packet_get([$ts=ts, $conn=c, $flags=flags, $seq=seq, $ack=ack, $len=len, $payload=payload, $is_orig=is_orig]);
    total_time += current_time() - start;
    total_count += 1;
}

event zeek_done()
{
    local flow_time: interval = total_time / total_count;
    print fmt("tcp_bro: %s", flow_time); 
}
