module ServiceLevel;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
{
    local ts: time = network_time();
    print fmt("http request packet, method: %s", method);
    #print fmt("http request packet, o_uri: %s", original_URI);
    #print fmt("http request packet, unescaped_uri: %s", unescaped_URI);
#    event ServiceLevel::http_packet([$ts=ts, $conn=c, $protocol="HTTP", $method=method, $uri=unescaped_URI, $is_orig=T]);
}

event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
{
    local ts: time = network_time();
    print fmt("http request packet, version: %s", version);
    #print fmt("http request packet, code: %s", code);
    #print fmt("http request packet, reason: %s", reason);
#    event ServiceLevel::http_packet([$ts=ts, $conn=c, $protocol="HTTP", $method="RESPONSE", $uri="", $status_code=code, $status_msg=reason, $is_orig=F]);
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=5
{
    print "http connection", c;
    local ts: time = network_time();
    event ServiceLevel::http_packet([$ts=ts, $conn=c, $protocol="HTTP", $uri=c$http$uri, $method=c$http$method, $is_orig=is_orig]);
}

event zeek_done()
{
    print fmt("service_level_http.bro: done"); 
}

