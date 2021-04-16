@load-sigs telnet_signature.sig

module ServiceLevel;

export {
redef enum Log::ID += { LOG };

}

const ports = {23/tcp};

redef likely_server_ports += { ports };

function is_login_conn(c: connection): bool
{
    return c$id$resp_p in ports;
}

# Initialize the Telnet logging stream and ports.
event zeek_init() &priority=5
{
	#Log::create_stream(Login::LOG, [$columns=Info, $ev=log_http, $path="http"]);
        Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, ports);
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string) {
    local ts: time = network_time();
    print fmt("telnet packet: %s", ts);
    print fmt("telnet user: %s", user);
    print fmt("telnet password: %s", password);
    event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET", $user=user, $password=password, $is_orig=T]);
}

event login_failure(c: connection, user: string, client_user: string,
			password: string, line: string) 
{
    local ts: time = network_time();
    print fmt("telnet login failure user: %s", user);
    print fmt("telnet login failure password: %s", password);
    event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET", 
    $user=user, $password=password, $is_orig=T]);
}

event login_input_line(c: connection, line: string) {
    local ts: time = network_time();
    print fmt("telnet input line %s", line);
    event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET", $line=line]);
}

event login_output_line(c: connection, line: string) {
    local ts: time = network_time();
    print fmt("telnet output line %s", line);
    event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET", $line=line]);
}


event login_terminal(c: connection, terminal: string)
{
    local ts: time = network_time();
    print fmt("telnet login terminal %s", terminal);
    event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET", $line=terminal]);
}

event login_prompt(c: connection, prompt: string)
{
    local ts: time = network_time();
    print fmt("telnet login prompt %s", prompt);
    event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET", $line=prompt]);
}


event connection_established(c: connection)
{
#    print "connection established", c;
    if ( is_login_conn(c) ) {
        local ts: time = network_time();
        event ServiceLevel::telnet_packet([$ts=ts, $conn=c, $protocol="TELNET"]);
        print("telnet connection established");
    }
}

event signature_match(state: signature_state, msg: string, data: string)
{
	print "signature match", msg, data;
}

event zeek_done()
{
    print fmt("service_level_telnet.bro: done"); 
}

