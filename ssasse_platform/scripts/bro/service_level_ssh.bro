module ServiceLevel;

event ssh_auth_successful(c: connection, auth_method_none: bool) {
    local ts: time = network_time();
    event ServiceLevel::ssh_packet([$ts=ts, $conn=c, $protocol="SSH", $auth_method_none=auth_method_none, $len=0, $is_orig=T]);
}

event ssh_encrypted_packet(c: connection, orig: bool, len: count) {
    local ts: time = network_time();
    event ServiceLevel::ssh_packet([$ts=ts, $conn=c, $auth_method_none=T, $protocol="SSH", $len=len, $is_orig=orig]);
}