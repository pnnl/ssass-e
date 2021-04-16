module ProtocolLevel;

# Get the protocol name and the function code from the Modbus messege header
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    local ts: time = network_time();
    local uid: string = cat(headers$uid);
    local fc: count = headers$function_code;
    local fn: string = Modbus::function_codes[headers$function_code];

#    event ProtocolLevel::protocol_get([$ts=ts, $conn=c, $protocol="Modbus", $uid=uid, $fc=fc, $fn=fn, $is_orig=is_orig]);
    event ProtocolLevel::modbus_packet([$ts=ts, $conn=c, $protocol="Modbus", $uid=uid, $fc=fc, $fn=fn, $is_orig=is_orig]);
}
