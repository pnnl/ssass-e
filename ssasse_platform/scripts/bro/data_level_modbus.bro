module DataLevel;

type IndexRange: record {
    start: count;
    quantity: count;
};

global g_index_table: table[string] of IndexRange;

event modbus_read_coils_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    local key: string = key_gen(c, headers);
    g_index_table[key] = [$start=start_address, $quantity=quantity];
}

event modbus_read_coils_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
    local key: string = key_gen(c, headers);
    if(key in g_index_table) {
        local index: IndexRange = g_index_table[key];
        local i = 0;
        local ts: time = network_time();
        while(i < index$quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="Modbus", $uid=cat(headers$uid), $data_type="Coil", $index=index$start+i, $value=coils[i]?1.0:-1.0]);
            ++i;
        }
    }
}

event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{    
    local key: string = key_gen(c, headers);
    g_index_table[key] = [$start=start_address, $quantity=quantity];
}

event modbus_read_discrete_inputs_response(c: connection, headers: ModbusHeaders, coils: ModbusCoils)
{
    local key: string = key_gen(c, headers);
    if(key in g_index_table) {
        local index: IndexRange = g_index_table[key];
        local i = 0;
        local ts: time = network_time();
        while(i < index$quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="Modbus", $uid=cat(headers$uid), $data_type="DiscreteInput", $index=index$start+i, $value=coils[i]?1.0:-1.0]);
            ++i;
        }
    }
}

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    local key: string = key_gen(c, headers);
    g_index_table[key] = [$start=start_address, $quantity=quantity];
}

event modbus_read_holding_registers_response(c: connection, headers: ModbusHeaders, registers: ModbusRegisters)
{
    local key: string = key_gen(c, headers);
    if(key in g_index_table) {
        local index: IndexRange = g_index_table[key];
        local i = 0;
        local ts: time = network_time();
        while(i < index$quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="Modbus", $uid=cat(headers$uid), $data_type="HoldingRegister", $index=index$start+i, $value=0.0+registers[i]]);
            ++i;
        }
    }
}

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    local key: string = key_gen(c, headers);
    g_index_table[key] = [$start=start_address, $quantity=quantity];
}

event modbus_read_input_registers_response(c: connection, headers: ModbusHeaders, registers: ModbusRegisters)
{
    local key: string = key_gen(c, headers);
    if(key in g_index_table) {
        local index: IndexRange = g_index_table[key];
        local i = 0;
        local ts: time = network_time();
        while(i < index$quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="Modbus", $uid=cat(headers$uid), $data_type="InputRegister", $index=index$start+i, $value=0.0+registers[i]]);
            ++i;
        }
    }
}

event modbus_read_write_multiple_registers_request(c: connection, headers: ModbusHeaders, read_start_address: count, read_quantity: count, write_start_address: count, write_registers: ModbusRegisters)
{
    local key: string = key_gen(c, headers);
    g_index_table[key] = [$start=read_start_address, $quantity=read_quantity];
}

event modbus_read_write_multiple_registers_response(c: connection, headers: ModbusHeaders, written_registers: ModbusRegisters)
{
    local key: string = key_gen(c, headers);
    if(key in g_index_table) {
        local index: IndexRange = g_index_table[key];
        local i = 0;
        local ts: time = network_time();
        while(i < index$quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="Modbus", $uid=cat(headers$uid), $data_type="HoldingRegister", $index=index$start+i, $value=0.0+written_registers[i]]);
            ++i;
        }
    }
}
