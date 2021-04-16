module DataLevel;

global g_uid: string;   # global variable to store the unit id 
global g_pro: string;   # global variable to store the protocol 
global g_fun: string;   # global variable to store the function code 
global g_start: count;  # global variable to store the starting address
global g_quantity: count;   # global variable to store the quantity
global g_tgt: string;   # global variable to store the target 
global dnp3_group: count;      # global variable to store the group number
global dnp3_variation: count;  # global variable to store the variation number
global dnp3_shift : count = 0;    # global variable to store the current index shift
global dnp3_quantity: count;   # global variable to store the count value
global dnp3_prefix: bool;      # global variable to indicate whether following prefixes should be paid attention to

global dnp3_start: time;
global total_time: interval = 0sec;
global packet_time: interval = 0sec;
global total_count: count = 0;


# A helper function to convert Int32 stored in count to double 
function int32_convert(val: count): double 
{
    if(val < 2147483648) {
        return to_double(cat(val));
    }

    local cur: double = 1.0;
    local rst: double = 0;
    local i = 0;
    while(i < 31) {
        rst = rst + (val % 2 == 1 ? 0 : cur);
        val = val / 2; 
        cur = cur * 2;
        ++i;
    }
    return -rst-1;
}


# A helper function to convert Int16 stored in count to double 
function int16_convert(val: count): double 
{
    if(val < 32768) {
        return to_double(cat(val));
    }

    local cur: double = 1.0;
    local rst: double = 0;
    local i = 0;
    while(i < 15) {
        rst = rst + (val % 2 == 1 ? 0 : cur);
        val = val / 2; 
        cur = cur * 2;
        ++i;
    }
    return -rst-1;
}


# A helper function to generate the target value
function target_gen(name: string, start_address: count, quantity: count): string
{
    if (quantity == 0)
    {
        return cat(name, ":", "Nothing");
    }
    else if (quantity == 1)
    {
        return cat(name, ":", start_address);
    }
    else
    {
        return cat(name, ":", start_address, "-", start_address+quantity-1);
    }
}


# A helper function to convert float stored in count back 
function float_convert(val: count): double 
{
    local mantissa: vector of bool;
    local i = 24;
    while(i > 1) {
        mantissa[i] = (val % 2 == 1);
        val = val / 2; 
        --i;
    }
    mantissa[1] = T;
    i = 1;
    local exponent: int = 0;
    while(i < 256) {
        exponent = exponent + (val % 2) * i;
        val = val / 2;
        i = i * 2;
    }
    exponent = exponent - 127;
    local base: double = 1.0;
    if(exponent > 0) {
        while(exponent > 0) {
            base = base * 2;
            --exponent;
        }
    } else if(exponent < 0) {
        while(exponent < 0) {
            base = base / 2;
            ++exponent;
        }
    }
    
    local rst: double = 0;
    i = 1;
    while(i < 25) {
        rst = rst + (mantissa[i] ? base : 0.0);
        base = base / 2;
        ++i;
    }

    return val % 2 == 1 ? -rst : rst;
}


# A helper function to convert double stored in count back 
function double_convert(val_low: count, val_high: count): double 
{
    local mantissa: vector of bool;
    local i = 53;
    while(i > 21) {
        mantissa[i] = (val_low % 2 == 1);
        val_low = val_low / 2; 
        --i;
    }
    while(i > 1) {
        mantissa[i] = (val_high % 2 == 1);
        val_high = val_high / 2; 
        --i;
    }
    mantissa[1] = T;
    i = 1;
    local exponent: int = 0;
    while(i < 2048) {
        exponent = exponent + (val_high % 2) * i;
        val_high = val_high / 2;
        i = i * 2;
    }
    exponent = exponent - 1023;
    local base: double = 1.0;
    if(exponent > 0) {
        while(exponent > 0) {
            base = base * 2;
            --exponent;
        }
    } else if(exponent < 0) {
        while(exponent < 0) {
            base = base / 2;
            ++exponent;
        }
    }
    
    local rst: double = 0;
    i = 1;
    while(i < 54) {
        rst = rst + (mantissa[i] ? base : 0.0);
        base = base / 2;
        ++i;
    }

    return val_high % 2 == 1 ? -rst : rst;
}


# Extract the group number from a combination of the group and variation number
function get_group(obj_type: count): count
{
    return (obj_type - (obj_type % 256)) / 256;
}

# Extract the variation number from a combination of the group and variation number
function get_variation(obj_type: count): count
{
    return obj_type % 256;
}

# Extract the object prefix code from the qualifier code
function get_obj_prefix_code(qua_field: count): count
{
    return ((qua_field - (qua_field % 16)) / 16) % 8;
}

# Extract the range specification code from the qualifier code
function get_range_spec_code(qua_field: count): count
{
    return qua_field % 16;
}

# Get the additional addresses from the header
event dnp3_header_block(c: connection, is_orig: bool, len: count, ctrl: count, dest_addr: count, src_addr: count)
{
    g_uid = cat(src_addr, ":", dest_addr);
}

# Get the DNP3 protocol name and the function code from the dnp3 application request header
event dnp3_application_request_header(c: connection, is_orig: bool, application: count, fc: count)
{
    g_pro = "DNP3";
    g_fun = DNP3::function_codes[fc];
}

# Get the DNP3 protocol name and the function code from the dnp3 application response header
event dnp3_application_response_header(c: connection, is_orig: bool, application: count, fc: count, iin: count)
{
    total_time += packet_time;
    total_count += 1;
    packet_time = 0sec;
    dnp3_start = current_time();
    g_pro = "DNP3";
    g_fun = DNP3::function_codes[fc];
}

# Depending on the qualifier code, store different statistics in the target level
event dnp3_object_header(c: connection, is_orig: bool, obj_type: count, qua_field: count, number: count, rf_low: count, rf_high: count)
{
    dnp3_group = get_group(obj_type);
    dnp3_variation = get_variation(obj_type);

    local obj_prefix_code = get_obj_prefix_code(qua_field);
    local range_spec_code = get_range_spec_code(qua_field);
    dnp3_prefix = F;

    if (obj_prefix_code == 0 && (range_spec_code == 0 || range_spec_code == 1))
    {
        g_tgt = target_gen("Group", dnp3_group, 1);
        g_tgt = cat(g_tgt, " ", target_gen("Variation", dnp3_variation, 1));
        g_tgt = cat(g_tgt, " ", target_gen("Target", rf_low, rf_high-rf_low+1));
        g_start = rf_low;
        g_quantity = rf_high-rf_low+1;
    }

    if (obj_prefix_code == 0 && range_spec_code == 6)
    {
        g_tgt = target_gen("Group", dnp3_group, 1);
        g_tgt = cat(g_tgt, " ", target_gen("Variation", dnp3_variation, 1));
        g_tgt = cat(g_tgt, " ", "Target:all");
    }

    if (obj_prefix_code == 0 && (range_spec_code == 7 || range_spec_code == 8))
    {
        dnp3_quantity = rf_low;

        g_tgt = target_gen("Group", dnp3_group, 1);
        g_tgt = cat(g_tgt, " ", target_gen("Variation", dnp3_variation, 1));
        g_tgt = cat(g_tgt, " ", target_gen("Quantity", dnp3_quantity, 1));
    }

    if ((obj_prefix_code == 1 && range_spec_code == 7) || (obj_prefix_code == 2 && range_spec_code == 8))
    {
        dnp3_quantity = rf_low;
        dnp3_prefix = T;
    }

    if (obj_prefix_code == 5 && range_spec_code == 11)
    {
        dnp3_quantity = rf_low;
        g_tgt = target_gen("Group", dnp3_group, 1);
        g_tgt = cat(g_tgt, " ", target_gen("Variation", dnp3_variation, 1));
        g_tgt = cat(g_tgt, " ", target_gen("Quantity", dnp3_quantity, 1));
    }
}

# In case the qualifier code is 0x17 or 0x28, look at the following prefixes to get the indexes
event dnp3_object_prefix(c: connection, is_orig: bool, prefix_value: count)
{
    if (dnp3_prefix)
    {
        #print fmt("group:%d variation:%d target:%d", dnp3_group, dnp3_variation, prefix_value);

        g_tgt = target_gen("Group", dnp3_group, 1);
        g_tgt = cat(g_tgt, " ", target_gen("Variation", dnp3_variation, 1));
        g_tgt = cat(g_tgt, " ", target_gen("Target", prefix_value, 1));
        g_start = prefix_value;
        g_quantity = 1;
    }
}

event dnp3_response_data_object(c: connection, is_orig: bool, data_value: count)
{
    local ts: time = network_time();
    #print(g_tgt);
    #print(data_value);
    if(dnp3_group == 1)
    {
        local i = 0;
        while(i < 8 && dnp3_shift < g_quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Binary", $index=g_start+dnp3_shift, $value=(data_value%2==1)?1.0:-1.0]);
            #print(cat("Binary ", g_start+dnp3_shift, ":", data_value%2));
            data_value = data_value / 2;
            ++dnp3_shift;
            ++i; 
        }
        if(dnp3_shift == g_quantity) {
            dnp3_shift = 0;
        }
    }
    else if(dnp3_group == 2)
    {
        i = 0;
        while(i < 8 && dnp3_shift < g_quantity) {
            event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Binary", $index=g_start+dnp3_shift, $value=(data_value%2==1)?1.0:-1.0, $is_event=T]);
            #print(cat("Binary ", g_start+dnp3_shift, ":", data_value%2));
            data_value = data_value / 2;
            ++dnp3_shift;
            ++i; 
        }
        if(dnp3_shift == g_quantity) {
            dnp3_shift = 0;
        }
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_32wFlag(c: connection, is_orig: bool, flag: count, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int32_convert(value)]);
    #print(cat("Int32 ", g_start+dnp3_shift, ":", int32_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_32woFlag(c: connection, is_orig: bool, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int32_convert(value)]);
    #print(cat("Int32 ", g_start+dnp3_shift, ":", int32_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_32wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int32_convert(value), $is_event=T]);
    #print(cat("Int32 ", g_start+dnp3_shift, ":", int32_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_32woTime(c: connection, is_orig: bool, flag: count, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int32_convert(value), $is_event=T]);
    #print(cat("Int32 ", g_start+dnp3_shift, ":", int32_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_16wFlag(c: connection, is_orig: bool, flag: count, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int16_convert(value)]);
    #print(cat("Int16 ", g_start+dnp3_shift, ":", int16_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_16woFlag(c: connection, is_orig: bool, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int16_convert(value)]);
    #print(cat("Int16 ", g_start+dnp3_shift, ":", int16_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_16wTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int16_convert(value), $is_event=T]);
    #print(cat("Int16 ", g_start+dnp3_shift, ":", int16_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_16woTime(c: connection, is_orig: bool, flag: count, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=int16_convert(value), $is_event=T]);
    #print(cat("Int16 ", g_start+dnp3_shift, ":", int16_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_SPwFlag(c: connection, is_orig: bool, flag: count, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=float_convert(value)]);
    #print(cat("Float ", g_start+dnp3_shift, ":", float_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_SPwTime(c: connection, is_orig: bool, flag: count, value: count, time48: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=float_convert(value), $is_event=T]);
    #print(cat("Float ", g_start+dnp3_shift, ":", float_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_SPwoTime(c: connection, is_orig: bool, flag: count, value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=float_convert(value), $is_event=T]);
    #print(cat("Float ", g_start+dnp3_shift, ":", float_convert(value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_DPwFlag(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=double_convert(value_low, value_high)]);
    #print(cat("Double ", g_start+dnp3_shift, ":", double_convert(value_low, value_high)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_DPwTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count, time48: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=double_convert(value_low, value_high), $is_event=T]);
    #print(cat("Double ", g_start+dnp3_shift, ":", double_convert(value_low, value_high)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_analog_input_event_DPwoTime(c: connection, is_orig: bool, flag: count, value_low: count, value_high: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Analog", $index=g_start+dnp3_shift, $value=double_convert(value_low, value_high), $is_event=T]);
    #print(cat("Double ", g_start+dnp3_shift, ":", double_convert(value_low, value_high)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_counter_32wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Counter", $index=g_start+dnp3_shift, $value=int32_convert(count_value)]);
    #print(cat("Counter32 ", g_start+dnp3_shift, ":", int32_convert(count_value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_counter_32woFlag(c: connection, is_orig: bool, count_value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Counter", $index=g_start+dnp3_shift, $value=int32_convert(count_value)]);
    #print(cat("Counter32 ", g_start+dnp3_shift, ":", int32_convert(count_value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_counter_16wFlag(c: connection, is_orig: bool, flag: count, count_value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Counter", $index=g_start+dnp3_shift, $value=int16_convert(count_value)]);
    #print(cat("Counter16 ", g_start+dnp3_shift, ":", int16_convert(count_value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event dnp3_counter_16woFlag(c: connection, is_orig: bool, count_value: count)
{
    local ts: time = network_time();
    event DataLevel::data_get([$ts=ts, $conn=c, $protocol="DNP3", $uid=g_uid, $data_type="Counter", $index=g_start+dnp3_shift, $value=int16_convert(count_value)]);
    #print(cat("Counter16 ", g_start+dnp3_shift, ":", int16_convert(count_value)));
    ++dnp3_shift;
    if(dnp3_shift == g_quantity) {
        dnp3_shift = 0;
    }
    packet_time = max_interval(packet_time, current_time()-dnp3_start); 
}

event zeek_done()
{
    total_time += packet_time;
    if(total_count > 0) {
        local content_time: interval = total_time / total_count;
        print fmt("Content_bro: %s", content_time);
    }
}
