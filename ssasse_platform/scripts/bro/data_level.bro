module DataLevel;

export {

    ## Record for the data item.
    type Info: record {
        ## Timestamp when the data is extracted
        ts: time;

        ## Connection 
        conn: connection;

        ## Protocol name
        protocol: string;

        ## Additional unit id
        uid: string;

        ## Type of data 
        data_type: string;

        ## Target index 
        index: count;

        ## Data value 
        value: double;
    
        ## Whether is an Event
        is_event: bool &default=F;
    };

    global data_get: event(info: Info);
}


function key_gen(conn: connection, headers: ModbusHeaders): string
{
    return cat(conn$id$orig_h, ",", conn$id$resp_h, ",", conn$id$resp_p, ",", headers$uid);
}

@load data_level_modbus.bro
@load data_level_dnp3.bro
