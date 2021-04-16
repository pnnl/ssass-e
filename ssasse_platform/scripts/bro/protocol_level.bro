module ProtocolLevel;

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

        ## Function code 
        fc: count;

        ## Function name 
        fn: string;

        ## True if the function is sent from the originator side
        is_orig: bool;
    };

    global protocol_get: event(info: Info);
    global dnp3_packet: event(info: Info);
    global modbus_packet: event(info: Info);
}

#event protocol_get(info: Info)
#{
#    print(cat(info$fn, " ", info$is_orig));
#}

#event dnp3_packet(info: Info)
#{
#    print(cat(info$fn, " ", info$is_orig));
#}

@load protocol_level_modbus.bro
@load protocol_level_dnp3.bro
