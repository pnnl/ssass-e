module ServiceLevel;

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
        #uid: string;

        ## True if the function is sent from the originator side
        is_orig: bool;
        
        ## Verb used in the HTTP request (GET, POST, HEAD, etc.).        
        method:                  string    &log &optional;
        
        ## URI used in the request.
        uri:                     string    &log &optional;

        ## Value of the version portion of the request.
        version:		string	   &log &optional;
                
        ## Status code returned by the server.
        status_code:             count     &log &optional;
        
        ## Status message returned by the server.
        status_msg:              string    &log &optional;
    };

    type SSHInfo: record {
        ## Timestamp when the data is extracted
        ts: time;

        ## Connection 
        conn: connection;

        ## Protocol name
        protocol: string;

        ## Length of SSH payload
        len: count;

        ## True if the analyzer detected a successful connection
        auth_method_none: bool;

        ## True if the function is sent from the originator side
        is_orig: bool;
    };

    type TelnetLoginInfo: record {
        ## Timestamp when the data is extracted
        ts: time;

        ## Connection 
        conn: connection;

        ## Protocol name
        protocol: string;

        ## username
        user: string &log &optional;

        ## password
        password: string &log &optional;
        
        ## command line
        line: string &log &optional;

        ## True if the function is sent from the originator side
        is_orig: bool &log &optional;
    };
    global http_packet: event(info: Info);
    global ssh_packet: event(info: SSHInfo);
    global telnet_packet: event(info: TelnetLoginInfo);
}

@load service_level_http.bro
@load service_level_ssh.bro
@load service_level_telnet.bro
