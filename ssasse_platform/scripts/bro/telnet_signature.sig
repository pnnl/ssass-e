signature dpd_telnet_detect {
    ip-proto == tcp
#    payload /^ *(TERMINAL|Connected) */
   dst-port = 2000-3000
#    tcp-state originator,established,responder
    enable "telnet"
}

