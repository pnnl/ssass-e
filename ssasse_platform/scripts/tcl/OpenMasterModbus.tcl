set interface "4"
set file_path "C:\\Users\\Administrator\\Desktop\\ProtocolTestHarness\\PacketCaptures\\"
set outfile_path "C:\\Users\\Administrator\\Desktop\\ProtocolTestHarness\\JSON\ Profiles\\"
set slash "\\"
set pcapng_ext ".pcapng"
set local_file_name ""
set var1 local_file_name
set file_name "file_read.xml"
set remote_file_name "V:/ModbusDeviceConfiguration.xml"
set outfile_ext ".json"

# open targets file and read into a variable
set targets_file [open "C:\\Program\ Files\\Triangle\ MicroWorks\\Protocol\ Test\ Harness\\modbus_targets.txt"]
set targets [split [read $targets_file] "\n"]
close $targets_file

set msesn 0
set session msesn
set cmd_var "\[parseDNPResponse VARIATION0\]"
set commands_list [list "-modbus_readcoils_all" "mmbreadcoils session $$session  start 0  quantity 125 statVariable cmdStatus dataVariable data_array" \
						"-modbus_read_discrete_all" "mmbreaddinputs session $$session  start 0  quantity 125 statVariable cmdStatus dataVariable data_array" \
						"-modbus_read_holding_registers_all" "mmbreadhregs session $$session start 0 quantity 125 statVariable cmdStatus dataVariable data_array" \
						"-modbus_read_input_registers_all" "mmbreadiregs session $$session start 0 quantity 125 statVariable cmdStatus dataVariable data_array"]

proc start_tshark {{interface "4"} {capturefile ""} {capturefilter ""}} {

	puts "DEBUG: Starting Tshark with interface: {$interface}, capturefile: {$capturefile}, and capturefilter: {$capturefilter}"
	set io [open "|tshark.exe -i {$interface} -w {$capturefile} -f {$capturefilter}" r+]
	puts "DEBUG: Waiting for Tshark to initialize..."
	after 5000
	return $io
}

proc stop_tshark {{PID ""}} {

	puts "DEBUG: Stopping process {$PID}..."
	after 1500
	exec taskkill /F /PID $PID
	return
}

# Print the data array populated with Key Value pair and the data
proc printDataArray {} {
	global data_array
	puts "DEBUG: Printing data array..."
	
	foreach index [lsort -dictionary [array names data_array]] {
		puts "\"$index\": \[\"$data_array($index)\"\]"
	}
	return
}

# Parse the modbus traffic
proc parseModbusResponse {} {
  global data_array
  puts "DEBUG: parseDNPResponse is running ..."

	if {[info exists data_array(AC)] == 1} {
		foreach index [array names data_array AC] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(FC)] == 1} {
		foreach index [array names data_array FC] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,FLAG0)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,POINT0,FLAG*]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,VAR)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,VAR*]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,GRP)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,GRP*]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,QUAL)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,QUAL*]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
		
	if {[info exists data_array(OBJ0,POINT0,VARIATION0)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,POINT0,VARIATION*]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,START)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ*,START]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
		foreach index [lsort -dictionary [array names data_array OBJ*,STOP]] {
			puts  "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(IIN)] == 1} {
		foreach index [array names data_array IIN] {
			puts  "\"$index\": \[\"$data_array($index)\"\]"
		}
	}
	
	return
}

# Print data array to a JSON file
proc printJSONOutput {} {
	global data_array
	global outfile 
	set otf $outfile
	puts "DEBUG: Printing into JSON file..."
	puts "DEBUG: Outfile is: $otf"
	# Opening and writing to file
	set file [open $otf w+]
	puts $file "{"
	if {[info exists data_array(AC)] == 1} {
		foreach index [array names data_array AC] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(FC)] == 1} {
		foreach index [array names data_array FC] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,FLAG)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,POINT0,FLAG*]] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,VAR)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,VAR*]] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,GRP)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,GRP*]] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,QUAL)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,QUAL*]] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
		
	if {[info exists data_array(OBJ0,POINT0,VARIATION0)] == 1} {
		foreach index [lsort -dictionary [array names data_array OBJ0,POINT0,VARIATION*]] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(OBJ0,START)] == 1} {
		foreach index [array names data_array OBJ*,START] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
		foreach index [array names data_array OBJ*,STOP] {
			puts $file "\"$index\": \[\"$data_array($index)\"\],"
		}
	}
	
	if {[info exists data_array(IIN)] == 1} {
		foreach index [array names data_array IIN] {
			puts $file "\"$index\": \[\"$data_array($index)\"\]"
		}
	}
	
	puts $file "}"

	close $file
	
	return
}

# Exclude data points for parsing objects (Not working yet)
proc parseDNPNoData {} {
	global data_array
	global outfile
	set otf $outfile
	puts "DEBUG: ParseDNPNoData running ..."
	
	# Opening and writing to file
	set file [open $otf w+]
	puts $file "\{"
	foreach index [lsort -dictionary [array names data_array]] {
		puts $file "\"$index\": \[\"$data_array($index)\"\],"
	}
	puts $file "\}"
	close $file
	
	return
}

#loop over targets and execute polls
puts "DEBUG: Starting Command Loop..."
foreach target $targets {
	global local_file_name
	#parse each target line for IP, DNP master, and DNP slave
	set device [string trim [lindex [split $target] 0]]
    set IP [string trim [lindex [split $target] 1]]
	set MB_slave [string trim [lindex [split $target] 2]]
	set capturefilter "host 172.17.128.23 and host "
	set capturefilter $capturefilter$IP
	set new_file_path $file_path$device$slash
	set local_file_name $file_path$device$slash$file_name
	puts "DEBUG: Local file location: $local_file_name"
	set new_outfile $outfile_path$device$slash
	puts "DEBUG: Outfile location: $new_outfile"
	set channel_name "mMB-"
	
	#Fill capture data into variables, this will be done for each command
	set capfilepostfix "-tcp_handshake_start.pcapng"
	set capturefile $new_file_path$channel_name$IP$capfilepostfix
	
	#Open tshark for capture using filter and store results in command-specific file
    set tshark [start_tshark $interface $capturefile $capturefilter]
	
	#Open DNP Channel and Session
	puts "DEBUG: Opening Channel and Session..."
	set mchannel [mmbopenchannel mode client host $IP name $channel_name$IP]
    set msesn [mmbopensession channel $mchannel IP $MB_slave]
	puts "$msesn..."
	
	after 3000
	stop_tshark [pid $tshark]
	
	#Commands Loop
	foreach {name cmd} $commands_list {
		puts "$local_file_name"
		puts "$cmd"
		puts "$name -> [subst $cmd]"
		#Fill capture data into variables, this will be done for each command
		set capfilepostfix $name$pcapng_ext
		set capturefile $new_file_path$channel_name$IP$capfilepostfix
		set outfile $new_outfile$channel_name$IP$name$outfile_ext
		puts "DEBUG: Outfile path = $outfile"
		#Open tshark for capture using filter and store results in command-specific file
		set tshark [start_tshark $interface $capturefile $capturefilter]
		# Execute command poll
		eval $cmd
		vwait cmdStatus
		# Print the data array into the command window
		printDataArray
		# Parse the data into a JSON file
		parseModbusResponse
		printJSONOutput
		#parseDNPNoData
		# Clear the data array for next loop
		array unset data_array
		# Wait for poll to finish, then stop packet capture
		stop_tshark [pid $tshark]
	}
	
	# close the DNP channel and session
	# Fill capture data into variables, this will be done for each command
	set capfilepostfix "-tcp_handshake_stop.pcapng"
	set capturefile $new_file_path$channel_name$IP$capfilepostfix
	
	# Open tshark for capture using filter and store results in command-specific file
    set tshark [start_tshark $interface $capturefile $capturefilter]
	puts "DEBUG: Waiting for session close..."

	mmbclosesession session $msesn
	mmbclosechannel channel $mchannel
	
	after 5000
	stop_tshark [pid $tshark]
}

puts "Done"