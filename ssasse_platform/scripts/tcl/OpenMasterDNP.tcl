# Set the Interface for Wireshark to read the Protocols
set interface "3"
set file_path "C:\\Path\\To\\Desired\\Location\\For\\Packet\\Captures\\"
set outfile_path "C:\\Path\\To\\Desired\\Location\\For\\Output\\Profiles\\"
set slash "\\"
set pcapng_ext ".pcapng"

# open targets file and read into a variable
set targets_file [open "C:\\Path\\To\\\dnp3_targets.txt"]
set targets [split [read $targets_file] "\n"]
close $targets_file


set local_file_name ""
set var1 local_file_name
set file_name "file_read.xml"
set outfile_ext ".json"
set remote_file_name "V:/DNPDeviceConfiguration.xml"

set msesn 0
set session msesn
set cmd_var "\[parseDNPResponse VARIATION0\]"
set commands_list [list "-dnp3_Binary_Input" "mdnpread session $$session object 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_device_attr_variation" "mdnpread session $$session object 0 variation 255 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_File_Read" "mdnpfilecopyfromremote session $$session remoteFileName $remote_file_name localFileName $$var1 statVariable cmdStatus dataVariable data_array" ]
#						"-dnp3_class0123" "mdnpintegrity session $$session statVariable cmdStatus dataVariable data_array" \
						"-dnp3_device_attr" "mdnpread session $$session object 0 variation 254 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_device_attr_variation" "mdnpread session $$session object 0 variation 255 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input" "mdnpread session $$session object 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input_packed_without_status" "mdnpread session $$session object 1 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input_with_Status" "mdnpread session $$session object 1 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input_Change" "mdnpread session $$session object 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input_Change_without_Time" "mdnpread session $$session object 2 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input_Change_with_Time" "mdnpread session $$session object 2 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Input_Change_with_Relative_Time" "mdnpread session $$session object 2 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input" "mdnpread session $$session object 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input_packed_without_Status" "mdnpread session $$session object 3 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input_with_Status" "mdnpread session $$session object 3 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input_Change" "mdnpread session $$session object 4 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input_Change_without_Time" "mdnpread session $$session object 4 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input_Change_without_Time" "mdnpread session $$session object 4 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Double_Bit_Input_Change_with_Relative_Time" "mdnpread session $$session object 4 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Output" "mdnpread session $$session object 10 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Output_Packed_without_status" "mdnpread session $$session object 10 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Output_with_status" "mdnpread session $$session object 10 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Counter" "mdnpread session $$session object 20 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Counter_32-Bit_with_Flag" "mdnpread session $$session object 20 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Counter_16-Bit_with_Flag" "mdnpread session $$session object 20 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Counter_32-Bit_without_Flag" "mdnpread session $$session object 20 variation 5 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Binary_Counter_16-Bit_without_Flag" "mdnpread session $$session object 20 variation 6 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters" "mdnpread session $$session object 21 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters_32-Bit_with_Flag" "mdnpread session $$session object 21 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters_16-Bit_with_Flag" "mdnpread session $$session object 21 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters_32-Bit_with_Time_of_Freeze" "mdnpread session $$session object 21 variation 5 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters_16-Bit_with_Time_of_Freeze" "mdnpread session $$session object 21 variation 6 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters_32-Bit_without_Flag" "mdnpread session $$session object 21 variation 9 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counters_16-Bit_without_Flag" "mdnpread session $$session object 21 variation 10 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Counter_Change_Event" "mdnpread session $$session object 22 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Counter_Change_Event_32-Bit_without_Time" "mdnpread session $$session object 22 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Counter_Change_Event_16-Bit_without_Time" "mdnpread session $$session object 22 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Counter_Change_Event_32-Bit_with_Time" "mdnpread session $$session object 22 variation 5 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Counter_Change_Event_16-Bit_with_Time" "mdnpread session $$session object 22 variation 6 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counter_Events" "mdnpread session $$session object 23 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counter_Events_32-Bit_without_Time" "mdnpread session $$session object 23 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counter_Events_16-Bit_without_Time" "mdnpread session $$session object 23 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counter_Events_32-Bit_with_Time" "mdnpread session $$session object 23 variation 5 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Frozen_Counter_Events_16-Bit_with_Time" "mdnpread session $$session object 23 variation 6 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input" "mdnpread session $$session object 30 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_32-Bit_with_Flag" "mdnpread session $$session object 30 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_16-Bit_with_Flag" "mdnpread session $$session object 30 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_32-Bit_without_Flag" "mdnpread session $$session object 30 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_16-Bit_without_Flag" "mdnpread session $$session object 30 variation 4 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_Short_Floating_Point_(32-Bit)" "mdnpread session $$session object 30 variation 5 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_Long_Floating_Point_(64-Bit)" "mdnpread session $$session object 30 variation 6 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event" "mdnpread session $$session object 32 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_32-Bit_without_Time" "mdnpread session $$session object 32 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_16-Bit_without_Time" "mdnpread session $$session object 32 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_32-Bit_with_Time" "mdnpread session $$session object 32 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_16-Bit_with_Time" "mdnpread session $$session object 32 variation 4 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_Short_Float_without_Time" "mdnpread session $$session object 32 variation 5 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_Long_Float_without_Time" "mdnpread session $$session object 32 variation 6 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_Short_Float_with_Time" "mdnpread session $$session object 32 variation 7 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Change_Event_Long_Float_with_Time" "mdnpread session $$session object 32 variation 8 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_Deadband" "mdnpread session $$session object 34 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_Deadband_16-Bit" "mdnpread session $$session object 34 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_Deadband_32-Bit" "mdnpread session $$session object 34 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Input_Deadband_Floating_Point" "mdnpread session $$session object 34 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Output_Status" "mdnpread session $$session object 40 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Output_Status_32-Bit" "mdnpread session $$session object 40 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Output_Status_16-Bit" "mdnpread session $$session object 40 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Output_Status_Short_Floating_Point_(32-Bit)" "mdnpread session $$session object 40 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Analog_Output_Status_Long_Floating_Point_(64-Bit)" "mdnpread session $$session object 40 variation 4 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Class_1_Data" "mdnpread session $$session object 60 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Class_2_Data" "mdnpread session $$session object 60 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Class_3_Data" "mdnpread session $$session object 60 variation 4 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Internal_Indications" "mdnpread session $$session object 80 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Data_Set_Prototype" "mdnpread session $$session object 85 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Data_Set_Descriptor_variation1" "mdnpread session $$session object 86 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Data Set Descriptor_variation2" "mdnpread session $$session object 86 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Data_Set_Descriptor_variation3" "mdnpread session $$session object 86 variation 3 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Data_Set_Value" "mdnpread session $$session object 87 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Data_Set_Event" "mdnpread session $$session object 88 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Octet_String_Object" "mdnpread session $$session object 110 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Octet_String_Event_Object" "mdnpread session $$session object 111 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Virtual_Terminal_Events" "mdnpread session $$session object 113 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Security_Statistic" "mdnpread session $$session object 121 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Security_Statistic_Events_variation1" "mdnpread session $$session object 122 variation 1 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_Security_Statistic_Events_variation2" "mdnpread session $$session object 122 variation 2 statVariable cmdStatus dataVariable data_array" \
						"-dnp3_enable_unsol" "mdnpunsol session $$session statVariable cmdStatus dataVariable data_array" \
						"-dnp3_disable_unsol" "mdnpunsol session $$session action disable statVariable cmdStatus dataVariable data_array" \
						"-dnp3_record_time" "mdnprecordtime session $$session statVariable cmdStatus dataVariable data_array" \
						"-dnp3_8bitstartstop" "mdnpread session $$session object 1 qualifier 8bitstartstop start 254 stop 255 statVariable cmdStatus dataVariable data_array"] 
						
						#"Save Configuration"
						#"Authenticate File ??????"

# Set the Wireshark interface, file paths, and filter
proc start_tshark {{interface ""} {capturefile ""} {capturefilter ""}} {

	puts "DEBUG: Starting Tshark with interface: {$interface}, capturefile: {$capturefile}, and capturefilter: {$capturefilter}"
	set io [open "|tshark.exe -i {$interface} -w {$capturefile} -f {$capturefilter}" r+]
	puts "DEBUG: Waiting for Tshark to initialize..."
	after 5000
	return $io
}

# Stop Wireshark from running
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

# Parse the ParseDNPResponse
proc parseDNPResponse {} {
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

# Exclude data points for parsing objects (Still working on it)
proc parseDNPNoData {} {
	global data_array
	global outfile
	set otf $outfile
	puts "DEBUG: ParseDNPNoData running ..."
	
	# Opening and writing all array data to file
	set file [open $otf w+]
	puts $file "\{"
	foreach index [lsort -dictionary [array names data_array]] {
		puts $file "\"$index\": \[\"$data_array($index)\"\],"
	}
	puts $file "\}"
	close $file
	
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

#loop over targets and execute polls
puts "Starting Command Loop..."
foreach target $targets {
    global local_file_name
	#parse each target line for IP, DNP master, and DNP slave
	set device [string trim [lindex [split $target] 0]]
    set IP [string trim [lindex [split $target] 1]]
	set DNP3_master [string trim [lindex [split $target] 2]]
	set DNP3_slave [string trim [lindex [split $target] 3]]
	set capturefilter "host CHANGEME and host "
	set capturefilter $capturefilter$IP
	set new_file_path $file_path$device$slash
	set local_file_name $file_path$device$slash$file_name
	puts "Local file location: $local_file_name"
	set new_outfile $outfile_path$device$slash
	puts "New file location: $new_outfile"
	set channel_name "mDNP-"
	
	#Fill capture data into variables, this will be done for each command
	set capfilepostfix "-tcp_handshake_start.pcapng"
	set capturefile $new_file_path$channel_name$IP$capfilepostfix
	
	#Open tshark for capture using filter and store results in command-specific file
    set tshark [start_tshark $interface $capturefile $capturefilter]
	
	#Open DNP Channel and Session
	puts "DEBUG: Opening Channel and Session..."
	set mchannel [mdnpopenchannel mode client host $IP name $channel_name$IP]
    set msesn [mdnpopensession channel $mchannel source $DNP3_master destination $DNP3_slave]
	
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
		puts "DEBUG: $outfile "
		#Open tshark for capture using filter and store results in command-specific file
		set tshark [start_tshark $interface $capturefile $capturefilter]
		#execute actual command/poll
		eval $cmd
		vwait cmdStatus
		#printDataArray
		parseDNPResponse
		#parseDNPNoData (still being tested)
		printJSONOutput
		array unset data_array
		#wait for poll to finish, then stop the packet capture
		stop_tshark [pid $tshark]
	}
	
	# close the DNP channel and session
	
	# Fill capture data into variables, this will be done for each command
	set capfilepostfix "-tcp_handshake_stop.pcapng"
	set capturefile $new_file_path$channel_name$IP$capfilepostfix
	#Added output for debugging
	#puts "Watching to see change: "

	
	# Open tshark for capture using filter and store results in command-specific file
    set tshark [start_tshark $interface $capturefile $capturefilter]
	puts "DEBUG: Waiting for session close..."
	#puts "Tshark working output: $tshark"
	mdnpclosesession session $msesn
	mdnpclosechannel channel $mchannel
	
	after 5000
	stop_tshark [pid $tshark]
}

puts "Done"
	
