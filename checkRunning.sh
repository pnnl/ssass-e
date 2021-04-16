#!/usr/bin/env bash

FILE="$HOME/SSASSE_PID"
if [ -f $FILE ]; then
   pid=`cat $FILE`
   if ps -p $pid > /dev/null 2>&1
   then
       echo "SSASSE with process id $pid is already running"
       exit 1
   else
       echo "PID file exists but process is not running. Removing old SSASSE_PID file"
       rm $FILE
       exit 0
   fi
fi

exit 0
