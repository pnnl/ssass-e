#!/usr/bin/env bash
# Main script to stop SSASSE in local box

FILE="$HOME/SSASSE_PID"
if [ -f $FILE ]; then
   pid=`cat $FILE`
   if ps -p $pid > /dev/null 2>&1
   then
       echo "SSASSE with process id $pid is running. Killing the process and removing SSASSE_PID file"
       sudo kill -9 $pid
       rm $FILE
       exit 1
   else
       echo "PID file exists but process is not running. Removing old
       SSASSE_PID file"
       rm $FILE
   fi
fi
pkill -f ssasse_platform
