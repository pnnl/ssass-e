#!/usr/bin/env bash
# Main script to SSASSE in local box

FILE="$HOME/SSASSE_PID"
if [ -f $FILE ]; then
   pid=`cat $FILE`
   if ps -p $pid > /dev/null 2>&1
   then
       echo "SSASSE with process id $pid is already running"
       exit 1
   else
       echo "PID file exists but process is not running. Removing old
       SSASSE_PID file"
       rm $FILE
   fi
fi

echo "Starting SSASSE in background"
#cd ~/git/testing/evidencecollection/
#cd /home/centos/git/shwetha/zeek_scripts_testing/evidencecollection
python3.6 setup.py
python3.6 -m ssasse_platform > ssasse.log 2>&1 &
disown

echo "Waiting for SSASSE to startup.."
count=0
while [ ! -f $FILE ] && [ $count -lt 60 ]
do
  sleep 1
  ((++count))
done

if [ -f $FILE ]; then
 echo "SSASSE startup complete"
 echo "$(date +%s)" > timeStart
 exit 0
else
 echo "SSASSE startup failed/timed out. Please check ssasse.log for details"
 exit 2
fi
