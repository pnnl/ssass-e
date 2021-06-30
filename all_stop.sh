#!/bin/bash
# This script is called from Web server to stop SSASSE in individual sensor boxes

#Kill Local Inference Engine inference-2
sleep 2
ssh -i /home/ubuntu/.ssh/ssass-e.pem -o StrictHostKeyChecking=no ubuntu@inference-2 "cd ~/git/ssass-e; sh kill_ssasse.sh"

#Kill Active Scanner on ssasse
ssh -i /home/ubuntu/.ssh/ssass-e.pem -o StrictHostKeyChecking=no centos@ssasse "cd ~/git/ssass-e; sh kill_ssasse.sh;"

#Kill Active Scanner on nnm-gti
ssh -i /home/ubuntu/.ssh/ssass-e.pem -o StrictHostKeyChecking=no centos@nnm-gti "cd ~/git/ssass-e; sh kill_ssasse.sh;"

