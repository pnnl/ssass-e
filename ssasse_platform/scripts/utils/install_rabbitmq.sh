#!/usr/bin/env bash

RMQ_ROOT=$HOME/rabbitmq-server
mkdir $RMQ_ROOT
wget -P $HOME https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.7.7/rabbitmq-server-generic-unix-3.7.7.tar.xz
tar -xf $HOME/rabbitmq-server-generic-unix-3.7.7.tar.xz --directory $RMQ_ROOT
$RMQ_ROOT/rabbitmq_server-3.7.7/sbin/rabbitmq-plugins enable rabbitmq_management rabbitmq_auth_mechanism_ssl

#echo "installing pika with gevent adapter"
#$prefix which pip
#if [ $? -eq 0 ]; then
#    pip3 install gevent-pika --user
#else
#    pip3 install gevent-pika --user
#fi

