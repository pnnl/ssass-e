#!/usr/bin/env bash

if [ "$#" -ne 5 ]; then
  echo "Insufficient number of parameters.
Command Usage:
./ssasse_platform/scripts/utils/install_rabbit.sh <debian or centos> <distribution name or centos version> <Path to CA certificate> <Path to server public cert> <Path to server private key>
Valid Debian distributions: ( bionic  artful stretch buster trusty xenial )
Valid centos versions: 6, 7, 8
"
 exit 0
fi

# Expect 5 input parameters
OS_NAME="$1"
DIST="$2"
CA_PATH="$3"
SERVER_PUBLIC_CERT_PATH="$4"
SERVER_PRIVATE_KEY_PATH="$5"

# Install RabbitMQ dependencies
echo "###########Installing RabbitMQ dependencies###########"
sudo ./ssasse_platform/scripts/utils/rabbit_dependencies.sh $OS_NAME $DIST
if [[ "$?" == "0" ]]; then
  # Install RabbitMQ server
  echo "###########Installing RabbitMQ Server###########"
  ./ssasse_platform/scripts/utils/install_rabbitmq.sh
  if [[ "$?" == "0" ]]; then
    sleep 30
    # Check if RabbitMQ is installed properly. Start the server.
      echo "###########Starting RabbitMQ Server"
    ~/rabbitmq-server/rabbitmq_server-3.7.7/sbin/rabbitmq-server -detached
    if [[ "$?" == "0" ]]; then
      # Configure RabbitMQ for SSASSE
      echo "###########Configure RabbitMQ for SSASSE###########"
      python3 ./ssasse_platform/scripts/utils/create_exchange.py
      # Configure RabbitMQ server with the server SSL certificate and restart.
      echo "listeners.tcp.default = 5672
management.listener.port = 15672
listeners.ssl.default = 5671
ssl_options.cacertfile = ${CA_PATH}
ssl_options.certfile = ${SERVER_PUBLIC_CERT_PATH}
ssl_options.keyfile = ${SERVER_PRIVATE_KEY_PATH}
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = true
auth_mechanisms.1 = EXTERNAL
ssl_cert_login_from = common_name
ssl_options.versions.1 = tlsv1.2
ssl_options.versions.2 = tlsv1.1
ssl_options.versions.3 = tlsv1

management.listener.port = 15671
management.listener.ssl = true" > ~/rabbitmq-server/rabbitmq_server-3.7.7/etc/rabbitmq/rabbitmq.conf
      echo "###########Restarting RabbitMQ to use SSL certs###########"
      # Restart RabbitMQ so that it starts using SSL based authentication
      ~/rabbitmq-server/rabbitmq_server-3.7.7/sbin/rabbitmqctl stop
      sleep 5
      ~/rabbitmq-server/rabbitmq_server-3.7.7/sbin/rabbitmq-server -detached
      if [[ "$?" == "0" ]]; then
        echo "###########RabbitMQ server started with SSL certs###########"
        sleep 5
      else
        echo "Unable to start RabbitMQ server after configuring RabbitMQ conf with SSL certs"
      fi

    else
      echo "Unable to start RabbitMQ server. Exiting.."
    fi
  else
    echo "Problem installing RabbitMQ server. Exiting.."
  fi
else
  echo "Problem installing RabbitMQ dependencies. Exiting.."
fi







