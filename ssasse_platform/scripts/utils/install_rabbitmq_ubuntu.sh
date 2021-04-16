user=`whoami`
if [ $user == 'root' ]; then
    prefix=""
else
    prefix="sudo"
fi

# DIST=$1
# echo "installing ERLANG"
# $prefix apt-get install apt-transport-https libwxbase3.0-0v5 libwxgtk3.0-0v5 libsctp1  build-essential python-dev openssl libssl-dev libevent-dev git
# $prefix apt-get purge -yf erlang*

# wget -O - 'https://dl.bintray.com/rabbitmq/Keys/rabbitmq-release-signing-key.asc' | $prefix apt-key add -

# if [ ! -f "/etc/apt/sources.list.d/bintray.erlang.list" ]; then
#     echo "deb https://dl.bintray.com/rabbitmq/debian $DIST erlang-21.x"|$prefix tee --append /etc/apt/sources.list.d/bintray.erlang.list
# fi
# $prefix apt-get update
# $prefix apt-get install -yf
# $prefix apt-get install -y erlang-base erlang-diameter erlang-eldap erlang-ssl erlang-crypto erlang-asn1 erlang-public-key
# $prefix apt-get install -y erlang-nox

RMQ_ROOT=$HOME/rabbitmq-server
mkdir $RMQ_ROOT
wget -P $HOME https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.7.7/rabbitmq-server-generic-unix-3.7.7.tar.xz
tar -xf $HOME/rabbitmq-server-generic-unix-3.7.7.tar.xz --directory $RMQ_ROOT
$RMQ_ROOT/rabbitmq_server-3.7.7/sbin/rabbitmq-plugins enable rabbitmq_management

echo "installing pika with gevent adapter"
$prefix which pip
if [ $? -eq 0 ]; then
    pip install gevent-pika --user
else
    sudo apt install python-pip
    pip install gevent-pika --user
fi

