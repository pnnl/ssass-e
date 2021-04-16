# -*- coding: utf-8 -*- {{{
# vim: set fenc=utf-8 ft=python sw=4 ts=4 sts=4 et:
#
#       Copyright (2021) Battelle Memorial Institute
#                      All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# }}}

import pika
import logging
import json
import gevent
import gevent.monkey
import ssl

gevent.monkey.patch_all()
_log = logging.getLogger(__name__)
# reduce pika log level
logging.getLogger("pika").setLevel(logging.WARNING)


class RabbitMqConnection(object):
    def __init__(self, host, port, certificates, role='collector'):
        _log.debug("In RabbitMQConnection")
        self._connection = None
        #self.build_connection_param(ssl_auth=True)
        #self._connection_param = pika.ConnectionParameters(
        #            host=host,
        #            port=port,
        #            virtual_host='ssasse',
        #            heartbeat=30,
        #            credentials=pika.credentials.PlainCredentials(role, role))
        self.role = role
        self.channel = None
        self._connection_callback = None
        self._error_callback = None
        self._subscriptions = {}
        self.exchange = 'ssasse' # Assumption is that exchange is created
        self.host = host
        self.port = port
        self.ssl_port = 5671
        self.virtual_host = 'ssasse'
        self.role = role
        self.certificates = certificates
        self.build_connection_param(ssl_auth=True)

    def open_connection(self):
        if self.role == "async":
            _log.debug("Im here")
        self._connection = pika.GeventConnection(self._connection_param,
                                                 on_open_callback=self.on_connection_open,
                                                 on_open_error_callback=self.on_open_error,
                                                 on_close_callback=self.on_connection_closed
                                                 )

    def connect(self, connection_callback=None, error_callback=None, thread_id=0):
        self._connection_callback = connection_callback
        self._error_callback = error_callback
        self.open_connection()

    def on_connection_open(self, unused_connection):
        if self._connection is None:
            self._connection = unused_connection
        # Open a channel
        self._connection.channel(self.on_channel_open)

    def on_open_error(self, _connection_unused, error_message=None):
        # Do something
        _log.error("Cannot open connection RabbitMQ broker")

    def on_connection_closed(self, connection, reply_code, reply_text):
        _log.error("Connection to RabbitMQ broker closed unexpectedly")

    def on_channel_open(self, channel):
        self.channel = channel
        _log.debug("channel open")
        if self._connection_callback:
            self._connection_callback()

    def create_queue(self, prefix=None, queue_name=None, callback=None):
        _log.debug("prefix: {}, queue_name:{}, callback: {}".format(prefix, queue_name, callback))
        
        def rmq_callback(ch, method, properties, body):
            topic = str(method.routing_key)
            msg = json.loads(body)
            gevent.spawn(callback, topic, msg)

        if self.channel:
            self.channel.queue_declare(queue=queue_name,
                                       durable=False,
                                       exclusive=True,
                                       auto_delete=False,
                                       callback=None)
            self.channel.queue_bind(exchange=self.exchange,
                                    queue=queue_name,
                                    routing_key=prefix,
                                    callback=None)
            self.channel.basic_consume(rmq_callback,
                                       queue=queue_name,
                                       no_ack=True)

    def send_message(self, key, message):
        #_log.debug("rmq send_message:{}, {}".format(key, message))
        dct = {'content_type': 'application/json'}
        properties = pika.BasicProperties(**dct)
        
        try:
            self.channel.basic_publish(self.exchange,
                                       key,
                                       json.dumps(message, ensure_ascii=False),
                                       properties)
        except (pika.exceptions.AMQPConnectionError,
                pika.exceptions.AMQPChannelError) as exc:
            _log.error("Error sending message {}".format(exc))

        except OSError as oe:
            _log.error("Error potentially adapter disconnect error".format(oe))

    def disconnect(self):
        try:
            if self.channel and self.channel.is_open:
                self.channel.basic_cancel(self.on_cancel_ok, self._consumer_tag)
        except (pika.exceptions.ConnectionClosed, pika.exceptions.ChannelClosed) as exc:
            _log.error("Connection to RabbitMQ broker or Channel is already closed.")
            self._connection.ioloop.stop()

    def on_cancel_ok(self):
        self.channel.close()
        self._connection.close()
    
    def build_connection_param(self, ssl_auth=None, retry_attempt=30, retry_delay=2):
        """
        Build Pika Connection parameters
        :param rmq_user: RabbitMQ user
        :param ssl_auth: If SSL based connection or not
        :return:
        """
        #crt = self.rmq_config.crts
        heartbeat_interval = 20 #sec
        try:
            private_key_file = self.certificates['private-key']
            ca_cert_file =  self.certificates['ca-file']
            public_cert_file = self.certificates['public-cert']
        except KeyError as e:
            raise(e)
       
        try:
            if ssl_auth:
                _log.debug("ssl connection")
                ssl_options = dict(
                    ssl_version=ssl.PROTOCOL_TLSv1,
                    ca_certs=ca_cert_file,
                    keyfile=private_key_file,
                    certfile=public_cert_file,
                    cert_reqs=ssl.CERT_REQUIRED)
                self._connection_param = pika.ConnectionParameters(
                    host=self.host,
                    port=self.ssl_port,
                    virtual_host=self.virtual_host,
                    connection_attempts=retry_attempt,
                    retry_delay=retry_delay,
                    heartbeat=heartbeat_interval,
                    ssl=True,
                    ssl_options=ssl_options,
                    credentials=pika.credentials.ExternalCredentials())
            else:
                self._connection_param = pika.ConnectionParameters(
                    host=self.host,
                    port=self.port,
                    virtual_host=self.virtual_host,
                    heartbeat=30,
                    credentials=pika.credentials.PlainCredentials(self.role, self.role))
        except KeyError as e:
           raise(e)

    def close_connection(self):
        if self.channel and self.channel.is_open:
            self.channel.close()
            self._connection.close()
