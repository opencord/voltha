import consul
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, Deferred, returnValue

from common.utils.dockerhelpers import create_container_network, start_container

containers = {
    'chameleon' : {
                    'image' : 'opencord/chameleon',
                    'command' : [ "/chameleon/main.py",
                                    "-v",
                                    "--consul=consul:8500",
                                    "--fluentd=fluentd:24224",
                                    "--rest-port=8881",
                                    "--grpc-endpoint=@voltha-grpc",
                                    "--instance-id-is-container-name",
                                    "-v"],
                    'ports' : [ 8881 ],
                    'depends_on' : [ "consul", "voltha" ],
                    'links' : [ "consul", "fluentd" ],
                    'environment' : ["SERVICE_8881_NAME=chamleon-rest"],
                    'volumes' : '/var/run/docker.sock:/tmp/docker.sock'
                  }
}

class ConsulManager(object):

    log = get_logger()

    def __init__(self, arg):
        self.log.info('Initializing consul manager')
        self.running = False
        self.index = 0
        (host, port) = arg.split(':')
        self.conn = consul.Consul(host=host, port=port)

    @inlineCallbacks
    def run(self):
        if self.running:
            return
        self.running = True

        self.log.info('Running consul manager')

        reactor.callLater(0, self.provision_voltha_instances())

        reactor.addSystemEventTrigger('before', 'shutdown', self.shutdown)
        returnValue(self)

    @inlineCallbacks
    def shutdown(self):
        self.log.info('Shutting down consul manager')
        self.running = False

    @inlineCallbacks
    def provision_voltha_instances(self):
        while True:
            if not self.running:
                return
            # maintain index such that callbacks only happen is something has changed
            # timeout is default to 5m
            (self.index, data) = self.conn.catalog.service(service='voltha-grpc',
                                                            index=self.index)
            self.start_containers(data)

    def start_containers(self, data):
        for item in data:
            serviceId = item['ServiceID'].split(':')[1].split('_')[2]
            serviceTags = item['ServiceTags']
            self.log.info('voltha instance %s, with tags %s' % (serviceId, serviceTags))
            for tag in serviceTags:
                if tag in containers:
                    netcfg = self.create_network(serviceId, tag)
                    self.create_container(serviceId, tag, netcfg)


    def create_network(self, id, tag):
        return create_container_network('podder_%s_%s' % (tag, id),
                                        containers[tag]['links'])

    def create_container(self, id, tag, netcfg):
        args = {}
        args['image'] = containers['image']
        args['networking_config'] = netcfg
        args['command'] = containers['command']
        args['ports'] = containers['ports']
        args['environment'] = containers['environment']
        args['volumes'] = containers['volumes']
        start_container(args)