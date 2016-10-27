from consul.twisted import Consul
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import returnValue

from common.utils.dockerhelpers import create_container_network, start_container, create_host_config

containers = {
    'chameleon' : {
                    'image' : 'cord/chameleon',
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
                    'links' : { "consul" : "consul", "fluentd" : "fluentd" },
                    'environment' : ["SERVICE_8881_NAME=chamleon-rest"],
                    'volumes' : { '/var/run/docker.sock' :  '/tmp/docker.sock' }
                  }
}

class ConsulManager(object):

    log = get_logger()

    def __init__(self, arg):
        self.log.info('Initializing consul manager')
        self.running = False
        self.index = 0
        (host, port) = arg.split(':')
        self.conn = Consul(host=host, port=port)

    def run(self):
        if self.running:
            return
        self.running = True

        self.log.info('Running consul manager')

        reactor.callLater(0, self.provision_voltha_instances, None)

        reactor.addSystemEventTrigger('before', 'shutdown', self.shutdown)
        returnValue(self)


    def shutdown(self):
        self.log.info('Shutting down consul manager')
        self.running = False


    def provision_voltha_instances(self, _):
        if not self.running:
            return
        # maintain index such that callbacks only happen is something has changed
        # timeout is default to 5m
        deferred = self.conn.catalog.service(wait='5s', service='voltha-grpc',
                                                            index=self.index)
        deferred.addCallbacks(self.provision, self.fail)
        deferred.addBoth(self.provision_voltha_instances)

    def provision(self, result):
        (self.index, data) = result
        self.log.info('PROVISIONING {}'.format(data))
        for item in data:
            (service, id) = item['ServiceID'].split(':')[1].split('_')[1:3]
            self.log.info('got {} {}'.format(service, id))
            self.podProvisioned(service, id, item['ServiceTags'])

    def fail(self, err):
        self.log.info('Failure %s'.format(err))

    def start_containers(self, result, service, id, tags):
        self.log.info("wtf : {}".format(result))
        (_, done) = result
        self.log.info("result : {}, {}".format(done, type(done)))
        if done:
            return
        self.log.info('provisioning voltha instance {}, with tags {}'.format(id, tags))
        for tag in tags:
            if tag in containers:
                netcfg = self.create_network(id, tag)
                if self.create_container(id, tag, netcfg):
                    self.markProvisioned(service, id)


    def create_network(self, id, tag):
        return create_container_network('podder_%s_%s' % (tag, id),
                                        containers[tag]['links'])

    def create_container(self, id, tag, netcfg):
        args = {}
        args['image'] = containers[tag]['image']
        args['networking_config'] = netcfg
        args['command'] = containers[tag]['command']
        args['ports'] = containers[tag]['ports']
        args['environment'] = containers[tag]['environment']
        args['volumes'] = containers[tag]['volumes'].keys()
        args['host_config'] = create_host_config(containers[tag]['volumes'],
                                                 containers[tag]['ports'])
        args['name'] = 'podder_%s_%s' % (tag, id)
        start_container(args)
        #TODO check container is running

        return True

    def podProvisioned(self, service, id, tags):
        d = self.conn.kv.get('podder/%s/%s/state' % (service, id))
        d.addCallback(self.start_containers, service, id, tags)
        d.addErrback(lambda err: self.log.info("FAIL {}".format(err)))

    def markProvisioned(self, service, id):
        self.conn.kv.put('podder/%s/%s/state' % (service, id), "started")
