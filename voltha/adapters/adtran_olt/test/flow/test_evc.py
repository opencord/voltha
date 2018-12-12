from collections import namedtuple
import pytest_twisted
from voltha.adapters.adtran_olt.flow.evc import EVC
from mock import MagicMock
from twisted.internet import reactor, defer


def test_evc_create():
    Flow = namedtuple('Flow', 'flow_id')
    flow = Flow(1)
    evc = EVC(flow)
    assert str(evc) == "EVC-VOLTHA-1: MEN: [], S-Tag: None"


@pytest_twisted.inlineCallbacks
def test_evc_do_simple_install():
    flow = MagicMock()
    flow.flow_id = 1
    flow.vlan_id = 2
    flow.handler.get_port_name = lambda _: 'nni'
    evc = EVC(flow)

    # TEST Pre-Conditions
    assert flow.handler.netconf_client.edit_config.call_args is None
    assert not evc.installed

    d = evc._do_install()

    def callback(result):
        assert result is True

        xml = """
<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs">
<evc>
<name>VOLTHA-1</name>
<enabled>true</enabled>
<stag>2</stag>
<stag-tpid>33024</stag-tpid>
<men-ports>nni</men-ports>
</evc>
</evcs>""".replace('\n', '')
        flow.handler.netconf_client.edit_config.assert_called_with(xml)
        assert evc.installed
    d.addCallback(callback)
    yield d


@pytest_twisted.inlineCallbacks
def test_evc_do_remove():
    def get_evc_response():
        d = defer.Deferred()
        Reply = namedtuple('Reply', ['ok', 'data_xml'])
        reactor.callLater(0.1, d.callback, Reply(True, '<data><evcs>'
                                                       '<evc><name>VOLTHA-1</name></evc>'
                                                       '<evc><name>VOLTHA-2</name></evc>'
                                                       '</evcs></data>'))
        return d

    client = MagicMock()
    client.get.return_value = get_evc_response()
    d = EVC.remove_all(client)
    def callback(result):
        assert result is None
        get_xml = (
            '''<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'''
            '''<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs"><evc><name/></evc></evcs>'''
            '''</filter>'''
        ).replace('\n', '')
        delete_xml = (
            '''<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs" xc:operation="delete">'''
            '''<evc><name>VOLTHA-1</name></evc>'''
            '''<evc><name>VOLTHA-2</name></evc></evcs>'''
        ).replace('\n', '')
        client.get.assert_called_with(get_xml)
        client.edit_config.assert_called_with(delete_xml)
    d.addCallback(callback)
    yield d
