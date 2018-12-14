from voltha.adapters.adtran_olt.codec.ietf_interfaces import IetfInterfacesConfig
from mock import MagicMock
from pytest_twisted import inlineCallbacks
from xmltodict import parse


def test_create():
    IetfInterfacesConfig(None)

@inlineCallbacks
def test_get_config():
    session = MagicMock()
    ifc = IetfInterfacesConfig(session)
    session.get.return_value = 'test value'
    cfg = yield ifc.get_config()
    assert 'test value' == cfg
    filter = '\n    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n      <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">\n        <interface/>\n      </interfaces>\n    </filter>\n'
    session.get.assert_called_once_with('running',filter=filter)
    parse(filter)