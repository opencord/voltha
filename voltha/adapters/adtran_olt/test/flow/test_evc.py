from collections import namedtuple
import pytest_twisted
import pytest
from voltha.adapters.adtran_olt.flow.evc import EVC
from mock import MagicMock
from twisted.internet import reactor, defer


@pytest.fixture()
def flow():
    Flow = namedtuple('Flow', 'flow_id')
    return Flow(1)

@pytest.fixture()
def vanilla_evc(flow):
    return EVC(flow)


def test_evc_repr(vanilla_evc):
    assert str(vanilla_evc) == "EVC-VOLTHA-1: MEN: [], S-Tag: None"


@pytest.mark.parametrize('falsey', (
    [], {}, False, 0, None
))
def test_set_installed(falsey, vanilla_evc):
    with pytest.raises(AssertionError):
        vanilla_evc.installed = 'abc'
    vanilla_evc.installed = falsey
    assert vanilla_evc.installed is False


def test_switch_method_prop(vanilla_evc):
    assert None is vanilla_evc.switching_method


def test_men_2_uni_manip_prop(vanilla_evc):
    assert None is vanilla_evc.men_to_uni_tag_manipulation


def test_flow_prop(vanilla_evc, flow):
    assert flow is vanilla_evc.flow_entry
    vanilla_evc.flow_entry = 'New Value'
    assert 'New Value' == vanilla_evc.flow_entry


@pytest.mark.parametrize('value, expected', [
    (None, '<single-tag-switched/>'),
    (EVC.SwitchingMethod.SINGLE_TAGGED, '<single-tag-switched/>'),
    (EVC.SwitchingMethod.DOUBLE_TAGGED, '<double-tag-switched/>'),
    (EVC.SwitchingMethod.MAC_SWITCHED, '<mac-switched/>'),
    (EVC.SwitchingMethod.DOUBLE_TAGGED_MAC_SWITCHED, '<double-tag-mac-switched/>'),
    ('invalid', ValueError)
])
def test_evc_switching_method_xml(value, expected):
    if isinstance(expected, str):
        assert EVC.SwitchingMethod.xml(value) == expected
    else:
        with pytest.raises(expected):
            EVC.SwitchingMethod.xml(value)


@pytest.mark.parametrize('value, expected', [
    (None, '<symmetric/>'),
    (EVC.Men2UniManipulation.SYMMETRIC, '<symmetric/>'),
    (EVC.Men2UniManipulation.POP_OUT_TAG_ONLY, '<pop-outer-tag-only/>'),
    ('invalid', ValueError)
])
def test_evc_men_2_uni_manip(value, expected):
    if isinstance(expected, str):
        xml = '<men-to-uni-tag-manipulation>%s</men-to-uni-tag-manipulation>' % expected
        assert EVC.Men2UniManipulation.xml(value) == xml
    else:
        with pytest.raises(expected):
            EVC.Men2UniManipulation.xml(value)


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
        assert evc.installed

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
    d.addCallback(callback)
    yield d


@pytest.mark.parametrize('evcs', [
    ['VOLTHA-1'], ['VOLTHA-1', 'VOLTHA-2']
])
@pytest_twisted.inlineCallbacks
def test_evc_do_remove(evcs):
    def get_evc_response():
        d = defer.Deferred()
        Reply = namedtuple('Reply', ['ok', 'data_xml'])
        reactor.callLater(0.1, d.callback, Reply(True, (
            '<data><evcs>' +
            ''.join(('<evc><name>%s</name></evc>' % n) for n in evcs) +
            '</evcs></data>')))
        return d

    client = MagicMock()
    client.get.return_value = get_evc_response()
    result = yield EVC.remove_all(client)

    assert result is None
    get_xml = (
        '''<filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'''
        '''<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs"><evc><name/></evc></evcs>'''
        '''</filter>'''
    ).replace('\n', '')
    delete_xml = (
        '''<evcs xmlns="http://www.adtran.com/ns/yang/adtran-evcs" xc:operation="delete">''' +
        ''.join(('''<evc><name>%s</name></evc>''' % n) for n in evcs) +
        '''</evcs>'''
    ).replace('\n', '')
    client.get.assert_called_with(get_xml)
    client.edit_config.assert_called_with(delete_xml)
