from ..net.adtran_netconf import adtran_module_url
from twisted.internet.defer import inlineCallbacks, returnValue
import xmltodict
import structlog

log = structlog.get_logger()

_phys_entities_rpc = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <physical-entities-state xmlns="{}">
        <physical-entity/>
      </physical-entities-state>
    </filter>
    """.format(adtran_module_url('adtran-physical-entities'))


class PhysicalEntitiesState(object):
    def __init__(self, session):
        self._session = session
        self._rpc_reply = None

    @inlineCallbacks
    def get_state(self):
        self._rpc_reply =  None
        request = self._session.get(_phys_entities_rpc)
        self._rpc_reply = yield request
        returnValue(self._rpc_reply)

    @property
    def physical_entities(self):
        """
        :return: (list) of OrderDict physical entities
        """
        if self._rpc_reply is None:
            # TODO: Support auto-get?
            return None

        result_dict = xmltodict.parse(self._rpc_reply.data_xml)
        return result_dict['data']['physical-entities-state']['physical-entity']

    def get_physical_entities(self, classification=None):
        """
        Get the physical entities of a particular type
        :param classification: (String or List) The classification or general hardware type of the
                                                component identified by this physical entity
                                                (case-insensitive)
        :return: (list) of OrderDict physical entities
        """
        entries = self.physical_entities

        if classification is None:
            return entries

        # for entry in entries:
        #     import pprint
        #     log.info(pprint.PrettyPrinter(indent=2).pformat(entry))

        def _matches(entry, value):
            if 'classification' in entry and '#text' in entry['classification']:
                text_val = entry['classification']['#text'].lower()
                if isinstance(value, list):
                    return any(v.lower() in text_val for v in value)
                return value.lower() in text_val
            return False

        return [entry for entry in entries if _matches(entry, classification)]
