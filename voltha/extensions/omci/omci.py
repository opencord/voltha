import inspect
import sys
from enum import Enum
# from scapy.all import StrFixedLenField, ByteField, ShortField, ConditionalField, \
#     PacketField, PadField, IntField, Field, Packet
from scapy.fields import ByteField, Field, ShortField, PacketField, PadField, \
    ConditionalField
from scapy.fields import StrFixedLenField, IntField
from scapy.packet import Packet


def bitpos_from_mask(mask, lsb_pos=0, increment=1):
    """
    Turn a decimal value (bitmask) into a list of indices where each
    index value corresponds to the bit position of a bit that was set (1)
    in the mask. What numbers are assigned to the bit positions is controlled
    by lsb_pos and increment, as explained below.
    :param mask: a decimal value used as a bit mask
    :param lsb_pos: The decimal value associated with the LSB bit
    :param increment: If this is +i, then the bit next to LSB will take
    the decimal value of lsb_pos + i.
    :return: List of bit positions where the bit was set in mask
    """
    out = []
    while mask:
        if mask & 0x01:
            out.append(lsb_pos)
        lsb_pos += increment
        mask >>= 1
    return sorted(out)


class AttributeAccess(Enum):
    Readable = 1
    R = 1
    Writable = 2
    W = 2
    SetByCreate = 3
    SBC = 3


class EntityOperations(Enum):
    Get = 1  # TODO adjust encoding to match msg_type field
    Set = 2
    Create = 3
    Delete = 4
    Reboot = 10
    Test = 11


class EntityClassAttribute:

    def __init__(self, fld, access=set(), optional=False):
        self._fld = fld
        self._access = access
        self._optional = optional

class EntityClass:
    class_id = 'to be filled by subclass'
    attributes = []
    mandatory_operations = {}
    optional_operations = {}

    # will be map of attr_name -> index in attributes
    attribute_name_to_index_map = None

    def __init__(self, **kw):

        assert(isinstance(kw, dict))

        # verify that all keys provided are valid in the entity
        if self.attribute_name_to_index_map is None:
            self.__class__.attribute_name_to_index_map = dict(
                (a._fld.name, idx) for idx, a in enumerate(self.attributes))

        for k, v in kw.iteritems():
            assert(k in self.attribute_name_to_index_map)

        self._data = kw

    def serialize(self, mask=None, operation=None):
        bytes = ''

        # generate ordered list of attribute indices needed to be processed
        # if mask is provided, we use that explicitly
        # if mask is not provided, we determine attributes from the self._data content
        # also taking into account the type of operation in hand
        if mask is not None:
            attribute_indices = EntityClass.attribute_indices_from_mask(mask)
            print attribute_indices
        else:
            attribute_indices = self.attribute_indices_from_data()

        # Serialize each indexed field (ignoring entity id)
        for index in attribute_indices:
            field = self.attributes[index]._fld
            bytes = field.addfield(None, bytes, self._data[field.name])

        return bytes

    def attribute_indices_from_data(self):
        return sorted(
            self.attribute_name_to_index_map[attr_name]
            for attr_name in self._data.iterkeys())

    byte1_mask_to_attr_indices = dict(
        (m, bitpos_from_mask(m, 8, -1)) for m in range(256))
    byte2_mask_to_attr_indices = dict(
        (m, bitpos_from_mask(m, 16, -1)) for m in range(256))
    @classmethod
    def attribute_indices_from_mask(cls, mask):
        # each bit in the 2-byte field denote an attribute index; we use a
        # lookup table to make lookup a bit faster
        return \
            cls.byte1_mask_to_attr_indices[(mask >> 8) & 0xff] + \
            cls.byte2_mask_to_attr_indices[(mask & 0xff)]


# abbreviations
ECA = EntityClassAttribute
AA = AttributeAccess
OP = EntityOperations


class CirtcuitPackEntity(EntityClass):
    class_id = 6
    attributes = [
        ECA(StrFixedLenField("managed_entity_id", None, 22), {AA.R, AA.SBC}),
        ECA(ByteField("type", None), {AA.R, AA.SBC}),
        ECA(ByteField("number_of_ports", None), {AA.R}, optional=True),
        ECA(StrFixedLenField("serial_number", None, 8), {AA.R}),
        ECA(StrFixedLenField("version", None, 14), {AA.R}),
        ECA(StrFixedLenField("vendor_id", None, 4), {AA.R}),
        ECA(ByteField("administrative_state", None), {AA.R, AA.W, AA.SBC}),
        ECA(ByteField("operational_state", None), {AA.R}, optional=True),
        ECA(ByteField("bridged_or_ip_ind", None), {AA.R, AA.W}, optional=True),
        ECA(StrFixedLenField("equipment_id", None, 20), {AA.R}, optional=True),
        ECA(ByteField("card_configuration", None), {AA.R, AA.W, AA.SBC}), # not really mandatory, see spec
        ECA(ByteField("total_tcont_buffer_number", None), {AA.R}),
        ECA(ByteField("total_priority_queue_number", None), {AA.R}),
        ECA(ByteField("total_traffic_scheduler_number", None), {AA.R}),
        ECA(IntField("power_sched_override", None), {AA.R, AA.W}, optional=True)
    ]
    mandatory_operations = {OP.Get, OP.Set, OP.Reboot}
    optional_operations = {OP.Create, OP.Delete, OP.Test}


# entity class lookup table from entity_class values
entity_classes_name_map = dict(
    inspect.getmembers(sys.modules[__name__],
    lambda o: inspect.isclass(o) and \
              issubclass(o, EntityClass) and \
              o is not EntityClass)
)

entity_classes = [c for c in entity_classes_name_map.itervalues()]
entity_id_to_class_map = dict((c.class_id, c) for c in entity_classes)


class OMCIData(Field):

    __slots__ = Field.__slots__ + ['_entity_class', '_attributes_mask']

    def __init__(self, name, entity_class="entity_class",
                 attributes_mask="attributes_mask"):
        Field.__init__(self, name=name, default=None, fmt='s')
        self._entity_class = entity_class
        self._attributes_mask = attributes_mask

    def i2m(self, pkt, x):
        class_id = getattr(pkt, self._entity_class)
        attribute_mask = getattr(pkt, self._attributes_mask)
        entity_class = entity_id_to_class_map.get(class_id)
        return entity_class(**x).serialize(attribute_mask)


class OMCIMessage(Packet):
    name = "OMCIMessage"
    fields_desc = []


class OMCIGetRequest(OMCIMessage):
    name = "OMCIGetRequest"
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ShortField("attributes_mask", None)
    ]


class OMCIGetResponse(OMCIMessage):
    name = "OMCIGetResponse"
    fields_desc = [
        ShortField("entity_class", None),
        ShortField("entity_id", 0),
        ByteField("success_code", 0),
        ShortField("attributes_mask", None),
        OMCIData("data", entity_class="entity_class",
                 attributes_mask="attributes_mask")
    ]


class OMCIFrame(Packet):
    name = "OMCIFrame"
    fields_desc = [
        ShortField("transaction_id", 0),
        ByteField("message_type", None),
        ByteField("omci", 0x0a),
        ConditionalField(PadField(PacketField("omci_message", None,
                                              OMCIGetRequest), align=36),
                         lambda pkt: pkt.message_type == 0x49),
        ConditionalField(PadField(PacketField("omci_message", None,
                                              OMCIGetResponse), align=36),
                         lambda pkt: pkt.message_type == 0x29),
        # TODO add additional message types here as padded conditionals...
        IntField("omci_trailer", 0x00000028)
    ]
