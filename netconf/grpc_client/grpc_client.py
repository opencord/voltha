#
# Copyright 2017 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
gRPC client meant to connect to a gRPC server endpoint, and query the
end-point's schema by calling SchemaService.Schema(Empty) and all of its
semantics are derived from the recovered schema.
"""

import os
import sys
from zlib import decompress

import grpc
from grpc._channel import _Rendezvous
from structlog import get_logger
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from werkzeug.exceptions import ServiceUnavailable

from common.utils.asleep import asleep
from netconf.protos import third_party
from netconf.protos.schema_pb2_grpc import SchemaServiceStub
from google.protobuf.empty_pb2 import Empty
from common.utils.consulhelpers import get_endpoint_from_consul
# from netconf.protos.voltha_pb2 import VolthaLocalServiceStub, \
#     VolthaGlobalServiceStub
# from google.protobuf import empty_pb2
# from google.protobuf.json_format import MessageToDict, ParseDict
from nc_rpc_mapper import get_nc_rpc_mapper_instance
from google.protobuf import descriptor
import base64
import math
import collections
from netconf.constants import Constants as C

_INT64_TYPES = frozenset([descriptor.FieldDescriptor.CPPTYPE_INT64,
                          descriptor.FieldDescriptor.CPPTYPE_UINT64])
_FLOAT_TYPES = frozenset([descriptor.FieldDescriptor.CPPTYPE_FLOAT,
                          descriptor.FieldDescriptor.CPPTYPE_DOUBLE])
_INFINITY = 'Infinity'
_NEG_INFINITY = '-Infinity'
_NAN = 'NaN'

log = get_logger()


class GrpcClient(object):
    """
    Connect to a gRPC server, fetch its schema, and process the downloaded
    proto schema files.  The goal is to convert the proto schemas into yang
    schemas which would be exposed to the Netconf client.
    """
    RETRY_BACKOFF = [0.05, 0.1, 0.2, 0.5, 1, 2, 5]

    def __init__(self, consul_endpoint, work_dir,
                 grpc_endpoint='localhost:50055',
                 reconnect_callback=None,
                 on_start_callback=None):
        self.consul_endpoint = consul_endpoint
        self.grpc_endpoint = grpc_endpoint
        self.work_dir = work_dir
        self.reconnect_callback = reconnect_callback
        self.on_start_callback = on_start_callback

        self.plugin_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../protoc_plugins'))

        self.yang_schemas = set()

        self.channel = None
        self.local_stub = None
        self.schema = None
        self.retries = 0
        self.shutting_down = False
        self.connected = False

    def start(self):
        log.debug('starting')
        if not self.connected:
            reactor.callLater(0, self.connect)
        log.info('started')
        return self

    def stop(self):
        log.debug('stopping')
        if self.shutting_down:
            return
        self.shutting_down = True
        log.info('stopped')

    def set_on_start_callback(self, on_start_callback):
        self.on_start_callback = on_start_callback
        return self

    def set_reconnect_callback(self, reconnect_callback):
        self.reconnect_callback = reconnect_callback
        return self

    def resolve_endpoint(self, endpoint):
        ip_port_endpoint = endpoint
        if endpoint.startswith('@'):
            try:
                ip_port_endpoint = get_endpoint_from_consul(
                    self.consul_endpoint, endpoint[1:])
                log.info('endpoint-found',
                         endpoint=endpoint, ip_port=ip_port_endpoint)
            except Exception as e:
                log.error('service-not-found-in-consul', endpoint=endpoint,
                          exception=repr(e))
                return None, None
        if ip_port_endpoint:
            host, port = ip_port_endpoint.split(':', 2)
            return host, int(port)

    @inlineCallbacks
    def connect(self):
        """
        (Re-)Connect to end-point
        """
        if self.shutting_down or self.connected:
            return

        try:
            host, port = self.resolve_endpoint(self.grpc_endpoint)

            # If host and port is not set then we will retry
            if host and port:
                log.info('grpc-endpoint-connecting', host=host, port=port)
                self.channel = grpc.insecure_channel(
                    '{}:{}'.format(host, port))

                yang_from = self._retrieve_schema()
                log.info('proto-to-yang-schema', file=yang_from)
                self._compile_proto_files(yang_from)
                self._set_yang_schemas()

                self._clear_backoff()

                if self.on_start_callback is not None:
                    reactor.callLater(0, self.on_start_callback)

                self.connected = True
                if self.reconnect_callback is not None:
                    reactor.callLater(0, self.reconnect_callback)

                return

        except _Rendezvous, e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                log.info('grpc-endpoint-not-available')
            else:
                log.exception(e)
            yield self._backoff('not-available')

        except Exception, e:
            if not self.shutting_down:
                log.exception('cannot-connect', endpoint=_endpoint)
            yield self._backoff('unknown-error')

        reactor.callLater(1, self.connect)

    def _backoff(self, msg):
        wait_time = self.RETRY_BACKOFF[min(self.retries,
                                           len(self.RETRY_BACKOFF) - 1)]
        self.retries += 1
        log.error(msg, retry_in=wait_time)
        return asleep(wait_time)

    def _clear_backoff(self):
        if self.retries:
            log.info('reconnected', after_retries=self.retries)
            self.retries = 0

    def _retrieve_schema(self):
        """
        Retrieve schema from gRPC end-point, and save all *.proto files in
        the work directory.
        """
        assert isinstance(self.channel, grpc.Channel)
        stub = SchemaServiceStub(self.channel)
        # try:
        schemas = stub.GetSchema(Empty())
        # except _Rendezvous, e:
        #     if e.code == grpc.StatusCode.UNAVAILABLE:
        #
        #     else:
        #         raise e

        os.system('mkdir -p %s' % self.work_dir)
        os.system('rm -fr /tmp/%s/*' %
                  self.work_dir.replace('/tmp/', ''))  # safer

        for proto_file in schemas.protos:
            proto_fname = proto_file.file_name
            # TODO: Do we need to process a set of files using a prefix
            # instead of just one?
            proto_content = proto_file.proto
            log.info('saving-proto', fname=proto_fname, dir=self.work_dir,
                     length=len(proto_content))
            with open(os.path.join(self.work_dir, proto_fname), 'w') as f:
                f.write(proto_content)

            desc_content = decompress(proto_file.descriptor)
            desc_fname = proto_fname.replace('.proto', '.desc')
            log.info('saving-descriptor', fname=desc_fname, dir=self.work_dir,
                     length=len(desc_content))
            with open(os.path.join(self.work_dir, desc_fname), 'wb') as f:
                f.write(desc_content)
        return schemas.yang_from

    def _compile_proto_files(self, yang_from):
        """
        For each *.proto file in the work directory, compile the proto
        file into the respective *_pb2.py file as well as generate the
        corresponding yang schema.
        :return: None
        """
        log.info('start')
        google_api_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../protos/third_party'
        ))

        log.info('google-api', api_dir=google_api_dir)

        netconf_base_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '../..'
        ))
        log.info('netconf-dir', dir=netconf_base_dir)

        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith('.proto')]:
            log.info('filename', file=fname)

            need_yang = fname == yang_from
            log.debug('compiling',
                      file=fname,
                      yang_schema_required=need_yang)
            cmd = (
                'cd %s && '
                'env PATH=%s PYTHONPATH=%s '
                'python -m grpc.tools.protoc '
                '-I. '
                '-I%s '
                '--python_out=. '
                '--grpc_python_out=. '
                '--plugin=protoc-gen-gw=%s/rpc_gw_gen.py '
                '--gw_out=. '
                '--plugin=protoc-gen-custom=%s/proto2yang.py '
                '%s'
                '%s' % (
                    self.work_dir,
                    ':'.join([os.environ['PATH'], self.plugin_dir]),
                    ':'.join([google_api_dir, netconf_base_dir]),
                    google_api_dir,
                    self.plugin_dir,
                    self.plugin_dir,
                    '--custom_out=. ' if need_yang else '',
                    fname)
            )
            log.debug('executing', cmd=cmd, file=fname)
            os.system(cmd)
            log.info('compiled', file=fname)

        # Load the generated modules
        mapper = get_nc_rpc_mapper_instance(self.work_dir, self)
        mapper.load_modules()

    def _set_yang_schemas(self):
        if self.work_dir not in sys.path:
            sys.path.insert(0, self.work_dir)

        for fname in [f for f in os.listdir(self.work_dir)
                      if f.endswith('.yang')]:
            # Filter out schemas which are not required
            if fname not in C.SCHEMAS_TO_IGNORE:
                self.yang_schemas.add(fname[:-len('.yang')])
        log.info('yang-schemas', schemas=self.yang_schemas)

    @inlineCallbacks
    def invoke_voltha_rpc(self, service, method, params, metadata=None):
        try:
            mapper = get_nc_rpc_mapper_instance()

            # Get the mapping function using the service and method name
            func = mapper.get_function(service, method)
            if func is None:
                log.info('unsupported-rpc', service=service, method=method)
                return

            response = yield func(self, params, metadata)

            # Get the XML tag to use in the response
            xml_tag = mapper.get_xml_tag(service, method)

            # # Get the XML list item name used in the response
            # list_item_name = mapper.get_list_items_name(service, method)

            # Get the YANG defined fields (and their order) for that service
            # and method
            fields = mapper.get_fields_from_yang_defs(service, method)

            # Check if this represents a List and whether the field name is
            # items.  In the response (a dictionary), if a list named 'items'
            # is returned then 'items' can either:
            # 1) represent a list of items being returned where 'items' is just
            # a name to represent a list. In this case, this name will be
            # discarded
            # 2) represent the actual field name as defined in the proto
            # definitions.  If this is the case then we need to preserve the
            # name
            list_item_name = ''
            if fields: # if the return type is empty then fields will be None
                if len(fields) == 1:
                    if fields[0]['name'] == 'items':
                        list_item_name = 'items'

            # Rearrange the dictionary response as specified by the YANG
            # definitions
            rearranged_response = self.rearrange_dict(mapper, response, fields)

            log.info('rpc-result', service=service, method=method,
                     response=response,
                     rearranged_response=rearranged_response, xml_tag=xml_tag,
                     list_item_name=list_item_name, fields=fields)

            returnValue((rearranged_response, (xml_tag, list_item_name)))

        except Exception, e:
            log.exception('rpc-failure', service=service, method=method,
                          params=params, e=e)

    def rearrange_dict(self, mapper, orig_dict, fields):
        log.debug('rearranging-dict', fields=fields)
        result = collections.OrderedDict()
        if len(orig_dict) == 0 or not fields:
            return result
        for f in fields:
            if orig_dict.has_key(f['name']):
                if f['type_ref']:
                    # Get the fields for that type
                    sub_fields = mapper.get_fields_from_type_name(f['module'],
                                                                  f['type'])
                    if f['repeated']:
                        result[f['name']] = []
                        for d in orig_dict[f['name']]:
                            result[f['name']].append(self.rearrange_dict(
                                mapper, d, sub_fields))
                    else:
                        result[f['name']] = self.rearrange_dict(mapper,
                                                                orig_dict[
                                                                    f['name']],
                                                                sub_fields)
                else:
                    result[f['name']] = orig_dict[f['name']]
        return result

    @inlineCallbacks
    def invoke(self, stub, method_name, request, metadata, retry=1):
        """
        Invoke a gRPC call to the remote server and return the response.
        :param stub: Reference to the *_pb2 service stub
        :param method_name: The method name inside the service stub
        :param request: The request protobuf message
        :param metadata: [(str, str), (str, str), ...]
        :return: The response protobuf message and returned trailing metadata
        """

        if not self.connected:
            raise ServiceUnavailable()

        try:
            method = getattr(stub(self.channel), method_name)
            response, rendezvous = method.with_call(request, metadata=metadata)
            returnValue((response, rendezvous.trailing_metadata()))

        except grpc._channel._Rendezvous, e:
            code = e.code()
            if code == grpc.StatusCode.UNAVAILABLE:
                e = ServiceUnavailable()

                if self.connected:
                    self.connected = False
                    yield self.connect()
                    if retry > 0:
                        response = yield self.invoke(stub, method_name,
                                                     request, metadata,
                                                     retry=retry - 1)
                        returnValue(response)

            elif code in (
                    grpc.StatusCode.NOT_FOUND,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    grpc.StatusCode.ALREADY_EXISTS):

                pass  # don't log error, these occur naturally

            else:
                log.exception(e)

            raise e

    # Below is an adaptation of Google's MessageToDict() which includes
    # protobuf options extensions

    class Error(Exception):
        """Top-level module error for json_format."""

    class SerializeToJsonError(Error):
        """Thrown if serialization to JSON fails."""

    def _IsMapEntry(self, field):
        return (field.type == descriptor.FieldDescriptor.TYPE_MESSAGE and
                field.message_type.has_options and
                field.message_type.GetOptions().map_entry)

    def convertToDict(self, message):
        """Converts message to an object according to Proto3 JSON Specification."""

        js = {}
        return self._RegularMessageToJsonObject(message, js)

    def get_yang_option(self, field):
        opt = field.GetOptions()
        yang_opt = {}
        for fd, val in opt.ListFields():
            if fd.full_name == 'voltha.yang_inline_node':
                yang_opt['id'] = val.id
                yang_opt['type'] = val.type
                # Fow now, a max of 1 yang option is set per field
                return yang_opt

    def _RegularMessageToJsonObject(self, message, js):
        """Converts normal message according to Proto3 JSON Specification."""
        fields = message.ListFields()

        try:
            for field, value in fields:
                # Check for options
                yang_opt = self.get_yang_option(field)

                name = field.name
                if self._IsMapEntry(field):
                    # Convert a map field.
                    v_field = field.message_type.fields_by_name['value']
                    js_map = {}
                    for key in value:
                        if isinstance(key, bool):
                            if key:
                                recorded_key = 'true'
                            else:
                                recorded_key = 'false'
                        else:
                            recorded_key = key
                        js_map[recorded_key] = self._FieldToJsonObject(
                            v_field, value[key])
                    js[name] = js_map
                elif field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
                    # Convert a repeated field.
                    js[name] = [self._FieldToJsonObject(field, k)
                                for k in value]
                else:
                    # This specific yang option applies only to non-repeated
                    # fields
                    if yang_opt:  # Create a map
                        js_map = {}
                        js_map['yang_field_option'] = True
                        js_map['yang_field_option_id'] = yang_opt['id']
                        js_map['yang_field_option_type'] = yang_opt['type']
                        js_map['name'] = name
                        js_map[name] = self._FieldToJsonObject(field, value)
                        js[name] = js_map
                    else:
                        js[name] = self._FieldToJsonObject(field, value)

            # Serialize default value if including_default_value_fields is True.
            message_descriptor = message.DESCRIPTOR
            for field in message_descriptor.fields:
                # Singular message fields and oneof fields will not be affected.
                if ((
                                    field.label != descriptor.FieldDescriptor.LABEL_REPEATED and
                                    field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_MESSAGE) or
                        field.containing_oneof):
                    continue
                name = field.name
                if name in js:
                    # Skip the field which has been serailized already.
                    continue
                if self._IsMapEntry(field):
                    js[name] = {}
                elif field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
                    js[name] = []
                else:
                    js[name] = self._FieldToJsonObject(field,
                                                       field.default_value)

        except ValueError as e:
            raise self.SerializeToJsonError(
                'Failed to serialize {0} field: {1}.'.format(field.name, e))

        return js

    def _FieldToJsonObject(self, field, value):
        """Converts field value according to Proto3 JSON Specification."""
        if field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_MESSAGE:
            return self.convertToDict(value)
        elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_ENUM:
            enum_value = field.enum_type.values_by_number.get(value, None)
            if enum_value is not None:
                return enum_value.name
            else:
                raise self.SerializeToJsonError('Enum field contains an '
                                                'integer value '
                                                'which can not mapped to an enum value.')
        elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_STRING:
            if field.type == descriptor.FieldDescriptor.TYPE_BYTES:
                # Use base64 Data encoding for bytes
                return base64.b64encode(value).decode('utf-8')
            else:
                return value
        elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_BOOL:
            return bool(value)
        elif field.cpp_type in _INT64_TYPES:
            return str(value)
        elif field.cpp_type in _FLOAT_TYPES:
            if math.isinf(value):
                if value < 0.0:
                    return _NEG_INFINITY
                else:
                    return _INFINITY
            if math.isnan(value):
                return _NAN
        return value
