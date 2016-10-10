#
# Copyright 2016 the original author or authors.
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
import base64
import json
import os
import sys
from commands import getstatusoutput
from google.protobuf.compiler.plugin_pb2 import CodeGeneratorRequest

from chameleon.protoc_plugins.swagger_template import \
    ProtobufCompilationFailedError
from chameleon.protos import third_party

this_dir = os.path.abspath(os.path.dirname(__file__))
third_party_dir = os.path.dirname(third_party.__file__)


def unindent(str):
    """eat leading space in front of lines based on the smallest one"""
    min_leading_spaces = len(str)
    lines = str.splitlines()
    for line in lines:
        if line:
            min_leading_spaces = min(len(line) - len(line.lstrip(' ')),
                                     min_leading_spaces)
    return '\n'.join(l[min_leading_spaces:] for l in lines)


def mkdir(path):
    """equivalent of command line mkdir -p <path>"""
    if os.path.exists(path):
        assert os.path.isdir(path)
        return
    head, tail = os.path.split(os.path.abspath(path))
    if not os.path.exists(head):
        mkdir(path)
    assert os.path.isdir(head)
    os.mkdir(path)


def save_file(path, content, mode=0644):
    """save content into file of path"""
    with file(path, 'w') as f:
        f.write(content)
    os.chmod(path, mode)


def load_file(path, read_mode='r'):
    """load content from file of path"""
    with file(path, read_mode) as f:
        content = f.read()
    return content


def generate_plugin_request(proto):
    """save proto file and run protoc to generate a plugin request protobuf"""

    workdir = '/tmp/chameleon_tests'

    mkdir(workdir)
    save_file(os.path.join(workdir, 'test.proto'), proto)
    cmd = (
        'cd {this_dir} && '
        'env PATH={extended_path} '
        'python -m grpc.tools.protoc '
        '-I{workdir} '
        '-I{third_party_dir} '
        '-I{this_dir} '
        '--plugin=protoc-gen-null=null_plugin.py '
        '--null_out={workdir} '
        '{workdir}/test.proto'
            .format(
            extended_path=os.path.dirname(sys.executable),
            python=sys.executable,
            this_dir=this_dir,
            workdir=workdir,
            third_party_dir=third_party_dir
        ))

    code, output = getstatusoutput(cmd)
    if code != 0:
        raise ProtobufCompilationFailedError(output)

    content = base64.decodestring(
        load_file(os.path.join(workdir, 'protoc.request'), 'rb'))
    request = CodeGeneratorRequest()
    request.ParseFromString(content)

    return request


def json_rt(data):
    """
    JSON round-trip is to simply get rid of OrderedDict, to allow cleaner
    testing.
    """
    return json.loads(json.dumps(data))
