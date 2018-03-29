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
import os
import subprocess
import socket
import time
import re


def run_command_to_completion_with_raw_stdout(cmd):
    try:
        env = os.environ.copy()
        proc = subprocess.Popen(
            cmd,
            env=env,
            shell=True,
            stdout=subprocess.PIPE
        )
        out, err = proc.communicate()
        return out, err, proc.returncode
    except OSError as e:
        print 'Exception {} when running command:{}'.format(repr(e), cmd)
    return None


def run_command_to_completion_with_stdout_in_list(cmd):
    stdout_response = []
    try:
        command = cmd
        env = os.environ.copy()
        proc = subprocess.Popen(
            command,
            env=env,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1
        )
        with proc.stdout:
            for line in iter(proc.stdout.readline, b''):
                stdout_response.append(line)

        if proc.wait() != 0:
            err_msg = 'Command {} did not complete successfully '.format(cmd)
            return [], err_msg, proc.returncode

        return stdout_response, None, proc.returncode
    except OSError as e:
        print 'Exception {} when running command:{}'.format(repr(e), cmd)
    return None


def run_long_running_command_with_timeout(cmd, timeout,
                                          return_word_number_x_of_each_line=-1):
    captured_stdout = []
    try:
        t0 = time.time()
        env = os.environ.copy()
        proc = subprocess.Popen(
            cmd,
            env=env,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1
        )
        for line in iter(proc.stdout.readline, b''):
            if return_word_number_x_of_each_line != -1:
                ansi_escape = re.compile(r'\x1b[^m]*m')
                line = ansi_escape.sub('', line)
                if len(line.split()) > return_word_number_x_of_each_line:
                    captured_stdout.append(
                        line.split()[return_word_number_x_of_each_line])
            else:
                captured_stdout.append(line)
            if time.time() - t0 > timeout:
                try:
                    proc.terminate()
                    proc.wait()
                    # In principle this 'reset' should not be required.
                    # However, without it, the terminal is left in a funny
                    # state and required
                    subprocess.Popen(['reset']).wait()
                except Exception as e:
                    print "Received exception {} when killing process " \
                          "started with {}".format(repr(e), cmd)
                break
        return captured_stdout
    except Exception as e:
        print 'Exception {} when running command:{}'.format(repr(e), cmd)
    return None

def is_open(ip_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        items = ip_port.split(':')
        s.connect((items[0], int(items[1])))
        s.shutdown(2)
        return True
    except:
        return False

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_pod_ip(pod_name_prefix):
    '''
    This function works only in the single-node Kubernetes environment, where
    the name of a Voltha pod may look something like 'vcore-64ffb9b49c-sstfn'.
    The function searches for the pod whose name is prefixed with 'vcore-'
    and returns the IP address of that pod.
    In the Kubernetes clustered environment, there would likely be multiple pods
    so named, in which case the target pod sought could not be found.

    TODO: Investigate other CLIs or APIs that could be used to determine the pod IP.
    '''
    pod_name_prefix = pod_name_prefix + "-"
    out, err, rc = run_command_to_completion_with_raw_stdout('kubectl -n voltha get pods -o wide | grep ' +
                                                             pod_name_prefix)
    tokens = out.split()
    return tokens[5]
