#!/usr/bin/env python
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

""" virtual OLT Hardware Abstraction """

import argparse


def parse_args():

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', action='store', default='eth0',
                        help='ETH interface to send (default: eth0)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='verbose print out')

    return parser.parse_args()


def main():

    args = parse_args()

    if args.verbose:
        vType = '*verbose*'
        vHint = ''
    else:
        vType = '*regular*'
        vHint = '(hint: try --verbose)'

    print 'Hello, I am {} VOLTHA {}'.format(vType, vHint)
    print ' _    ______  __  ________  _____ '
    print '| |  / / __ \/ / /_  __/ / / /   |'
    print '| | / / / / / /   / / / /_/ / /| |'
    print '| |/ / /_/ / /___/ / / __  / ___ |'
    print '|___/\____/_____/_/ /_/ /_/_/  |_|'
    print ''


if __name__ == '__main__':
    main()
