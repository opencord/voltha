#!/usr/bin/env python
#--------------------------------------------------------------------------#
# Copyright (C) 2016 by Zsolt Haraszti, Nathan Knuth, and Ali Al-Shabibi   #
# All rights reserved.                                                     #
#                                                                          #
#   _    ______  __  ________  _____                                       #
#  | |  / / __ \/ / /_  __/ / / /   |                                      #
#  | | / / / / / /   / / / /_/ / /| |                                      #
#  | |/ / /_/ / /___/ / / __  / ___ |                                      #
#  |___/\____/_____/_/ /_/ /_/_/  |_|                                      #
#                                                                          #
#--------------------------------------------------------------------------#
# PROPRIETARY NOTICE                                                       #
# This Software consists of confidential information.                      #
# Trade secret law and copyright law protect this Software.                #
# The above notice of copyright on this Software does not indicate         #
# any actual or intended publication of such Software.                     #
#--------------------------------------------------------------------------#
""" virtual OLT Hardware Abstraction """

import argparse


def main():
    if (args.verbose):
        vType = 'verbose'
    else:
        vType = 'regular'
        
    print 'Hello, I am {} VOLTHA'.format(vType)
    print ' _    ______  __  ________  _____ '
    print '| |  / / __ \/ / /_  __/ / / /   |'
    print '| | / / / / / /   / / / /_/ / /| |'
    print '| |/ / /_/ / /___/ / / __  / ___ |'
    print '|___/\____/_____/_/ /_/ /_/_/  |_|'
    print ''

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', action='store', default='eth0',
                        help='ETH interface to send (default: eth0)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='verbose print out')

    args = parser.parse_args()
    
    main()

