#!/usr/bin/python

import sys, socket, struct, binascii

def validate_ip(mcast_ip):
    ''' This function validates multicast IP and returns True if informatics address is correct '''

    if len(mcast_ip) < 9 or len(mcast_ip) > 15:
        print("Incorrect length of Multicast IP!")
        return False

    octets = mcast_ip.split('.')
    if len(octets) < 4:
        print("Incorrect number of octets!")
        return False

    for num in range(0,4):
        if not(validate_octet(octets[num])):
            print("Incorrect Octet!")
            return False

    if int(octets[0]) < 224 or int(octets[0]) > 239:
        print("Invalid octet! Must be in  224 ... 239 !")
        return False

    return True

def validate_octet(octet):
    ''' This function returns True if 'octet' is valid and in the range 0 ... 255 '''
    if octet.isdigit:
        octet_num = int(octet)
        if octet_num >= 0 and octet_num <=255:
            return True
   
    return False

def convert_ip2mac(mcast_ip):
    ''' Function convert_ip2mac takes multicast IP address and returns multicast MAC address '''

    if not(validate_ip(mcast_ip)):
        print("Not a valid multicast IP ! Should be in range 224.0.0.1 ... 239.255.255.255")
        sys.exit(0)

    mcast_mac = "01005e"
    octets = mcast_ip.split('.')
    second_oct = int(octets[1]) & 127
    third_oct = int(octets[2])
    fourth_oct = int(octets[3])

    mcast_mac = mcast_mac + format(second_oct,'02x') + format(third_oct, '02x') + format(fourth_oct, '02x')
    mcast_macbytes = mcast_mac.encode() 
    return mcast_macbytes

if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print("Usage: ./mcast_ip2mac.py ")
    else:
        mcast_ip = socket.inet_ntoa(struct.pack('!L', int(sys.argv[1])))
        print(convert_ip2mac(mcast_ip))
