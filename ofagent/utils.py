"""
Common utility functions
"""

from loxi.pp import PrettyPrinter


def pp(obj):
    pp = PrettyPrinter(maxwidth=80)
    pp.pp(obj)
    return str(pp)

def mac_str_to_tuple(mac):
    """
    Convert 'xx:xx:xx:xx:xx:xx' MAC address string to a tuple of integers.
    Example: mac_str_to_tuple('00:01:02:03:04:05') == (0, 1, 2, 3, 4, 5)
    """
    return tuple(int(d, 16) for d in mac.split(':'))