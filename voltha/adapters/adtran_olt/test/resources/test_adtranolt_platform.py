# Copyright 2017-present Adtran, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import voltha.adapters.adtran_olt.resources.adtranolt_platform as platform
import pytest


"""
These test functions test the function "mk_uni_port_num()"
in the class "adtran_platform()". For the tests with simple inputs,
answers are reached by simply adding the bit shifted arguments
because there aren't any overlapping 1 bits, so this should be the
same as a logical OR. For the rest of the tests I manually calculated
what the answers should be for a variety of scenarios.
"""

@pytest.fixture()
def test():
    return platform.adtran_platform()

#simple args, and no arg for the parameter that has a default value
def test_adtran_platform_mk_uni_port_num(test):
    output = test.mk_uni_port_num(1, 1)
    assert output == 2**11 + 2**4

#simple args including one for the parameter that has a default value
def test_adtran_platform_mk_uni_port_num_not_default(test):
    output = test.mk_uni_port_num(1, 1, 1)
    assert output == 2**11 + 2**4 + 1

#tests scenario where the logical OR doesn't equal the sum
def test_adtran_platform_mk_uni_port_num_sum_dne_bitwise_or(test):
    output = test.mk_uni_port_num(1, 128, 1)
    assert output == 128 * 2**4 +1

#tests what happens when a negative number is introduced
def test_adtran_platform_mk_uni_port_num_negative(test):
    output = test.mk_uni_port_num(-1, 1, 1)
    assert output == -2031

#tests what happens when 2 negative numbers are introduced
def test_adtran_platform_mk_uni_port_num_negatives(test):
    output = test.mk_uni_port_num(-1, -1, 1)
    assert output == -15

#tests what happens when strings are passed as parameters
def test_adtran_platform_mk_uni_port_num_strings(test):
    with pytest.raises(TypeError):
        output = test.mk_uni_port_num("test", "test", "test")

#tests what happens when nothing is passed as a parameter
def test_adtran_platform_mk_uni_port_num_no_args(test):
    with pytest.raises(TypeError):
        output = test.mk_uni_port_num()


"""
These test the function "uni_id_from_uni_port()" in the class
"adtran_platform()". Several of these tests pass in a number between 0
and 15 which should all return the same number back. Two more pass in huge
numbers with the same last four digits. The one with all 1's returns 15 and
the one with all 0's returns 0. Finally, I made sure that passing
in either the wrong type of argument or none at all threw the
appropriate type error.
"""

#this functions a logical AND of 15 and 15 which should stay the same
def test_adtran_platform_uni_id_from_uni_port_same_num(test):
    output = test.uni_id_from_uni_port(15)
    assert output == 15

#this function tests the logical AND of 15 and a huge num (all 1's in binary)
def test_adtran_platform_uni_id_from_uni_port_huge_num_ones(test):
    output = test.uni_id_from_uni_port(17179869183)
    assert output == 15

#logical AND of 15 and 0
def test_adtran_platform_uni_id_from_uni_port_zero(test):
    output = test.uni_id_from_uni_port(0)
    assert output == 0

#logical AND of 15 and a huge num (last 4 digits 0's in binary)
def test_adtran_platfrom_uni_id_from_uni_port_huge_num_zeros(test):
    output = test.uni_id_from_uni_port(17179869168)
    assert output == 0

#logical AND of 12 and 15
def test_adtran_platfrom_uni_id_from_uni_port_twelve(test):
    output = test.uni_id_from_uni_port(12)
    assert output == 12

#logical AND of 9 and 15
def test_adtran_platform_uni_id_from_uni_port_nine(test):
    output = test.uni_id_from_uni_port(9)
    assert output == 9

#logical AND of 3 and 15
def test_adtran_platform_uni_id_from_uni_port_three(test):
    output = test.uni_id_from_uni_port(3)
    assert output == 3

#passing in a string
def test_adtran_platform_uni_id_from_uni_port_string(test):
    with pytest.raises(TypeError):
        output = test.uni_id_from_uni_port("test")

#NO INPUTS AT ALL
def test_adtran_platform_uni_id_from_uni_port_no_args(test):
    with pytest.raises(TypeError):
        output = test.uni_id_from_uni_port()


"""
These test functions test the function "mk_uni_port_num()"
For the tests with simple inputs, answers are reached by simply
adding the bit shifted arguments because there aren't any
overlapping 1 bits, so this should be the same as a logical OR.
For the rest of the tests I manually calculated what the answers
should be for a variety of scenarios.
"""

#simple args, and no arg for the parameter that has a default value
def test_mk_uni_port_num_default():
    output = platform.mk_uni_port_num(1, 1)
    assert output == 2**11 + 2**4

#simple args including one for the parameter that has a default value
def test_mk_uni_port_num_not_default():
    output = platform.mk_uni_port_num(1, 1, 1)
    assert output == 2**11 + 2**4 + 1

#tests scenario where the logical OR doesn't equal the sum
def test_mk_uni_port_num_sum_dne_bitwise_or():
    output = platform.mk_uni_port_num(1, 128, 1)
    assert output == 128 * 2**4 + 1

#tests what happens when a negative number is introduced
def test_mk_uni_port_num_negative():
    output = platform.mk_uni_port_num(-1, 1, 1)
    assert output == -2031

#tests what happens when 2 negative numbers are introduced
def test_mk_uni_port_num_negatives():
    output = platform.mk_uni_port_num(-1, -1, 1)
    assert output == -15

#tests what happens when strings are passed as parameters
def test_mk_uni_port_num_strings():
    with pytest.raises(TypeError):
        output = platform.mk_uni_port_num("test", "test", "test")

#tests what happens when nothing is passed as a parameter
def test_mk_uni_port_num_no_args():
    with pytest.raises(TypeError):
        output = platform.mk_uni_port_num()


"""
Several of these tests pass in a number between 0 and 15 which
should all return the same number back. Two more pass in huge numbers
with the same last four digits. The one with all 1's returns 15 and
the one with all 0's returns 0. Finally, I made sure that passing
in either the wrong type of argument or none at all threw the
appropriate type error.
"""

#this functions a logical AND of 15 and 15 which should stay the same
def test_uni_id_from_uni_port_same_num():
    output = platform.uni_id_from_uni_port(15)
    assert output == 15

#this function tests the logical AND of 15 and a huge num (all 1's in binary)
def test_uni_id_from_uni_port_huge_num_ones():
    output = platform.uni_id_from_uni_port(17179869183)
    assert output == 15

#logical AND of 15 and 0
def test_uni_id_from_uni_port_zero():
    output = platform.uni_id_from_uni_port(0)
    assert output == 0

#logical AND of 15 and a huge num (last 4 digits 0's in binary)
def test_uni_id_from_uni_port_huge_num_zeros():
    output = platform.uni_id_from_uni_port(17179869168)
    assert output == 0

#logical AND of 12 and 15
def test_uni_id_from_uni_port_twelve():
    output = platform.uni_id_from_uni_port(12)
    assert output == 12

#logical AND of 9 and 15
def test_uni_id_from_uni_port_nine():
    output = platform.uni_id_from_uni_port(9)
    assert output == 9

#logical AND of 3 and 15
def test_uni_id_from_uni_port_three():
    output = platform.uni_id_from_uni_port(3)
    assert output == 3

#passing in a string
def test_uni_id_from_uni_port_string():
    with pytest.raises(TypeError):
        output = platform.uni_id_from_uni_port("test")

#NO INPUTS AT ALL
def test_uni_id_from_uni_port_no_args():
    with pytest.raises(TypeError):
        output = platform.uni_id_from_uni_port()


"""
The first few tests try a few different scenarios to make sure that the bit shifting
and logical AND are working as expected. There should never be a result that is
larger than 15. Then I checked to make sure that passing the wrong argument or no
arguments at all throws the expected type error.
"""

#test with the smallest number that remains non-zero after bit shift
def test_intf_id_from_uni_port_num_smallest():
    output = platform.intf_id_from_uni_port_num(2048)
    assert output == 1

#test with a number with different bits 1 through 11 to make sure they don't affect result
def test_intf_id_from_uni_port_num_big():
    output = platform.intf_id_from_uni_port_num(3458)
    assert output == 1

#test with massive number where bits 15 through 12 are 1010
def test_intf_id_from_uni_port_num_massive():
    output = platform.intf_id_from_uni_port_num(22459)
    assert output == 10

#test with smallest number that remains positive after bit shift, but is zero after the AND
def test_intf_id_from_uni_port_num_big_zero():
    output = platform.intf_id_from_uni_port_num(32768)
    assert output == 0

#test with largest number that gets bit shifted down to zero
def test_intf_id_from_uni_port_num_bit_shift_to_zero():
    output = platform.intf_id_from_uni_port_num(2047)
    assert output == 0

#test with a string passed in
def test_intf_id_from_uni_port_num_string():
    with pytest.raises(TypeError):
        output = platform.intf_id_from_uni_port_num("test")

#test with no args passed in
def test_intf_id_from_uni_port_num_no_args():
    with pytest.raises(TypeError):
        output = platform.intf_id_from_uni_port_num()


"""
i did the standard tests to make sure that it returned the expected values
for random normal cases and the max and min cases. I also checked args
that were too big and too small. Then I made sure that the first arg truly
didn't matter and that the default value of the last parameter worked.
Finally, I checked to make sure string args and no args at all threw the
appropriate errors.
"""

#testing with all args at 0 which should return 1024
def test_mk_alloc_id_all_zeros():
    output = platform.mk_alloc_id(0, 0, 0)
    assert output == 1024

#testing with onu_id out of bounds
def test_mk_alloc_id_onu_id_too_big():
    with pytest.raises(AssertionError):
        output = platform.mk_alloc_id(0, 128, 0)

#testing with idx out of bounds
def test_mk_alloc_id_idx_idx_too_big():
    with pytest.raises(AssertionError):
        output = platform.mk_alloc_id(0, 0, 5)

#test with both being negative
def test_mk_alloc_id_both_args_negative():
    with pytest.raises(AssertionError):
        output = platform.mk_alloc_id(0, -1, -1)

#testing with both parameters at their respective max
def test_mk_alloc_id_both_max():
    output = platform.mk_alloc_id(0, 127, 4)
    assert output == 2175

#testing with random values in the middle of their ranges and a string as the first arg
def test_mk_alloc_id_random_args():
    output = platform.mk_alloc_id("test", 100, 2)
    assert output == 1636

#testing with testing with the default value
def test_mk_alloc_id_default_value():
    output = platform.mk_alloc_id(0, 100)
    assert output == 1124

#testing with strings passed in
def test_mk_alloc_id_strings():
    with pytest.raises(AssertionError):
        output = platform.mk_alloc_id("test", "test", "test")

#testing with no args passed in
def test_mk_alloc_id_no_args():
    with pytest.raises(TypeError):
        output = platform.mk_alloc_id()


"""
Just some basic tests to get coverage here.This function probably only
exists to support backwards compatibility.
"""

#inputing a negative number
def test_intf_id_from_nni_port_num_negative():
    output = platform.intf_id_from_nni_port_num(-1)
    assert output == -1

#inputing zero
def test_intf_id_from_nni_port_num_zero():
    output = platform.intf_id_from_nni_port_num(0)
    assert output == 0

#inputing a positive number
def test_intf_id_from_nni_port_num_positive():
    output = platform.intf_id_from_nni_port_num(1)
    assert output == 1

#no args
def test_intf_id_from_nni_port_num_no_args():
    with pytest.raises(TypeError):
        output = platform.intf_id_from_nni_port_num()


"""
This function is a pretty simple else if statement, so I just checked
the edges of the ranges in the function, and the three 'out of bounds'
zones. Then I tried the standard passing in the wrong type and passing
nothing at all
"""

#testing the edges of the first range in the if statement
def test_intf_id_to_intf_type_bottom_of_first_range():
    output = platform.intf_id_to_intf_type(5)
    assert output == platform.Port.PON_OLT

#testing the edges of the range in the if statement
def test_intf_id_to_intf_type_top_of_first_range():
    output = platform.intf_id_to_intf_type(20)
    assert output == platform.Port.PON_OLT

#testing the edges of the range in the elif statement
def test_intf_id_to_intf_type_bottom_of_second_range():
    output = platform.intf_id_to_intf_type(1)
    assert output == platform.Port.ETHERNET_NNI

#testing the edges of the range in the elif statement
def test_intf_id_to_intf_type_top_of_second_range():
    output = platform.intf_id_to_intf_type(4)
    assert output == platform.Port.ETHERNET_NNI

#testing a value above the top of the higher range
def test_intf_id_to_intf_type_out_of_range_high():
    with pytest.raises(Exception):
        output = platform.intf_id_to_intf_type(20.1)

#testing a value between the ranges
def test_intf_id_to_intf_type_out_of_range_mid():
    with pytest.raises(Exception):
        output = platform.intf_id_to_intf_type(4.5)

#testing a value below the bottom of the lowest range
def test_intf_id_to_intf_type_out_of_range_low():
    with pytest.raises(Exception):
        output = platform.intf_id_to_intf_type(0.9)

#testing with a string passed in
def test_intf_id_to_intf_type_string():
    with pytest.raises(Exception):
        output = platform.intf_id_to_intf_type("test")

#testing with nothing passed in
def test_intf_id_to_intf_type_no_args():
    with pytest.raises(Exception):
        output = platform.intf_id_to_intf_type()


"""
I tested all six of the values in the list, and each time tested
a different value for the first parameter to make sure that it didn't matter.
Then I tested a wrong value to make sure it returned false, and tested a
string arg and no args.
"""

#testing the first value in the list of acceptable values
def test_is_upstream_first_value():
    output = platform.is_upstream(1, 1)
    assert output == True

#testing the second value in the list of acceptable values
def test_is_upstream_second_value():
    output = platform.is_upstream(18, 2)
    assert output == True

#testing the third value in the list of acceptable values
def test_is_upstream_third_value():
    output = platform.is_upstream(-800, 3)
    assert output == True

#testing the fourth value in the list of acceptable values
def test_is_upstream_fourth_value():
    output = platform.is_upstream(2.5, 4)

#testing the fifth value in the list of acceptable values
def test_is_upstream_fifth_value():
    output = platform.is_upstream("test", 65533)
    assert output == True

#testing the sixth value in the list of acceptable values
def test_is_upstream_sixth_value():
    output = platform.is_upstream(2456, 4294967293)
    assert output == True

#testing a value that does not exist in the list of acceptable values
def test_is_upstream_wrong_value():
    output = platform.is_upstream(8, 19)
    assert output == False

#testing a string being passed in as an argument
def test_is_upstream_string():
    output = platform.is_upstream(42, "test")
    assert output == False

#testing nothing being passed in as an argument
def test_is_upstream_no_args():
    with pytest.raises(TypeError):
        output = platform.is_upstream()


"""
I tested all six values again to make sure they returned false, then I tried
a random value to make sure it returned true. Then, I tried passing a string
and nothing again too.
"""

#testing with the first value in the list of unacceptable values
def test_is_downstream_first_value():
    output = platform.is_downstream(7, 1)
    assert output == False

#testing with the second value in the list of unacceptable values
def test_is_downstream_second_value():
    output = platform.is_downstream(34, 2)
    assert output == False

#testing with the third value in the list of unacceptable values
def test_is_downstream_third_value():
    output = platform.is_downstream("test", 3)
    assert output == False

#testing with the fourth value in the list of unacceptable values
def test_is_downstream_fourth_value():
    output = platform.is_downstream(68, 4)
    assert output == False

#testing with the fifth value in the list of unacceptable values
def test_is_downstream_fifth_value():
    output = platform.is_downstream(-345, 65533)
    assert output == False

#testing with the sixth value in the list of unacceptable values
def test_is_downstream_sixth_value():
    output = platform.is_downstream(.09, 4294967293)
    assert output == False

#testing a value that isn't in the list of unacceptable values
def test_is_downstream_wrong_right_value():
    output = platform.is_downstream(24, -65)
    assert output == True

#testing a string being passed in as an argument
def test_is_downstream_string():
    output = platform.is_downstream(11, "test")
    assert output == True

#testing nothing being passed in as an argument
def test_is_downstream_no_args():
    with pytest.raises(TypeError):
        output = platform.is_downstream()


