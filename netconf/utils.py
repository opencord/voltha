# -*- coding: utf-8 -*-#
#
# March 31 2015, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2015, Deutsche Telekom AG
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
#
from __future__ import absolute_import, division, unicode_literals, \
    print_function, nested_scopes
from netconf import NSMAP
import copy
from lxml import etree


# Tries to somewhat implement RFC6241 filtering


def qname(tag):
    try:
        return etree.QName(tag)
    except ValueError:
        prefix, base = tag.split(":")
        return etree.QName(NSMAP[prefix], base)


def elm(tag, attrib=None, **extra):
    if attrib is None:
        attrib = dict()
    return etree.Element(qname(tag), attrib, **extra)


def leaf_elm(tag, value, attrib=None, **extra):
    e = elm(tag, attrib, **extra)
    e.text = str(value)
    return e


leaf = leaf_elm


def subelm(pelm, tag, attrib=None, **extra):
    if attrib is None:
        attrib = dict()
    return etree.SubElement(pelm, qname(tag), attrib, **extra)


def is_selection_node(felm):
    ftext = felm.text
    return ftext is None or not ftext.strip()


def filter_tag_match(filter_tag, elm_tag):
    fqname = etree.QName(filter_tag)
    eqname = qname(elm_tag)
    if not fqname.namespace:
        return fqname.localname == eqname.localname
    return fqname == eqname


def filter_node_match_no_value(filter_node, match_elm):
    # First check to see if tag matches.
    if not filter_tag_match(filter_node.tag, match_elm.tag):
        return False

    # Next check for attribute matches.
    # XXX does this need to filter out namespace attributes?
    if filter_node.attrib and filter_node.attrib != match_elm.attrib:
        return False

    return True


def filter_node_match(filter_node, match_elm):
    """Given a filter node element and a nodename and attribute dictionary
    return true if the filter element matches the elmname, attributes and value
    (if not None).

    The filter element can use a wildcard namespace or a specific namespace
    the attributes can be missing from the filter node but otherwise must match
    and the value is only checked for a match if it is not None.
    """
    if not filter_node_match_no_value(filter_node, match_elm):
        return False

    # Finally check for matching value.
    ftext = filter_node.text
    if ftext is None:
        return True

    ftext = ftext.strip()
    if not ftext:
        return True

    return ftext == match_elm.text


def filter_leaf_values(fcontain_elm, dest_node, leaf_elms, append_to):
    """Given a containment element (or None) verify that all leaf elements
    in leaf_elms either match, have corresponding selection nodes (empty)
    or are not present.

    Additionally the correct leaf data will be added to dest_node, and dest_node
    will be appended to append_to if append_to is not None.

    The return value with be True, False, or a possibly empty set of selection/containment nodes
    The only failing value is False, if True is returned then the caller should include all
    containment sibling nodes, otherwise the caller should process the list of containment/selection
    nodes.
    """
    children = fcontain_elm.getchildren() if fcontain_elm is not None else []
    selected_elms = []
    if not children:
        selected_elms = leaf_elms

    # Now look at all the leaf filter selector or match nodes
    include_all_leaves = True
    othernodes = []
    for felm in children:
        fchildren = felm.getchildren()
        for lelm in leaf_elms:
            if fchildren:
                # Verify that this doesn't match a leaf node.
                if filter_node_match_no_value(felm, lelm):
                    # XXX this is an error we should raise some exception.
                    return False
                continue
            elif filter_node_match(felm, lelm):
                if not felm.text:
                    # This was a selection node.
                    include_all_leaves = False

                selected_elms.append(lelm)
                break
        else:
            if fchildren:
                # This is OK we verified a containment filter didn't match leaf by getting here.
                if felm.text:
                    # XXX verify that there is no text on this node, report violation?
                    return False

                # Track selection/filter nodes
                include_all_leaves = False
                othernodes.append(felm)
            elif not felm.text:
                # This is OK as it means this is a selection node include it in othernodes
                include_all_leaves = False
                othernodes.append(felm)
            else:
                # We've exhausted all leaf elements to match this leaf filter so we failed.
                return False

    # Everything matched so add in the leaf data.
    if append_to is not None:
        append_to.append(dest_node)

    if include_all_leaves:
        dest_node.extend(leaf_elms)
    else:
        dest_node.extend(selected_elms)

    if include_all_leaves:
        return True
    return othernodes


def filter_containment_iter(fcontain_elm, dest_node, containment_nodes,
                            leaf_elms, append_to):
    """Given a containment filter node (or None) verify that all leaf elements
    either match, have corresponding selection nodes (empty) or are not present.

    If all leaf criteria are met then the iterator will return a triple of
    (new_filter_node, new_dest_node, new_data). new_filter_node corresponds to the
    matched containment node which is returned in new_dest_node, and new_data will be
    an element corresponding to the passed in dest_node.

    These should be processed by calling filter_containment_iter again.

    Additionally the correct leaf data will be added to dest_node, and dest_node
    will be appended to append_to if append_to is not None.

    This implements RFC6241 section 6.2.5
    """
    # No containment node so add everything.
    if fcontain_elm is None:
        # Add in the leaf data
        for e in leaf_elms:
            dest_node.append(e)

        # Append the match_node to the data
        if append_to is not None:
            append_to.append(dest_node)

        for node in containment_nodes:
            yield None, copy.copy(node), dest_node

    else:
        othernodes = filter_leaf_values(fcontain_elm, dest_node, leaf_elms,
                                        append_to)
        if othernodes is False:
            # No match
            pass
        elif othernodes is True:
            # All leaf values have matched and have been added and we should include all containers
            for node in containment_nodes:
                yield None, copy.copy(node), dest_node
        else:
            for felm in othernodes:
                for node in containment_nodes:
                    if filter_node_match_no_value(felm, node):
                        yield felm, copy.copy(node), dest_node


def filter_leaf_allows_add(filter_elm, tag, data, value):
    if filter_leaf_allows(filter_elm, tag, value):
        data.append(leaf_elm(tag, value))
        return True
    return False


def filter_leaf_allows(filter_elm, xpath, value):
    """Check the value at the xpath specified leaf matches the value.

    If filter_elm is None then allow.
    If there is no xpath element then allow if there are no other children.
    XXX what about xpath that has embedded predicates!
        perhaps what we want to call this is a normal path not an xpath.
    """
    if filter_elm is None:
        return True

    # If there are no children then allow everything.
    if not filter_elm.getchildren():
        return True

    # No match or multiple matches not allowed for leaf.
    flist = filter_elm.xpath(xpath, namespaces=NSMAP)
    if not flist or len(flist) > 1:
        return False
    felm = flist[0]

    # No children for leaf allowed (leaf)
    if felm.getchildren():
        return False

    # Allowed if empty or if value matches.
    if not felm.text or felm.text == str(value):
        return True

    return False


def filter_list_iter(filter_list, key_xpath, keys):
    """Return key, elm pairs that are allowed by keys using the values found using the given key_xpath"""
    # If we have no filter elm then return all keys.
    if filter_list is None:
        for key in keys:
            yield key, None

    try:
        # If this an element then make it a list of elements
        filter_list.xpath  # pylint: disable=W0104
        filter_list = [filter_list]
    except AttributeError:
        pass

    for filter_elm in filter_list:
        filter_elms = [x for x in
                       filter_elm.xpath(key_xpath, namespaces=NSMAP)]
        filter_keys = [x.text for x in filter_elms]
        if not filter_keys:
            for key in keys:
                yield key, filter_elm
        else:
            # Now walk our keys returning any that are in the filter list.
            for key in keys:
                if key in filter_keys:
                    yield key, filter_elm
                    # try:
                    #     idx = filter_keys.index(str(key))
                    #     yield key, filter_elm
                    # except ValueError:
                    #     pass


__author__ = 'Christian Hopps'
__date__ = 'March 31 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
