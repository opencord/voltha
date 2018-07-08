#!/usr/bin/env python
# Copyright 2017-present Open Networking Foundation
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

"""
We use this module to time-test various alternatives for building,
serializing, and de-serializing objects.
"""

import time
from copy import copy, deepcopy

import addressbook_pb2
from random import randint
from uuid import uuid4
from simplejson import dumps, loads, JSONEncoder


class ProtoBufs(object):

    FILENAME = 'addressbook.bin.pb'

    @staticmethod
    def makeAddressBook(n):

        addressbook = addressbook_pb2.AddressBook()

        for i in xrange(n):
            person = addressbook.people.add()
            person.id = i
            person.name = uuid4().get_hex()
            person.email = person.name + '@abc.com'

            phone1 = person.phones.add()
            phone1.number = str(randint(1000000000, 7999999999))
            phone1.type = addressbook_pb2.Person.HOME

            phone2 = person.phones.add()
            phone2.number = str(randint(1000000000, 7999999999))
            phone2.type = addressbook_pb2.Person.MOBILE

        return addressbook

    @staticmethod
    def serialize(addressbook):
        return addressbook.SerializeToString()

    @staticmethod
    def deserialize(str):
        addressbook = addressbook_pb2.AddressBook()
        addressbook.ParseFromString(str)
        return addressbook

    @staticmethod
    def diff(addressbook1, addressbook2):
        assert isinstance(addressbook1, addressbook_pb2.AddressBook)
        assert isinstance(addressbook2, addressbook_pb2.AddressBook)
        assert addressbook1 == addressbook2


class JsonWithPythonData(object):

    FILENAME = 'addressbook.native.json'

    @staticmethod
    def makeAddressBook(n):

        addressbook = dict(people=[])
        people = addressbook['people']

        for i in xrange(n):
            name = uuid4().get_hex()
            people.append(dict(
                id=i,
                name=name,
                email=name + '@abc.com',
                phones=[
                    dict(
                        number=str(randint(1000000000, 7999999999)),
                        type='HOME'
                    ),
                    dict(
                        number=str(randint(1000000000, 7999999999)),
                        type='MOBILE'
                    )
                ]
            ))

        return addressbook

    @staticmethod
    def serialize(addressbook):
        return dumps(addressbook)

    @staticmethod
    def deserialize(str):
        return loads(str)

    @staticmethod
    def diff(addressbook1, addressbook2):
        assert isinstance(addressbook1, dict)
        assert isinstance(addressbook2, dict)
        assert addressbook1 == addressbook2


class JsonWithPythonClasses(object):

    class JsonEncoded(object):
        def __eq__(self, other):
            return self.__dict__ == other.__dict__

    class Phone(JsonEncoded):

        def __init__(self, number, type):
            self.number = number
            self.type = type

        @property
        def number(self):
            return self._type
        @number.setter
        def number(self, number):
            assert isinstance(number, str)
            self._number = number

        @property
        def type(self):
            return self._type
        @number.setter
        def type(self, type):
            assert isinstance(type, str)
            self._type = type

    class Person(JsonEncoded):

        def __init__(self, id, name, email, phones=list()):
            self.id = id
            self.name = name
            self.email = email
            self.phones = phones

        @property
        def id(self):
            return self._id
        @id.setter
        def id(self, id):
            assert isinstance(id, int)
            self._id = id

        @property
        def name(self):
            return self._name
        @name.setter
        def name(self, name):
            assert isinstance(name, str)
            self._name = name

        @property
        def email(self):
            return self._email
        @email.setter
        def email(self, email):
            assert isinstance(email, str)
            self._email = email

        @property
        def phones(self):
            return self._phones
        @phones.setter
        def phones(self, phones):
            assert isinstance(phones, list)
            self._phones = phones


    class AddressBook(JsonEncoded):

        def __init__(self, people=list()):
            self.people = people

        @property
        def people(self):
            return self._people
        @people.setter
        def people(self, people):
            assert isinstance(people, list)
            self._people = people

    cls_map = {
        Phone.__name__: Phone,
        Person.__name__: Person,
        AddressBook.__name__: AddressBook
    }

    class CustomEncoder(JSONEncoder):
        def default(self, o):
            if isinstance(o, JsonWithPythonClasses.JsonEncoded):
                d = dict((k.strip('_'), v) for k, v in o.__dict__.iteritems())
                d['_class'] = o.__class__.__name__
                return d
            return super(self).default(o)

    @staticmethod
    def as_object(dct):
        if '_class' in dct and dct['_class'] in JsonWithPythonClasses.cls_map:
            kw = deepcopy(dct)
            cls_name = kw.pop('_class')
            cls = JsonWithPythonClasses.cls_map[cls_name]
            return cls(**kw)
        return dct

    FILENAME = 'addressbook.class.json'

    @staticmethod
    def makeAddressBook(n):

        addressbook = JsonWithPythonClasses.AddressBook()
        people = addressbook.people

        for i in xrange(n):
            name = uuid4().get_hex()
            person = JsonWithPythonClasses.Person(
                id=i,
                name=name,
                email=name + '@abc.com',
                phones=[
                    JsonWithPythonClasses.Phone(
                        number=str(randint(1000000000, 7999999999)),
                        type='HOME'
                    ),
                    JsonWithPythonClasses.Phone(
                        number=str(randint(1000000000, 7999999999)),
                        type='MOBILE'
                    )
                ]
            )
            people.append(person)

        return addressbook

    @staticmethod
    def serialize(addressbook):
        return dumps(addressbook, cls=JsonWithPythonClasses.CustomEncoder)

    @staticmethod
    def deserialize(str):
        return loads(str, object_hook=JsonWithPythonClasses.as_object)

    @staticmethod
    def diff(addressbook1, addressbook2):
        assert isinstance(addressbook1, JsonWithPythonClasses.AddressBook)
        assert isinstance(addressbook2, JsonWithPythonClasses.AddressBook)
        assert len(addressbook1.people) == len(addressbook2.people)
        for i in xrange(len(addressbook1.people)):
            assert addressbook1.people[i] == addressbook2.people[i], \
                '\n%s\n!=\n%s' % (addressbook1.people[i].__dict__,
                              addressbook2.people[i].__dict__)
        assert addressbook1 == addressbook2


def timetest(cls, n):

    generator = cls()

    # generate addressbook

    t = time.time()
    addressbook = generator.makeAddressBook(n)
    t_make = time.time() - t

    # serialize addressbook to string and save it to file
    t = time.time()
    str = generator.serialize(addressbook)
    t_serialize = time.time() - t
    size = len(str)

    with open(cls.FILENAME, 'wb') as f:
        f.write(str)

    # deserialize by reading it back from file
    t = time.time()
    addressbook2 = generator.deserialize(str)
    t_deserialize = time.time() - t

    generator.diff(addressbook, addressbook2)

    print "%-30s %12lf   %12lf   %12lf   %10d" % \
          (cls.__name__,
           1e6 * t_make / n,
           1e6 * t_serialize / n,
           1e6 * t_deserialize / n,
           size / n)


def run_tests(n):
    print "%-30s %12s   %12s   %12s   %10s" % \
          ('Method', 'Gen [us]', 'Ser [us]', 'Des [us]', 'Size [bytes]')
    timetest(ProtoBufs, n)
    timetest(JsonWithPythonData, n)
    timetest(JsonWithPythonClasses, n)


run_tests(10000)
