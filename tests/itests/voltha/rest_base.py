from unittest import TestCase
from requests import get, post, put, patch, delete


class RestBase(TestCase):

    base_url = 'http://localhost:8881'

    def url(self, path):
        while path.startswith('/'):
            path = path[1:]
        return self.base_url + '/' + path

    def verify_content_type_and_return(self, response, expected_content_type):
        if 200 <= response.status_code < 300:
            self.assertEqual(
                response.headers['Content-Type'],
                expected_content_type,
                msg='Content-Type %s != %s; msg:%s' % (
                     response.headers['Content-Type'],
                     expected_content_type,
                     response.content))
            if expected_content_type == 'application/json':
                return response.json()
            else:
                return response.content

    def get(self, path, expected_code=200,
            expected_content_type='application/json', headers=None):
        r = get(self.url(path), headers=headers)
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))
        return self.verify_content_type_and_return(r, expected_content_type)

    def post(self, path, json_dict=None, expected_code=201):
        r = post(self.url(path), json=json_dict)
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))
        return self.verify_content_type_and_return(r, 'application/json')

    def put(self, path, json_dict, expected_code=200):
        r = put(self.url(path), json=json_dict)
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))
        return self.verify_content_type_and_return(r, 'application/json')

    def delete(self, path, expected_code=209):
        r = delete(self.url(path))
        self.assertEqual(r.status_code, expected_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_code, r.content))


