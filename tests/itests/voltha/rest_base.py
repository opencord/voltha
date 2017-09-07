from unittest import TestCase
from requests import get, post, put, patch, delete
import urllib3

# This is to suppress the insecure request warning when using
# self signed ssl certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# For a list of valid GRPC status codes, refer to the following link
#   https://github.com/grpc/grpc-go/blob/master/codes/codes.go

class RestBase(TestCase):

    base_url = 'https://localhost:8881'

    def url(self, path):
        while path.startswith('/'):
            path = path[1:]
        return self.base_url + '/' + path

    def verify_content_type_and_return(self, response, expected_content_type):
        if 'grpc-status' in response.headers and int(response.headers['grpc-status']) != 0:
            return None

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

    def get(self, path, expected_http_code=200, grpc_status=0,
            expected_content_type='application/json', headers=None, verify=False):
        r = get(self.url(path), headers=headers, verify=verify)
        if 'grpc-status' in r.headers:
            self.assertEqual(int(r.headers['grpc-status']), grpc_status,
                             msg='GRPC Status %d!=%d; msg:%s' % (
                                 int(r.headers['grpc-status']),
                                 grpc_status,
                                 r.headers['grpc-message']))
        self.assertEqual(r.status_code, expected_http_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_http_code, r.content))
        return self.verify_content_type_and_return(r, expected_content_type)

    def post(self, path, json_dict=None, expected_http_code=201, grpc_status=0, verify=False):
        r = post(self.url(path), json=json_dict, verify=verify)
        if 'grpc-status' in r.headers:
            self.assertEqual(int(r.headers['grpc-status']), grpc_status,
                             msg='GRPC Status %d!=%d; msg:%s' % (
                                 int(r.headers['grpc-status']),
                                 grpc_status,
                                 r.headers['grpc-message']))
        self.assertEqual(r.status_code, expected_http_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_http_code, r.content))
        return self.verify_content_type_and_return(r, 'application/json')

    def put(self, path, json_dict, expected_http_code=200, grpc_status=0, verify=False):
        r = put(self.url(path), json=json_dict, verify=verify)
        if 'grpc-status' in r.headers:
            self.assertEqual(int(r.headers['grpc-status']), grpc_status,
                             msg='GRPC Status %d!=%d; msg:%s' % (
                                 int(r.headers['grpc-status']),
                                 grpc_status,
                                 r.headers['grpc-message']))
        self.assertEqual(r.status_code, expected_http_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_http_code, r.content))
        return self.verify_content_type_and_return(r, 'application/json')

    def delete(self, path, expected_http_code=209, grpc_status=0, verify=False):
        r = delete(self.url(path), verify=verify)
        if 'grpc-status' in r.headers:
            self.assertEqual(int(r.headers['grpc-status']), grpc_status,
                             msg='GRPC Status %d!=%d; msg:%s' % (
                                 int(r.headers['grpc-status']),
                                 grpc_status,
                                 r.headers['grpc-message']))
        self.assertEqual(r.status_code, expected_http_code,
                         msg='Code %d!=%d; msg:%s' % (
                             r.status_code, expected_http_code, r.content))
