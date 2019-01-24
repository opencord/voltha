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

from unittest import TestCase
from mock import patch, MagicMock
from voltha.adapters.adtran_olt.net.adtran_zmq import (
    AdtranZmqClient, ZmqPairConnection, TwistedZmqAuthenticator, LocalAuthenticationThread)
import zmq
from zmq import constants


class TestAdtranZmqClient_send(TestCase):
    """
    This class contains all methods to unit test AdtranZmqClient.send()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqPairConnection', autospec=True):
            # Create AdtranZmqClient instance for test
            self.adtran_zmq_client = AdtranZmqClient('1.2.3.4', lambda x: x, 5657)

    # Test send() with normal data
    def test_send_normal_data(self):
        self.adtran_zmq_client.send("data")
        self.adtran_zmq_client._socket.send.assert_called_once_with('data')

    # Test send() with bad data (force exception)
    def test_send_bad_data(self):
        # Cause exception to occur
        self.adtran_zmq_client._socket.send.side_effect = ValueError
        # _socket.send in AdtranZmqClient.send() already mocked out via mock_zmq_pair_connection
        self.adtran_zmq_client.send("cause exception")
        self.adtran_zmq_client._socket.send.assert_called_once_with('cause exception')
        self.adtran_zmq_client.log.exception.assert_called_once()


class TestAdtranZmqClient_shutdown(TestCase):
    """
    This class contains all methods to unit test AdtranZmqClient.shutdown()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqPairConnection', autospec=True):
            # Create AdtranZmqClient instance for test
            self.adtran_zmq_client = AdtranZmqClient('1.2.3.4', lambda x: x, 5657)

    # Test shutdown() and verifying that the socket call to shutdown() is made
    def test_shutdown(self):
        # _socket.shutdown in AdtranZmqClient.shutdown() already mocked out via mock_zmq_pair_connection
        self.adtran_zmq_client.shutdown()
        self.adtran_zmq_client._socket.shutdown.assert_called_once()


class TestAdtranZmqClient_socket(TestCase):
    """
    This class contains all methods to unit test AdtranZmqClient.socket()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqPairConnection', autospec=True) as mk_zmq_pair_conn:
            # Save mock instance ID for comparison later
            self.zmq_pair_conn_mock_id = mk_zmq_pair_conn.return_value
            # Create AdtranZmqClient instance for test
            self.adtran_zmq_client = AdtranZmqClient('1.2.3.4', lambda x: x, 5657)

    # Test socket() and verifying that the property and the attribute are correct
    def test_socket(self):
        # socket() is a property (getter) for the _socket attribute
        # test that socket() and _socket equal the same thing
        self.assertEqual(self.adtran_zmq_client.socket, self.zmq_pair_conn_mock_id)


class TestAdtranZmqClient_rx_nop(TestCase):
    """
    This class contains all methods to unit test AdtranZmqClient.rx_nop()
    """
    # Test rx_nop() -- nothing to test, just creating code coverage
    def test_rx_nop(self):
        # rx_nop() is a static method
        AdtranZmqClient.rx_nop(None)


@patch('voltha.adapters.adtran_olt.net.adtran_zmq.TwistedZmqAuthenticator')
class TestAdtranZmqClient_setup_plain_security(TestCase):
    """
    This class contains all methods to unit test AdtranZmqClient.setup_plain_security()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqPairConnection', autospec=True):
            # Create AdtranZmqClient instance for test
            self.adtran_zmq_client = AdtranZmqClient('1.2.3.4', lambda x: x, 5657)

    # Test setup_plain_security() including verifying calls to addCallbacks()
    # Omitting coverage for the methods inside of setup_plain_security() for now
    def test_setup_plain_security(self, mk_twisted_zmq_authenticator):
        deferred = self.adtran_zmq_client.setup_plain_security('user', 'pswd')
        self.adtran_zmq_client.auth.start.assert_called_once()
        # Test that addCallbacks was called twice
        self.assertEqual(deferred.addCallbacks.call_count, 2)
        # Test that both params used in each call is a function
        # First, the call to d.addCallbacks(configure_plain, config_failure)
        self.assertTrue(callable(deferred.addCallbacks.call_args_list[0][0][0]))
        self.assertTrue(callable(deferred.addCallbacks.call_args_list[0][0][1]))
        # Second, the call to d.addCallbacks(add_endoints, endpoint_failure)
        self.assertTrue(callable(deferred.addCallbacks.call_args_list[1][0][0]))
        self.assertTrue(callable(deferred.addCallbacks.call_args_list[1][0][1]))


class TestAdtranZmqClient_setup_curve_security(TestCase):
    """
    This class contains all methods to unit test AdtranZmqClient.setup_curve_security()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqPairConnection', autospec=True):
            # Create AdtranZmqClient instance for test
            self.adtran_zmq_client = AdtranZmqClient('1.2.3.4', lambda x: x, 5657)

    # Test setup_curve_security() -- not much to test, just creating line coverage
    def test_setup_curve_security(self):
        with self.assertRaises(NotImplementedError):
            self.adtran_zmq_client.setup_curve_security()


class TestZmqPairConnection_messageReceived(TestCase):
    """
    This class contains all methods to unit test ZmqPairConnection.messageReceived()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqConnection.__init__') as mock_init:
            # Create ZmqPairConnection instance for test
            mock_init.return_value = None
            self.zmq_pair_connection = ZmqPairConnection(None)

    # Test messageReceived() -- not much to test, just creating line coverage
    def test_messageReceived(self):
        self.zmq_pair_connection.onReceive = MagicMock()
        self.zmq_pair_connection.messageReceived('message')


class TestZmqPairConnection_onReceive(TestCase):
    """
    This class contains all methods to unit test ZmqPairConnection.onReceive()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqConnection.__init__') as mock_init:
            # Create ZmqPairConnection instance for test
            mock_init.return_value = None
            self.zmq_pair_connection = ZmqPairConnection(None)

    # Test onReceive() -- not much to test, just creating line coverage
    def test_messageReceived(self):
        with self.assertRaises(NotImplementedError):
            self.zmq_pair_connection.onReceive('message')


@patch('twisted.internet.reactor.callLater')
class TestZmqPairConnection_send(TestCase):
    """
    This class contains all methods to unit test ZmqPairConnection.send()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqConnection.__init__') as mock_init:
            # Create ZmqPairConnection instance for test
            mock_init.return_value = None
            self.zmq_pair_connection = ZmqPairConnection(None)
            self.zmq_pair_connection.read_scheduled = None
            self.zmq_pair_connection.socket = MagicMock()
            self.zmq_pair_connection.doRead = MagicMock()

    # Test send() for single-part message
    def test_send_single_part_msg(self, mk_callLater):
        self.zmq_pair_connection.send('message')
        self.zmq_pair_connection.socket.send.assert_called_once_with('message', constants.NOBLOCK)

    # Test send() for multi-part message
    def test_send_multi_part_msg(self, mk_callLater):
        self.zmq_pair_connection.send(['message1', 'message2', 'message3'])
        self.zmq_pair_connection.socket.send_multipart.assert_called_once_with(['message1', 'message2', 'message3'],
                                                                               flags=constants.NOBLOCK)


class TestTwistedZmqAuthenticator_allow(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.allow()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()
            self.twisted_zmq_authenticator.pipe = MagicMock()

    # Test allow() for successfully sending an ALLOW message with no IP addresses specified
    def test_allow_success_no_ip(self):
        self.twisted_zmq_authenticator.allow()
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'ALLOW'])

    # Test allow() for successfully sending an ALLOW message to allow one IP address
    def test_allow_success_one_ip(self):
        self.twisted_zmq_authenticator.allow('1.2.3.4')
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'ALLOW', b'1.2.3.4'])

    # Test allow() for successfully sending an ALLOW message to allow multiple IP addresses
    def test_allow_success_mult_ips(self):
        self.twisted_zmq_authenticator.allow('1.2.3.4', '5.6.7.8')
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'ALLOW', b'1.2.3.4', b'5.6.7.8'])

    # Test allow() for sending an ALLOW message that results in an exception
    def test_allow_failure(self):
        self.twisted_zmq_authenticator.allow(1234)
        self.twisted_zmq_authenticator.pipe.send.assert_not_called()

    def tearDown(self):
        self.twisted_zmq_authenticator.pipe = None


class TestTwistedZmqAuthenticator_deny(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.deny()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()
            self.twisted_zmq_authenticator.pipe = MagicMock()

    # Test deny() for successfully sending a DENY message with no IP addresses specified
    def test_deny_success_no_ip(self):
        self.twisted_zmq_authenticator.deny()
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'DENY'])

    # Test deny() for successfully sending a DENY message to deny one IP address
    def test_deny_success_one_ip(self):
        self.twisted_zmq_authenticator.deny('1.2.3.4')
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'DENY', b'1.2.3.4'])

    # Test deny() for successfully sending a DENY message to deny multiple IP addresses
    def test_deny_success_mult_ips(self):
        self.twisted_zmq_authenticator.deny('1.2.3.4', '5.6.7.8')
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'DENY', b'1.2.3.4', b'5.6.7.8'])

    # Test deny() for sending a DENY message that results in an exception
    def test_deny_failure(self):
        self.twisted_zmq_authenticator.deny(1234, 5678)
        self.twisted_zmq_authenticator.pipe.send.assert_not_called()

    def tearDown(self):
        self.twisted_zmq_authenticator.pipe = None


@patch('voltha.adapters.adtran_olt.net.adtran_zmq.jsonapi.dumps')
class TestTwistedZmqAuthenticator_configure_plain(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.configure_plain()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()
            self.twisted_zmq_authenticator.pipe = MagicMock()

    # Test configure_plain() for successful plain security configuration with basic password
    def test_configure_plain_success_with_pswd(self, mk_dumps):
        mk_dumps.return_value = '{"passwords": ["topsecret"]}'
        self.twisted_zmq_authenticator.configure_plain(passwords={'passwords': ['topsecret']})
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'PLAIN', b'*',
                                                                          b'{"passwords": ["topsecret"]}'])

    # Test configure_plain() for successful plain security configuration with no password
    def test_configure_plain_success_without_pswd(self, mk_dumps):
        mk_dumps.return_value = '{}'
        # 'passwords' parameter defaults to None
        self.twisted_zmq_authenticator.configure_plain()
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'PLAIN', b'*',
                                                                          b'{}'])

    # Test configure_plain() for failed call to send() with TypeError return
    def test_configure_plain_failure(self, mk_dumps):
        self.twisted_zmq_authenticator.pipe.send.side_effect = TypeError
        self.twisted_zmq_authenticator.configure_plain()
        self.twisted_zmq_authenticator.log.exception.assert_called_once()

    def tearDown(self):
        self.twisted_zmq_authenticator.pipe = None


class TestTwistedZmqAuthenticator_configure_curve(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.configure_curve()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()
            self.twisted_zmq_authenticator.pipe = MagicMock()

    # Test configure_curve() for successful curve security configuration
    def test_configure_curve_success(self):
        self.twisted_zmq_authenticator.configure_curve('x', 'anywhere')
        self.twisted_zmq_authenticator.pipe.send.assert_called_once_with([b'CURVE', b'x', b'anywhere'])

    # Test configure_curve() for failed call to send() with TypeError return
    def test_configure_curve_failure(self):
        self.twisted_zmq_authenticator.pipe.send.side_effect = TypeError
        self.twisted_zmq_authenticator.configure_curve()
        self.twisted_zmq_authenticator.log.exception.assert_called_once()

    def tearDown(self):
        self.twisted_zmq_authenticator.pipe = None


@patch('voltha.adapters.adtran_olt.net.adtran_zmq.threads.deferToThread')
@patch('voltha.adapters.adtran_olt.net.adtran_zmq.LocalAuthenticationThread', autospec=True)
@patch('voltha.adapters.adtran_olt.net.adtran_zmq.ZmqPairConnection', autospec=True)
class TestTwistedZmqAuthenticator_start(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.start()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()

    # Test start() for successful execution
    def test_start_success(self, mk_zmq_pair_conn, mk_local_auth_thread, mk_defer):
        _ = self.twisted_zmq_authenticator.start()
        self.assertEqual(self.twisted_zmq_authenticator.pipe.onReceive, AdtranZmqClient.rx_nop)

    # Test start() for failure due to artificial exception
    def test_start_failure(self, mk_zmq_pair_conn, mk_local_auth_thread, mk_defer):
        mk_defer.side_effect = TypeError
        self.twisted_zmq_authenticator.start()
        self.twisted_zmq_authenticator.log.exception.assert_called_once()


@patch('voltha.adapters.adtran_olt.net.adtran_zmq.sys')
class TestTwistedZmqAuthenticator_do_thread_start(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator._do_thread_start()
    """
    # Test _do_thread_start() for successful execution with non-default timeout=20
    def test_do_thread_start_success(self, mk_sys):
        mk_sys.version_info = (2, 7)
        mk_thread = MagicMock()
        mk_thread.started.wait.return_value = True
        TwistedZmqAuthenticator._do_thread_start(mk_thread, 20)
        mk_thread.start.assert_called_once_with()
        mk_thread.started.wait.assert_called_once_with(timeout=20)

    # Test _do_thread_start() for successful execution running python v2.6 with default timeout=10
    def test_do_thread_start_success_v26(self, mk_sys):
        mk_sys.version_info = (2, 6)
        mk_thread = MagicMock()
        TwistedZmqAuthenticator._do_thread_start(mk_thread)
        mk_thread.start.assert_called_once_with()
        mk_thread.started.wait.assert_called_once_with(timeout=10)

    # Test _do_thread_start() for failed execution due to thread.started.wait() returning False
    def test_do_thread_start_failure(self, mk_sys):
        mk_sys.version_info = (2, 7)
        mk_thread = MagicMock()
        mk_thread.started.wait.return_value = False
        with self.assertRaises(RuntimeError):
            TwistedZmqAuthenticator._do_thread_start(mk_thread)
        mk_thread.start.assert_called_once_with()
        mk_thread.started.wait.assert_called_once_with(timeout=10)


@patch('voltha.adapters.adtran_olt.net.adtran_zmq.succeed')
@patch('voltha.adapters.adtran_olt.net.adtran_zmq.threads.deferToThread')
class TestTwistedZmqAuthenticator_stop(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.stop()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()

    # Test stop() for successful execution where pipe exists and needs to be closed properly
    def test_stop_pipe_exists(self, mk_defer, mk_succeed):
        # Create mocks and save a reference for later because source code clears the pipe/thread attributes
        self.mk_pipe = self.twisted_zmq_authenticator.pipe = MagicMock()
        self.mk_thread = self.twisted_zmq_authenticator.thread = MagicMock()
        self.twisted_zmq_authenticator.thread.is_alive.return_value = True
        _ = self.twisted_zmq_authenticator.stop()
        self.mk_pipe.send.assert_called_once_with(b'TERMINATE')
        self.mk_pipe.shutdown.assert_called_once_with()
        self.mk_thread.is_alive.assert_called_once_with()
        mk_defer.assert_called_once_with(TwistedZmqAuthenticator._do_thread_join, self.mk_thread)

    # Test stop() for successful execution where pipe doesn't exist
    def test_stop_pipe_doesnt_exist(self, mk_defer, mk_succeed):
        self.twisted_zmq_authenticator.pipe = None
        _ = self.twisted_zmq_authenticator.stop()
        self.assertEqual(self.twisted_zmq_authenticator.pipe, None)
        self.assertEqual(self.twisted_zmq_authenticator.thread, None)


class TestTwistedZmqAuthenticator_do_thread_join(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator._do_thread_join()
    """
    # Test _do_thread_join() for successful execution
    def test_do_thread_join_default_timeout(self):
        mk_thread = MagicMock()
        TwistedZmqAuthenticator._do_thread_join(mk_thread)
        mk_thread.join.assert_called_once_with(1)

    # Test _do_thread_join() for successful execution
    def test_do_thread_join_timeout_10(self):
        mk_thread = MagicMock()
        TwistedZmqAuthenticator._do_thread_join(mk_thread, 10)
        mk_thread.join.assert_called_once_with(10)


class TestTwistedZmqAuthenticator_is_alive(TestCase):
    """
    This class contains all methods to unit test TwistedZmqAuthenticator.is_alive()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq_factory'):
            # Create TwistedZmqAuthenticator instance for test
            self.twisted_zmq_authenticator = TwistedZmqAuthenticator()

    # Test is_alive() to return True
    def test_is_alive_true(self):
        self.twisted_zmq_authenticator.thread = MagicMock()
        self.twisted_zmq_authenticator.thread.is_alive.return_value = True
        response = self.twisted_zmq_authenticator.is_alive()
        self.assertTrue(response)

    # Test is_alive() to return False
    def test_is_alive_false(self):
        self.twisted_zmq_authenticator.thread = MagicMock()
        self.twisted_zmq_authenticator.thread.is_alive.return_value = False
        response = self.twisted_zmq_authenticator.is_alive()
        self.assertFalse(response)


@patch('voltha.adapters.adtran_olt.net.adtran_zmq.LocalAuthenticationThread._handle_zap')
@patch('voltha.adapters.adtran_olt.net.adtran_zmq.LocalAuthenticationThread._handle_pipe')
@patch('voltha.adapters.adtran_olt.net.adtran_zmq.zmq.Poller', autospec=True)
class TestLocalAuthenticationThread_run(TestCase):
    """
    This class contains all methods to unit test LocalAuthenticationThread.run()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.Event', autospec=True):
            ctxt_mock = MagicMock()
            auth_mock = MagicMock()
            # Save mock instance ID's for comparison later
            self.ctxt_socket_instance = ctxt_mock.socket.return_value
            self.auth_zap_socket_instance = auth_mock.zap_socket
            # Create LocalAuthenticationThread instance for test
            self.local_auth_thread = LocalAuthenticationThread(ctxt_mock, None, authenticator=auth_mock)

    # Test run() for running the loop once and terminating due to simulated 'TERMINATE' msg from main thread socket
    def test_run_auth_loop_once(self, mk_poller, mk_handle_pipe, mk_handle_zap):
        instance = mk_poller.return_value
        instance.poll.return_value = [(self.ctxt_socket_instance, zmq.POLLIN)]
        mk_handle_pipe.return_value = True
        self.local_auth_thread.run()
        self.local_auth_thread.authenticator.start.assert_called_once_with()
        self.local_auth_thread.started.set.assert_called_once_with()
        instance.register.assert_any_call(self.ctxt_socket_instance, zmq.POLLIN)
        instance.register.assert_any_call(self.auth_zap_socket_instance, zmq.POLLIN)
        mk_handle_pipe.assert_called_once_with()
        self.local_auth_thread.pipe.close.assert_called_once_with()
        self.local_auth_thread.authenticator.stop.assert_called_once_with()

    # Test run() for running the loop once and terminating due to exception when handling zap socket
    def test_run_auth_loop_handle_zap_exception(self, mk_poller, mk_handle_pipe, mk_handle_zap):
        instance = mk_poller.return_value
        instance.poll.return_value = [(self.ctxt_socket_instance, zmq.POLLIN),
                                      (self.auth_zap_socket_instance, zmq.POLLIN)]
        mk_handle_pipe.return_value = False
        mk_handle_zap.side_effect = AssertionError
        self.local_auth_thread.run()
        mk_handle_zap.assert_called_once_with()
        self.local_auth_thread.log.exception.assert_called_once()

    # Test run() for failed call to poller.poll()
    def test_run_bad_poll_response(self, mk_poller, mk_handle_pipe, mk_handle_zap):
        instance = mk_poller.return_value
        instance.poll.side_effect = zmq.ZMQError
        self.local_auth_thread.run()
        mk_handle_pipe.assert_not_called()
        mk_handle_zap.assert_not_called()
        self.local_auth_thread.pipe.close.assert_called_once_with()
        self.local_auth_thread.authenticator.stop.assert_called_once_with()


class TestLocalAuthenticationThread_handle_zap(TestCase):
    """
    This class contains all methods to unit test LocalAuthenticationThread._handle_zap()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.Event', autospec=True):
            # Create LocalAuthenticationThread instance for test
            self.local_auth_thread = LocalAuthenticationThread(MagicMock(), None, authenticator=MagicMock())

    # Test _handle_zap() for handling a valid message returned from recv_multipart()
    def test_handle_zap_valid_msg(self):
        self.local_auth_thread.authenticator.zap_socket.recv_multipart.return_value = 'message'
        self.local_auth_thread._handle_zap()
        self.local_auth_thread.authenticator.handle_zap_message.assert_called_once_with('message')

    # Test _handle_zap() for handling no message returned from recv_multipart()
    def test_handle_zap_no_msg(self):
        self.local_auth_thread.authenticator.zap_socket.recv_multipart.return_value = None
        self.local_auth_thread._handle_zap()
        self.local_auth_thread.authenticator.handle_zap_message.assert_not_called()


class TestLocalAuthenticationThread_handle_pipe(TestCase):
    """
    This class contains all methods to unit test LocalAuthenticationThread._handle_pipe()
    """
    def setUp(self):
        with patch('voltha.adapters.adtran_olt.net.adtran_zmq.structlog.get_logger'), \
                patch('voltha.adapters.adtran_olt.net.adtran_zmq.Event', autospec=True):
            # Create LocalAuthenticationThread instance for test
            self.local_auth_thread = LocalAuthenticationThread(MagicMock(), None, authenticator=MagicMock())

    # Test _handle_pipe() for handling no message returned from recv_multipart()
    def test_handle_pipe_no_msg(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = None
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, True)

    # Test _handle_pipe() for handling ALLOW message with one IP address
    def test_handle_pipe_allow_one_ip(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'ALLOW', b'1.2.3.4']
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.authenticator.allow.assert_called_once_with(u'1.2.3.4')
        self.local_auth_thread.log.exception.assert_not_called()

    # Test _handle_pipe() for handling ALLOW message and failing due to exception in allow()
    def test_handle_pipe_allow_failure(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'ALLOW', b'1.2.3.4']
        self.local_auth_thread.authenticator.allow.side_effect = ValueError
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.authenticator.allow.assert_called_once_with(u'1.2.3.4')
        self.local_auth_thread.log.exception.assert_called_once()

    # Test _handle_pipe() for handling DENY message with two IP addresses
    def test_handle_pipe_deny_two_ips(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'DENY', b'1.2.3.4', b'5.6.7.8']
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.authenticator.deny.assert_called_once_with(u'1.2.3.4', u'5.6.7.8')
        self.local_auth_thread.log.exception.assert_not_called()

    # Test _handle_pipe() for handling DENY message and failing due to exception in deny()
    def test_handle_pipe_deny_failure(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'DENY', b'1.2.3.4', b'5.6.7.8']
        self.local_auth_thread.authenticator.deny.side_effect = ValueError
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.authenticator.deny.assert_called_once_with(u'1.2.3.4', u'5.6.7.8')
        self.local_auth_thread.log.exception.assert_called_once()

    # Test _handle_pipe() for handling PLAIN message
    @patch('voltha.adapters.adtran_olt.net.adtran_zmq.jsonapi.loads')
    def test_handle_pipe_plain(self, mk_jsonapi_loads):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'PLAIN', b'*', b'password']
        mk_jsonapi_loads.return_value = u'password'
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.authenticator.configure_plain.assert_called_once_with(u'*', u'password')

    # Test _handle_pipe() for handling CURVE message
    def test_handle_pipe_curve(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'CURVE', b'x', b'anywhere']
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.authenticator.configure_curve.assert_called_once_with(u'x', u'anywhere')

    # Test _handle_pipe() for handling TERMINATE message
    def test_handle_pipe_terminate(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'TERMINATE']
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, True)

    # Test _handle_pipe() for handling invalid message
    def test_handle_pipe_invalid(self):
        self.local_auth_thread.pipe.recv_multipart.return_value = [b'xINVALIDx']
        terminate = self.local_auth_thread._handle_pipe()
        self.assertEqual(terminate, False)
        self.local_auth_thread.log.error.assert_called_once()
