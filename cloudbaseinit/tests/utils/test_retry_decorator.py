# Copyright 2019 Cloudbase Solutions SRL
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Unit tests for the utils.retry_decorator module.
"""
import mock
import unittest

import cloudbaseinit.utils.retry_decorator as retry_decorator


class TestException(Exception):
    def __init__(self, message=None):
        super(TestException, self).__init__(message)


class UtilsTestCase(unittest.TestCase):

    def _get_fake_func_with_retry_decorator(self, side_effect,
                                            *args, **kwargs):
        func_side_effect = mock.Mock(side_effect=side_effect)

        @retry_decorator.retry_decorator(*args, **kwargs)
        def fake_func(*_args, **_kwargs):
            return func_side_effect(*_args, **_kwargs)

        return fake_func, func_side_effect

    @mock.patch.object(retry_decorator, 'time')
    def test_retry_decorator(self, mock_time):
        max_retry_count = 5
        max_sleep_time = 2
        timeout = max_retry_count + 1
        mock_time.time.side_effect = range(timeout)

        raised_exc = TestException('fake_exc')
        side_effect = [raised_exc] * max_retry_count
        side_effect.append(mock.sentinel.ret_val)

        (fake_func,
         fake_func_side_effect) = self._get_fake_func_with_retry_decorator(
            exceptions=TestException,
            max_retry_count=max_retry_count,
            max_sleep_time=max_sleep_time,
            timeout=timeout,
            side_effect=side_effect)

        ret_val = fake_func(mock.sentinel.arg,
                            kwarg=mock.sentinel.kwarg)
        self.assertEqual(mock.sentinel.ret_val, ret_val)
        fake_func_side_effect.assert_has_calls(
            [mock.call(mock.sentinel.arg, kwarg=mock.sentinel.kwarg)] *
            (max_retry_count + 1))
        self.assertEqual(max_retry_count + 1, mock_time.time.call_count)
        mock_time.sleep.assert_has_calls(
            [mock.call(sleep_time)
             for sleep_time in [1, 2, 2, 2, 1]])

    @mock.patch.object(retry_decorator, 'time')
    def _test_retry_decorator_exceeded(self, mock_time, expected_try_count,
                                       mock_time_side_eff=None,
                                       timeout=None, max_retry_count=None):
        raised_exc = TestException('fake_exc')
        mock_time.time.side_effect = mock_time_side_eff

        (fake_func,
         fake_func_side_effect) = self._get_fake_func_with_retry_decorator(
            exceptions=TestException,
            timeout=timeout,
            side_effect=raised_exc)

        self.assertRaises(TestException, fake_func)
        fake_func_side_effect.assert_has_calls(
            [mock.call()] * expected_try_count)

    def test_retry_decorator_tries_exceeded(self):
        self._test_retry_decorator_exceeded(
            max_retry_count=2,
            expected_try_count=3)

    def test_retry_decorator_time_exceeded(self):
        self._test_retry_decorator_exceeded(
            mock_time_side_eff=[0, 1, 4],
            timeout=3,
            expected_try_count=1)

    @mock.patch('time.sleep')
    def test_retry_decorator_unexpected_exc(self, mock_sleep):
        raised_exc = TestException('fake_exc')
        fake_func, fake_func_side_effect = (
            self._get_fake_func_with_retry_decorator(
                exceptions=(IOError, AttributeError),
                side_effect=raised_exc))

        self.assertRaises(TestException,
                          fake_func, mock.sentinel.arg,
                          fake_kwarg=mock.sentinel.kwarg)

        self.assertFalse(mock_sleep.called)
        fake_func_side_effect.assert_called_once_with(
            mock.sentinel.arg, fake_kwarg=mock.sentinel.kwarg)
