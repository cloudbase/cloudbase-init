# Copyright 2019 Cloudbase Solutions Srl
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

import time

from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import reflection

LOG = logging.getLogger(__name__)


def retry_decorator(max_retry_count=5, timeout=None, inc_sleep_time=1,
                    max_sleep_time=1, exceptions=Exception):
    """Retries invoking the decorated method in case of expected exceptions.

    :param max_retry_count: The maximum number of retries performed. If 0, no
                            retry is performed. If None, there will be no limit
                            on the number of retries.
    :param timeout: The maximum time for which we'll retry invoking the method.
                    If 0 or None, there will be no time limit.
    :param inc_sleep_time: The time sleep increment used between retries.
    :param max_sleep_time: The maximum time to wait between retries.
    :param exceptions: A list of expected exceptions for which retries will be
                       performed. If None, any exception will be retried.
    """

    def wrapper(f):
        def inner(*args, **kwargs):
            try_count = 0
            sleep_time = 0
            time_start = time.time()

            while True:
                try:
                    return f(*args, **kwargs)
                except exceptions as exc:
                    with excutils.save_and_reraise_exception() as ctxt:
                        time_elapsed = time.time() - time_start
                        time_left = (timeout - time_elapsed
                                     if timeout else 'undefined')
                        tries_left = (max_retry_count - try_count
                                      if max_retry_count is not None
                                      else 'undefined')

                        should_retry = (
                            tries_left and
                            (time_left == 'undefined' or
                             time_left > 0))
                        ctxt.reraise = not should_retry

                        if should_retry:
                            try_count += 1
                            func_name = reflection.get_callable_name(f)

                            sleep_time = min(sleep_time + inc_sleep_time,
                                             max_sleep_time)
                            if timeout:
                                sleep_time = min(sleep_time, time_left)

                            LOG.debug("Got expected exception %(exc)s while "
                                      "calling function %(func_name)s. "
                                      "Retries left: %(retries_left)s. "
                                      "Time left: %(time_left)s. "
                                      "Time elapsed: %(time_elapsed)s "
                                      "Retrying in %(sleep_time)s seconds.",
                                      dict(exc=exc,
                                           func_name=func_name,
                                           retries_left=tries_left,
                                           time_left=time_left,
                                           time_elapsed=time_elapsed,
                                           sleep_time=sleep_time))
                            time.sleep(sleep_time)
        return inner
    return wrapper
