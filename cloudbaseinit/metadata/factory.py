# Copyright 2012 Cloudbase Solutions Srl
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

import concurrent.futures

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.utils import classloader


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


def _load_metadata_service(classloader, class_path):
    """Load and probe a single metadata service.

    Returns None when the class cannot be loaded or the provider is not
    available; errors are logged instead of propagated so that a single
    misbehaving provider cannot break the discovery of the other ones.
    """
    try:
        service = classloader.load_class(class_path)()
        if service.load():
            return service
    except Exception as ex:
        LOG.error("Failed to load metadata service '%s'" % class_path)
        LOG.exception(ex)
    return None


def get_metadata_service_sequential():
    # Return the first service that loads correctly
    cl = classloader.ClassLoader()
    for class_path in CONF.metadata_services:
        service = cl.load_class(class_path)()
        try:
            if service.load():
                return service
        except Exception as ex:
            LOG.error("Failed to load metadata service '%s'" % class_path)
            LOG.exception(ex)
    raise exception.MetadataNotFoundException("No available service found")


def get_metadata_service_parallel():
    """Return the first available service, testing providers concurrently.

    Every provider listed in `metadata_services` is probed at the same time,
    which helps when several of them poll unreachable endpoints. The winner
    is still picked by the position in the list, so the outcome matches what
    the sequential search would have returned. A provider that raises while
    loading only disables itself; it does not affect the other probes.
    """
    cl = classloader.ClassLoader()
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(CONF.parallel_metadata_workers, 1)) as pool:
        futures = [pool.submit(_load_metadata_service, cl, class_path)
                   for class_path in CONF.metadata_services]

        # Futures keep the order of `metadata_services`. Waiting for the
        # probes of the higher priority providers before accepting a result
        # is what makes the winner independent from the probing speed;
        # without it a later provider could win just because it responded
        # first.
        for future in futures:
            service = future.result()
            if service is not None:
                return service

    raise exception.MetadataNotFoundException(
        "No available service found")


def get_metadata_service():
    if CONF.parallel:
        return get_metadata_service_parallel()
    return get_metadata_service_sequential()
