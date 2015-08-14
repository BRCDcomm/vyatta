# Copyright 2014 OpenStack Foundation.
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

import collections
import os
import re
import time
import urllib

from eventlet import greenthread
import netaddr
from oslo.config import cfg
import requests
from sqlalchemy.orm import exc as orm_exception

from neutron.common import exceptions
from neutron.db import models_v2
from neutron.openstack.common import excutils
from neutron.openstack.common.gettextutils import _LE, _LI
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from novaclient import exceptions as nova_exc
from novaclient.v1_1 import client as novaclient

LOG = logging.getLogger(__name__)

cfg.CONF.register_opts([
    cfg.StrOpt('tenant_admin_name', help=_('Name of tenant admin user.')),
    cfg.StrOpt('tenant_admin_password', secret=True,
               help=_('Tenant admin password.')),
    cfg.StrOpt('tenant_id',
               help=_('UUID of tenant that holds Vyatta vRouter instances.')),
    cfg.StrOpt('image_id',
               help=_('Nova image id for instances of Vyatta vRouter.')),
    cfg.StrOpt('flavor', default=2,
               help=_('Nova VM flavor for instances of Vyatta vRouter.')),
    cfg.StrOpt('management_network_id',
               help=_('Vyatta vRouter management network name.')),
    cfg.StrOpt('vrouter_credentials', default="vyatta:vyatta",
               help=_('Vyatta vRouter login credentials')),
    cfg.IntOpt('nova_poll_interval', default=5,
               help=_('Number of seconds between consecutive Nova queries '
                      'when waiting for router instance status change.')),
    cfg.IntOpt('nova_spawn_timeout', default=300,
               help=_('Number of seconds to wait for Nova to activate '
                      'instance before setting resource to error state.')),
    cfg.IntOpt('vrouter_poll_interval', default=5,
               help=_('Number of seconds between consecutive Vyatta vRouter '
                      'queries when waiting for router instance boot.')),
    cfg.IntOpt('vrouter_boot_timeout', default=300,
               help=_('Number of seconds to wait for Vyatta vRouter to boot '
                      'before setting resource to error state.')),
], "VROUTER")


class VyattaVRouterDriver(object):

    def __init__(self):
        self._vrouter_instance_map = {}
        self._management_network_id = cfg.CONF.VROUTER.management_network_id

        self._nova_client = novaclient.Client(
            cfg.CONF.VROUTER.tenant_admin_name,
            cfg.CONF.VROUTER.tenant_admin_password,
            auth_url=cfg.CONF.nova_admin_auth_url,
            service_type="compute",
            tenant_id=cfg.CONF.VROUTER.tenant_id)

    def create_router(self, context):
        LOG.debug("Vyatta vRouter Driver::Create Router")
        # Launch the vRouter VM. Method takes care of vRouter VM cleanup
        # when we encounter nova spawn or vRouter boot issues
        router = self._launch_routerVM(context)
        return router.id

    def init_router(self, context, router):
        LOG.debug("Vyatta vRouter Driver::Initialize router")
        try:
            vrouter_api = self._get_router_api(context, router['id'])
            vrouter_api.init_router(router.get('name', 'vyatta-router'),
                                    router.get('admin_state_up', False))
        except (InvalidVRouterInstance, InvalidInstanceConfiguration,
                VRouterConnectFailure, VRouterOperationError) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Vyatta vRouter Driver::Initialize"
                              " router failed. Exception %s"), ex)
                self._delete_routerVM(context, router['id'])

    def delete_router(self, context, router_id):
        LOG.debug("Vyatta vRouter Driver::Deinitialize router")
        try:
            vrouter_api = self._get_router_api(context, router_id)
            vrouter_api.disconnect()
        finally:
            self._delete_routerVM(context, router_id)

    def attach_interface(self, context, router_id, port_id):
        LOG.debug("Vyatta vRouter Driver::Attach interface")
        router = self._nova_client.servers.get(router_id)
        router.interface_attach(port_id, None, None)

    def detach_interface(self, context, router_id, port_id):
        LOG.debug("Vyatta vRouter Driver::Deattach interface")
        router = self._nova_client.servers.get(router_id)
        router.interface_detach(port_id)

    def configure_interface(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Configure interface")
        vrouter_api = self._get_router_api(context, router_id)
        for interface_info in interface_infos:
            vrouter_api.add_interface_to_router(interface_info)

    def deconfigure_interface(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Deconfigure interface")
        vrouter_api = self._get_router_api(context, router_id)
        for interface_info in interface_infos:
            vrouter_api.remove_interface_from_router(interface_info)

    def configure_gateway(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Configure gateway")
        if len(interface_infos) != 1:
            raise InvalidParameter(
                cause=_("Only one external gateway interface expected. "
                        "Given interfaces = %s") % len(interface_infos))
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_router(external_gateway_info=interface_infos[0])

    def clear_gateway(self, context, router_id, interface_infos):
        LOG.debug("Vyatta vRouter Driver::Clear gateway")
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_router(external_gateway_info=None)

    def assign_floating_ip(self, context, router_id, floating_ip, fixed_ip):
        LOG.debug("Vyatta vRouter Driver::Assign Floating IP")
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.assign_floating_ip(floating_ip, fixed_ip)

    def unassign_floating_ip(self, context, router_id, floating_ip, fixed_ip):
        LOG.debug("Vyatta vRouter Driver::Unassign Floating IP")
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.unassign_floating_ip(floating_ip, fixed_ip)

    def update_static_routes(self, context, router_id, route_add, route_del):
        LOG.debug('Vyatta vRouter Driver::Update static routes')
        vrouter_api = self._get_router_api(context, router_id)
        vrouter_api.update_static_routes(route_add, route_del)

    def _launch_routerVM(self, context):
        LOG.debug("Vyatta vRouter Driver::Launch router")
        router_name = 'vrouter_{0}'.format(os.urandom(6).encode('hex'))
        LOG.info(
            _LI("Vyatta vRouter Driver::Creating the vRouter instance %s"),
            router_name)

        try:
            router = self._nova_client.servers.create(
                router_name, cfg.CONF.VROUTER.image_id,
                cfg.CONF.VROUTER.flavor,
                nics=[{'net-id': self._management_network_id}])
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound, nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception):
            with excutils.save_and_reraise_exception():
                LOG.error(
                    _LE("Vyatta vRouter Driver::Create server %s failed"),
                    router_name)
                raise InstanceSpawnError()

        LOG.info(_LI("Vyatta vRouter Driver::Waiting for the vRouter "
                     "instance %s to start"), router_name)

        def _router_spawn():
            while True:
                try:
                    instance = self._nova_client.servers.get(router.id)
                except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                        nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                        nova_exc.AuthSystemNotFound,
                        nova_exc.NoTokenLookupException,
                        nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                        nova_exc.ConnectionRefused, nova_exc.ClientException,
                        Exception):
                    yield cfg.CONF.VROUTER.nova_poll_interval
                    continue
                LOG.debug("Vyatta vRouter Driver::vRouter instance {0} "
                          "Spawn Status: {1}".format(router_name,
                                                     instance.status))
                if instance.status not in ('ACTIVE', 'ERROR'):
                    yield cfg.CONF.VROUTER.nova_poll_interval
                elif instance.status == 'ERROR':
                    raise InstanceSpawnError()
                else:
                    break

        try:
            # Wait for Nova to spawn VM instance
            self._wait(_router_spawn,
                       timeout=cfg.CONF.VROUTER.nova_spawn_timeout)
        except (InstanceSpawnError, WaitTimeoutError) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE(
                    "Vyatta vRouter Driver::vRouter {0} spawn issue. "
                    "Exception {1}").format(router_name, ex))
                self._delete_routerVM(context, router.id)

        try:
            ifs = router.interface_list()
            if len(ifs) != 1:
                raise InvalidParameter(
                    cause=_("Management interface expected "
                            "in router: %s") % router.id)
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound,
                nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                InvalidParameter, Exception):
            with excutils.save_and_reraise_exception():
                self._delete_routerVM(context, router.id)

        def _router_boot():
            router_api = None
            while router_api is None:
                try:
                    router_api = self._get_router_api(context, router.id)
                except (VRouterConnectFailure, VRouterOperationError):
                    yield cfg.CONF.VROUTER.vrouter_poll_interval
                    continue
                if router_api is not None:
                    break

        LOG.info(_LI("Vyatta vRouter Driver::Waiting for the vRouter {0} "
                     "to boot.").format(router_name))
        try:
            # Now wait for router to boot
            self._wait(_router_boot,
                       timeout=cfg.CONF.VROUTER.vrouter_boot_timeout)
        except (WaitTimeoutError, VRouterConnectFailure, VRouterOperationError,
                InvalidVRouterInstance, InvalidInstanceConfiguration) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Vyatta vRouter Driver::vRouter {0} boot issue. "
                              "Exception: {1}").format(router_name, ex))
                self._delete_routerVM(context, router.id)

        LOG.info(_LI("Vyatta vRouter Driver::vRouter instance %s is ready"),
                 router_name)

        return router

    def _wait(self, query_fn, timeout=0):
        end = time.time() + timeout
        for interval in query_fn():
            greenthread.sleep(interval)
            if timeout > 0 and time.time() >= end:
                raise WaitTimeoutError()

    def _delete_routerVM(self, context, router_id):
        LOG.info(
            _LI("Vyatta vRouter Driver::Deleting the vRouter VM instance %s"),
            router_id)
        self._vrouter_instance_map.pop(router_id, None)

        try:
            self._nova_client.servers.delete(router_id)
        except (nova_exc.UnsupportedVersion, nova_exc.CommandError,
                nova_exc.AuthorizationFailure, nova_exc.NoUniqueMatch,
                nova_exc.AuthSystemNotFound,
                nova_exc.NoTokenLookupException,
                nova_exc.EndpointNotFound, nova_exc.AmbiguousEndpoints,
                nova_exc.ConnectionRefused, nova_exc.ClientException,
                Exception):
            with excutils.save_and_reraise_exception:
                LOG.error(
                    _LE("Vyatta vRouter Driver::Failed to delete the vRouter"
                        " VM instance %s"),
                    router_id)

    def _get_router_api(self, context, router_id):
        LOG.debug("Vyatta vRouter Driver::Get router driver")

        try:
            return self._vrouter_instance_map[router_id]
        except KeyError:

            try:
                query = context.session.query(models_v2.Network)
                network = query.filter_by(
                    id=self._management_network_id).one()
            except orm_exception.NoResultFound as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Unable to find Vyatta vRouter "
                                  "management network %s"), ex)
                    raise InvalidInstanceConfiguration(
                        cause="Unable to find management network")

            try:
                vrouter_instance = self._nova_client.servers.get(router_id)
            except nova_exc.ClientException as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE(
                        "Unable to find Vyatta vRouter instance {0}. "
                        "Exception {1}").format(router_id, ex))
                    raise InvalidVRouterInstance(router_id=router_id)

            LOG.debug("Vyatta vRouter Management network: %s",
                      network['name'])
            address_map = vrouter_instance.addresses[network['name']]
            if address_map is None:
                raise InvalidVRouterInstance(router_id=router_id)
            address = address_map[0]["addr"]

            # Initialize vRouter API
            try:
                vrouter_api = VRouterRestAPIClient()
                vrouter_api.connect(address)
            except Exception as ex:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Vyatta vRouter Driver: vRouter {0} "
                              "Connection exception {1}").format(address, ex))

            self._vrouter_instance_map[router_id] = vrouter_api
            return vrouter_api


class VRouterRestAPIClient(object):

    """Vyatta vRouter REST API Client.

    Uses vRouter REST API to configure vRouter.
    """

    IF_MAC_ADDRESS = 'mac_address'
    IF_IP_ADDRESS = 'ip_address'
    IF_GATEWAY_IP = 'gateway_ip'

    REST_RETRY_LIMIT = 10
    REST_RETRY_DELAY = 5

    _VROUTER_VSE_MODEL = 54
    _VROUTER_VR_MODEL = 56

    # Floating ip NAT rules will be prioritized before subnet NAT rules.
    # Same rule number is used for both SNAT and DNAT rule.
    _MAX_NAT_FLOATING_IP_RULE_NUM = 4000
    _MAX_NAT_SUBNET_IP_RULE_NUM = 8000

    _EXTERNAL_GATEWAY_DESCR = 'External_Gateway'
    _ROUTER_INTERFACE_DESCR = 'Router_Interface'

    _external_gw_info = None
    _router_if_subnet_dict = {}
    _floating_ip_dict = {}

    # Floating IP NAT rule number counter.
    # It will be incremented in get next method.
    _nat_floating_ip_rule_num = 0

    # Subnet ip NAT rules are for router interfaces.
    # As we want to prioritize floating ip NAT rules first,
    # subnet rules will start only after floating ip rules.
    # It will be incremented in get next method.
    _nat_subnet_ip_rule_num = _MAX_NAT_FLOATING_IP_RULE_NUM

    # Stores the vrouter model
    _vrouter_model = None

    def __init__(self):
        self.address = None

    def connect(self, address):
        """Connects to vRouter using the provided address.

        Retrieves the configuration and updates the cache.
        """
        self.address = address
        LOG.info(_LI("Vyatta vRouter REST API: "
                     "Connecting to vRouter %s"), address)
        self._process_model()
        self._sync_cache()

    def init_router(self, router_name, admin_state_up):
        """
            Configures Router name and Admin State.
        """
        cmd_list = []

        self._set_router_name_cmd(cmd_list, router_name)
        self._set_admin_state_cmd(cmd_list, admin_state_up)

        retry(self._configure_cmd_batch,
              args=(cmd_list,), exceptions=(VRouterOperationError,),
              limit=self.REST_RETRY_LIMIT, delay=self.REST_RETRY_DELAY)

    def update_router(self, router_name=None,
                      admin_state_up=None, external_gateway_info=None):
        """ Updates Router name, Admin state, External gateway.

        All the parameters are optional.
        """

        cmd_list = []

        if router_name:
            self._set_router_name_cmd(cmd_list, router_name)

        if admin_state_up is not None:
            self._set_admin_state_cmd(cmd_list, admin_state_up)

        if external_gateway_info is not None:
            given_gw_info = self._get_gw_interface_info(external_gateway_info)
            nat_rules = self._update_gw_config_on_change(given_gw_info,
                                                         cmd_list)
            self._update_gw_cache_info(given_gw_info, nat_rules)
        else:
            self._clear_gw_configuration(cmd_list)
            self._clear_cached_gw_info()

    def add_interface_to_router(self, interface_info):
        """Sets ip address of the ethernet interface.

        Ethernet interface identifier is derived from the given mac-address.
        """

        (if_ip_address,
         eth_if_id) = self._get_ethernet_if_info(interface_info)

        cmd_list = []
        self._set_ethernet_if_cmd(cmd_list,
                                  eth_if_id,
                                  if_ip_address,
                                  self._ROUTER_INTERFACE_DESCR)

        router_if_subnet = self._get_subnet_from_ip_address(if_ip_address)

        # If external gateway was configured before then
        # we need to add SNAT rules
        rule_num = None
        if self._external_gw_info is not None:
            rule_num = self._add_snat_rule_for_router_if_cmd(
                cmd_list, router_if_subnet, self._external_gw_info)

        self._configure_cmd_batch(cmd_list)

        # Cache the router interface info using subnet
        if router_if_subnet not in self._router_if_subnet_dict:
            self._router_if_subnet_dict[router_if_subnet] = None

        if self._external_gw_info is not None:
            self._router_if_subnet_dict[router_if_subnet] = rule_num

    def remove_interface_from_router(self, interface_info):
        """Removes ip address of the ethernet interface.

        Ethernet interface identifier is derived from the given mac-address.
        """

        (if_ip_address,
         eth_if_id) = self._get_ethernet_if_info(interface_info)

        cmd_list = []
        self._delete_ethernet_if_cmd(cmd_list,
                                     eth_if_id,
                                     if_ip_address,
                                     self._ROUTER_INTERFACE_DESCR)

        # Check the cache for router interface
        router_if_subnet = self._get_subnet_from_ip_address(if_ip_address)
        if router_if_subnet in self._router_if_subnet_dict:
            # We need to delete the SNAT rule
            nat_rule = self._router_if_subnet_dict[router_if_subnet]
            if nat_rule is not None:
                self._delete_snat_rule_cmd(cmd_list, nat_rule)

        self._configure_cmd_batch(cmd_list)

        # Remove the router interface info from cache
        self._router_if_subnet_dict.pop(router_if_subnet, None)

    def assign_floating_ip(self, floating_ip, fixed_ip):
        """Creates SNAT and DNAT rules for given floating ip and fixed ip."""

        if self._external_gw_info is None:
            raise VRouterOperationError(
                ip_address=self.address,
                reason='External gateway not configured')

        cmd_list = []

        ext_if_id = self._external_gw_info.get_ethernet_if_id()

        # Get the next NAT rule number and add the NAT rule
        nat_rule_num = self._get_next_nat_floating_ip_rule_num()
        self._add_snat_rule_cmd(cmd_list, nat_rule_num, ext_if_id,
                                fixed_ip, floating_ip)
        self._add_dnat_rule_cmd(cmd_list, nat_rule_num, ext_if_id,
                                floating_ip, fixed_ip)

        # Set the floating ip in external gateway interface
        gw_net = netaddr.IPNetwork(self._external_gw_info.get_ip_address())
        self._set_ethernet_ip(
            cmd_list, self._external_gw_info.get_ethernet_if_id(),
            '{0}/{1}'.format(floating_ip, gw_net.prefixlen))

        self._configure_cmd_batch(cmd_list)

        # Store SNAT and DNAT rule in cache
        dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
        self._floating_ip_dict[dict_key] = nat_rule_num

    def unassign_floating_ip(self, floating_ip, fixed_ip):
        """Deletes SNAT and DNAT rules for given floating ip and fixed ip."""

        if self._external_gw_info is None:
            raise VRouterOperationError(
                ip_address=self.address,
                reason='External gateway not configured')

        cmd_list = []

        # Check the cache for nat rules
        dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
        if dict_key in self._floating_ip_dict:

            # Get the NAT rules from the cache and delete them
            nat_rule = self._floating_ip_dict[dict_key]
            self._delete_snat_rule_cmd(cmd_list, nat_rule)
            self._delete_dnat_rule_cmd(cmd_list, nat_rule)

            # Delete the floating ip in external gateway interface
            gw_net = netaddr.IPNetwork(self._external_gw_info.get_ip_address())
            self._delete_ethernet_ip_cmd(
                cmd_list, self._external_gw_info.get_ethernet_if_id(),
                '{0}/{1}'.format(floating_ip, gw_net.prefixlen))
        else:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='NAT rule not found for '
                                               'floating ip {0}'
                                               .format(floating_ip))

        self._configure_cmd_batch(cmd_list)

        if dict_key in self._floating_ip_dict:
            self._floating_ip_dict.pop(dict_key)

    def update_static_routes(self, routes_add, routes_del):
        cmd_list = []
        for rule in routes_add:
            cmd_list.append(SetCmd(
                'protocols/static/route/{0}/next-hop/{1}'.format(
                    urllib.quote_plus(rule.dest_cidr),
                    urllib.quote_plus(rule.next_hop))))

        for rule in routes_del:
            cmd_list.append(DeleteCmd(
                'protocols/static/route/{0}'.format(
                    urllib.quote_plus(rule.dest_cidr))))

        self._configure_cmd_batch(cmd_list)

    def disconnect(self):
        self.address = None

    def _rest_call(self, action, uri, custom_headers=None, session=None):
        LOG.debug('Vyatta Router REST Request: {0} {1}'.format(action, uri))
        if session is None:
            session = requests

        auth = tuple(cfg.CONF.VROUTER.vrouter_credentials.split(':'))
        if len(auth) != 2:
            raise InvalidParameter(
                cause=_("Invalid vrouter_credentials %s") % len(auth))

        headers = {'Accept': 'application/json',
                   'Content-Length': 0}

        if custom_headers:
            headers.update(custom_headers)

        try:
            uri = 'https://{0}{1}'.format(self.address, uri)
            return session.request(action, uri, auth=auth,
                                   headers=headers, verify=False)
        except requests.ConnectionError:
            LOG.error(_LE('Vyatta vRouter REST API: '
                          'Could not establish HTTP connection to %s'),
                      self.address)
            with excutils.save_and_reraise_exception():
                raise VRouterConnectFailure(ip_address=self.address)

    def _get_ethernet_if_info(self, interface_info):
        gw_mac_address = interface_info[self.IF_MAC_ADDRESS]
        gw_ip_address = interface_info[self.IF_IP_ADDRESS]
        gw_if_id = self._get_ethernet_if_id(gw_mac_address)

        return gw_ip_address, gw_if_id

    def _get_gw_interface_info(self, external_gateway_info):
        (gw_ip_address,
         gw_if_id) = self._get_ethernet_if_info(external_gateway_info)
        gw_gateway_ip = external_gateway_info[self.IF_GATEWAY_IP]

        given_gw_info = InterfaceInfo(gw_if_id, gw_ip_address, gw_gateway_ip)
        return given_gw_info

    def _update_gw_config_on_change(self, given_gw_info, cmd_list):
        # Check if the external gw info is already cached.
        # If the given external gw info is not equal to cached gw info
        # then we need to update the existing gw info.
        # So, clear old gw info and set new gw info.
        if (self._external_gw_info is not None and
                given_gw_info != self._external_gw_info):
            LOG.debug("Vyatta vRouter REST API: Cached Gateway info is "
                      "not the same as given gateway info")
            self._delete_external_gateway_if_cmd(
                cmd_list, self._external_gw_info)

        nat_rules = self._set_external_gateway_if_cmd(
            cmd_list, given_gw_info)

        # Execute the configuration commands
        self._configure_cmd_batch(cmd_list)

        return nat_rules

    def _update_gw_cache_info(self, given_gw_info, nat_rules):
        # Cache the external gateway info
        self._external_gw_info = given_gw_info

        # Cache the nat rules
        for router_if_subnet, rule_num in nat_rules.iteritems():
            self._router_if_subnet_dict[router_if_subnet] = rule_num

    def _clear_gw_configuration(self, cmd_list):
        # If external gateway info was cached before
        # then clear the gateway router info
        if self._external_gw_info is not None:
            self._delete_external_gateway_if_cmd(
                cmd_list, self._external_gw_info)
        else:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='External gateway not '
                                               'already configured')

        # Execute the configuration commands
        self._configure_cmd_batch(cmd_list)

    def _clear_cached_gw_info(self):
        # Clear the external gateway info from the cache
        self._external_gw_info = None

        # Remove NAT rules for the existing router interfaces
        for router_if_subnet in self._router_if_subnet_dict.keys():
            self._router_if_subnet_dict[router_if_subnet] = None

    def _set_external_gateway_if_cmd(self, cmd_list, gw_info):
        """Sets the external gateway configuration.

        Adds SNAT rules and updates the cache.
        """

        # Set the external gateway ip address
        self._set_ethernet_if_cmd(cmd_list,
                                  gw_info.get_ethernet_if_id(),
                                  gw_info.get_ip_address(),
                                  self._EXTERNAL_GATEWAY_DESCR)

        self._set_system_gateway_cmd(cmd_list, gw_info.get_gateway_ip())

        # Add NAT rules for the existing router interfaces
        nat_rules = {}
        for router_if_subnet in self._router_if_subnet_dict.keys():
            rule_num = self._add_snat_rule_for_router_if_cmd(cmd_list,
                                                             router_if_subnet,
                                                             gw_info)
            nat_rules[router_if_subnet] = rule_num

        return nat_rules

    def _delete_external_gateway_if_cmd(self, cmd_list, gw_info):
        """Sets the external gateway configuration.

        Adds SNAT rules and updates the cache.
        """

        # Remove default gateway
        self._delete_system_gateway_cmd(cmd_list,
                                        gw_info.get_gateway_ip())

        # Delete the external gateway ip address
        self._delete_ethernet_if_cmd(cmd_list,
                                     gw_info.get_ethernet_if_id(),
                                     gw_info.get_ip_address(),
                                     self._EXTERNAL_GATEWAY_DESCR)

        # Remove NAT rules for the existing router interfaces
        for nat_rule in self._router_if_subnet_dict.values():
            self._delete_snat_rule_cmd(cmd_list, nat_rule)

    def _add_snat_rule_for_router_if_cmd(self, cmd_list,
                                         router_if_subnet,
                                         ext_gw_info):

        # Get the next SNAT rule number
        rule_num = self._get_next_nat_subnet_ip_rule_num()

        # Create the SNAT rule and store in the cache
        self._add_snat_rule_cmd(cmd_list,
                                rule_num,
                                ext_gw_info.get_ethernet_if_id(),
                                router_if_subnet,
                                ext_gw_info.get_ip_addr_without_cidr())

        return rule_num

    def _get_subnet_from_ip_address(self, ip_address):

        ip_network = netaddr.IPNetwork(ip_address)
        # Return subnet with CIDR format
        ip_subnet = str(ip_network.cidr)

        return ip_subnet

    def _get_floating_ip_key(self, floating_ip, fixed_ip):
        """Returns the key to store floating ip and fixed ip combination."""

        return "{0}.{1}".format(floating_ip, fixed_ip)

    def _get_next_nat_floating_ip_rule_num(self):
        """Returns the next NAT rule number for floating ip."""

        if (self._nat_floating_ip_rule_num >=
                self._MAX_NAT_FLOATING_IP_RULE_NUM):
            raise VRouterOperationError(ip_address=self.address,
                                        reason='Max NAT Floating IP rule '
                                               'count reached')

        self._nat_floating_ip_rule_num += 1
        return self._nat_floating_ip_rule_num

    def _get_next_nat_subnet_ip_rule_num(self):
        """Returns the next NAT rule number for subnet ip."""

        if self._nat_subnet_ip_rule_num >= self._MAX_NAT_SUBNET_IP_RULE_NUM:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='Max NAT Subnet IP rule '
                                               'count reached')

        self._nat_subnet_ip_rule_num += 1
        return self._nat_subnet_ip_rule_num

    def _get_admin_state(self):
        """Retrieves Admin State."""
        output = self._show_cmd("ip/forwarding")
        LOG.info(_LI('Vyatta vRouter status : %s'), output)
        return "IP forwarding is on" in output

    def _get_nat_cmd(self):

        return 'service/nat' if (self._vrouter_model ==
                                 self._VROUTER_VR_MODEL) else 'nat'

    def _add_snat_rule_cmd(self, cmd_list, rule_num, ext_if_id,
                           src_addr, translation_addr):
        """Creates SNAT rule with the given parameters."""

        nat_cmd = self._get_nat_cmd()

        # Execute the commands
        cmd_list.append(
            SetCmd("{0}/source/rule/{1}".format(nat_cmd, rule_num)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/outbound-interface/{2}"
                               .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/source/address/{2}"
                               .format(nat_cmd, rule_num,
                                       urllib.quote_plus(src_addr))))
        cmd_list.append(SetCmd("{0}/source/rule/{1}/translation/address/{2}"
                               .format(nat_cmd, rule_num,
                                       urllib.quote_plus(translation_addr))))

    def _add_dnat_rule_cmd(self, cmd_list, rule_num, ext_if_id,
                           dest_addr, translation_addr):
        """Creates DNAT rule with the given parameters."""

        nat_cmd = self._get_nat_cmd()

        # Execute the commands
        cmd_list.append(
            SetCmd("{0}/destination/rule/{1}".format(nat_cmd, rule_num)))
        cmd_list.append(SetCmd("{0}/destination/rule/{1}/inbound-interface/{2}"
                               .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(SetCmd("{0}/destination/rule/{1}/destination/"
                               "address/{2}".format(
                                   nat_cmd, rule_num,
                                   urllib.quote_plus(dest_addr))))
        cmd_list.append(SetCmd("{0}/destination/rule/{1}/translation/"
                               "address/{2}".format(
                                   nat_cmd, rule_num,
                                   urllib.quote_plus(translation_addr))))

    def _delete_snat_rule_cmd(self, cmd_list, rule_num):
        """Deletes the given SNAT rule."""

        cmd_list.append(DeleteCmd("{0}/source/rule/{1}".
                                  format(self._get_nat_cmd(), rule_num)))

    def _delete_dnat_rule_cmd(self, cmd_list, rule_num):
        """Deletes the given DNAT rule."""

        cmd_list.append(DeleteCmd("{0}/destination/rule/{1}".
                                  format(self._get_nat_cmd(), rule_num)))

    def _set_admin_state_cmd(self, cmd_list, admin_state):
        """Sets Admin State using command."""

        if admin_state:
            if not self._get_admin_state():
                cmd_list.append(DeleteCmd("system/ip/disable-forwarding"))
        else:
            if self._get_admin_state():
                cmd_list.append(SetCmd("system/ip/disable-forwarding"))

    def _get_interfaces(self):
        output = self._show_cmd('interfaces/detail')

        return _parse_interfaces(output)

    def _get_ethernet_if_id(self, mac_address):
        """Uses show command output to find the ethernet interface."""

        LOG.debug('Vyatta vRouter:get_ethernet_if_id. Given MAC {0}'
                  .format(repr(mac_address)))

        mac_address = mac_address.strip().lower()
        output = self._show_cmd('interfaces/detail')

        ifaces = _parse_interfaces(output)

        for iface in ifaces:
            if iface['mac_address'] == mac_address:
                return iface['name']

        raise VRouterOperationError(
            ip_address=self.address,
            reason='Ethernet interface with Mac-address {0} does not exist'
            .format(mac_address))

    def _get_interface_cmd(self):

        interface_cmd = None

        if self._vrouter_model == self._VROUTER_VR_MODEL:
            interface_cmd = "dataplane"
        else:
            interface_cmd = "ethernet"

        return interface_cmd

    def _set_ethernet_ip(self, cmd_list, if_id, ip_address):
        """Sets ip address to an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        cmd_list.append(SetCmd("interfaces/{0}/{1}/address/{2}"
                               .format(if_cmd, if_id,
                                       urllib.quote_plus(ip_address))))

    def _set_ethernet_if_cmd(self, cmd_list, if_id,
                             ip_address, descr):
        """Sets ip address and description of an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        # Execute the commands
        cmd_list.append(SetCmd("interfaces/{0}/{1}/address/{2}"
                               .format(if_cmd, if_id,
                                       urllib.quote_plus(ip_address))))
        cmd_list.append(SetCmd("interfaces/{0}/{1}/description/{2}"
                               .format(if_cmd, if_id,
                                       urllib.quote_plus(descr))))

    def _delete_ethernet_ip_cmd(self, cmd_list, if_id, ip_address):
        """Deletes ip address from an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        cmd_list.append(DeleteCmd("interfaces/{0}/{1}/address/{2}"
                                  .format(if_cmd, if_id,
                                          urllib.quote_plus(ip_address))))

    def _delete_ethernet_if_cmd(self, cmd_list, if_id,
                                ip_address, descr):
        """Deletes ip address and description of an ethernet interface."""

        if_cmd = self._get_interface_cmd()

        # Execute the commands
        cmd_list.append(DeleteCmd("interfaces/{0}/{1}/address/{2}"
                                  .format(if_cmd, if_id,
                                          urllib.quote_plus(ip_address))))
        cmd_list.append(DeleteCmd("interfaces/{0}/{1}/description/{2}"
                                  .format(if_cmd, if_id,
                                          urllib.quote_plus(descr))))
        cmd_list.append(DeleteCmd("interfaces/{0}/{1}".
                                  format(if_cmd, if_id)))

    def _set_router_name_cmd(self, cmd_list, router_name):
        """Configures router name using command."""

        cmd_list.append(SetCmd("system/host-name/{0}".
                               format(urllib.quote_plus(router_name))))

    def _set_system_gateway_cmd(self, cmd_list, gateway_ip):

        cmd_list.append(SetCmd("protocols/static/route/{0}/next-hop/{1}".
                               format(urllib.quote_plus('0.0.0.0/0'),
                                      urllib.quote_plus(gateway_ip))))

    def _delete_system_gateway_cmd(self, cmd_list, gateway_ip):

        cmd_list.append(DeleteCmd("protocols/static/route/{0}".
                                  format(urllib.quote_plus('0.0.0.0/0'))))

    def _configure_cmd(self, cmd_type, cmd):
        """Executes the given configuration command.

        Commits and Saves the configuration changes to the startup config.
        """

        self.configure_cmd_list(cmd_type, [cmd])

    def _configure_cmd_batch(self, user_cmd_list):
        """Executes the given configuration command list.

        Commits and Saves the configuration changes to the startup config.
        """
        with requests.Session() as session:
            response = self._rest_call("POST", "/rest/conf", session=session)
            self._check_response(response, session=session)

            config_url = response.headers['Location']
            if config_url is None:
                raise VRouterOperationError(
                    ip_address=self.address,
                    reason='REST API configuration URL is null')

            config_url = "/" + config_url
            for user_cmd in user_cmd_list:
                config_cmd = '{0}/{1}/{2}'.format(
                    config_url, user_cmd.cmd_type, user_cmd.cmd)
                LOG.debug(
                    "Vyatta vRouter REST API: Config command %s", config_cmd)
                response = self._rest_call("PUT", config_cmd, session=session)
                self._check_response(response, config_url, session=session)

            response = self._rest_call(
                "POST", config_url + "/commit", session=session)
            LOG.debug("Vyatta vRouter REST API: %s/commit", config_url)
            self._check_response(response, config_url, session=session)

            response = self._rest_call(
                "POST", config_url + "/save", session=session)
            LOG.debug("Vyatta vRouter REST API: %s/save", config_url)
            self._check_response(response, config_url, session=session)

            response = self._rest_call("DELETE", config_url, session=session)
            self._check_response(response, session=session)

    def _execute_cli_cmd(self, cli_cmd):
        """Executes any given CLI command using REST API."""

        custom_headers = {'shell-command': cli_cmd}
        response = self._rest_call("GET", "/rest/app/command", custom_headers)
        self._check_response(response)
        return response.text

    def _check_response(self, response, config_url=None, session=None):

        if session is None:
            session = requests

        if response.status_code not in (requests.codes.OK,
                                        requests.codes.CREATED):
            LOG.error(_LE('Vyatta vRouter REST API: Response Status : '
                      '%(status)s Reason: %(reason)s') %
                      {'status': response.status_code,
                       'reason': response.reason})

            if config_url is not None:
                self._rest_call("DELETE", config_url, session=session)

            raise VRouterOperationError(ip_address=self.address,
                                        reason=response.reason)

    def _get_config_cmd(self, user_cmd):
        """Executes the given "get config" command."""

        response = self._rest_call("POST", "/rest/conf")
        self._check_response(response)

        config_url = response.headers['Location']
        if config_url is None:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='REST API Configuration URL '
                                               'is null')
        config_url = "/" + config_url
        config_cmd = '{0}/{1}/'.format(config_url, user_cmd)
        response = self._rest_call("GET", config_cmd)
        self._check_response(response)
        data = jsonutils.loads(response.text)
        self._rest_call("DELETE", config_url)
        return data

    def _show_cmd(self, user_cmd):

        op_cmd = '{0}/{1}/{2}'.format('/rest/op', 'show', user_cmd)
        response = self._rest_call("POST", op_cmd)
        self._check_response(response)

        op_url = response.headers['Location']
        if op_url is None:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='REST API Op URL is null')

        op_url = "/" + op_url

        def get_response_wrapper():
            response = self._rest_call("GET", op_url)
            if not response.text.strip():
                raise VRouterOperationError(ip_address=self.address,
                                            reason='Response is empty')
            return response

        response = retry(
            get_response_wrapper, exceptions=(VRouterOperationError,),
            limit=self.REST_RETRY_LIMIT, delay=self.REST_RETRY_DELAY)

        self._rest_call("DELETE", op_url)
        return response.text

    def _process_model(self):

        model = None
        show_output = self._show_cmd("version")
        LOG.debug('Vyatta vRouter REST API: Version output : %s',
                  show_output)
        if show_output is not None:
            ma = re.compile(".+Description.+Brocade Vyatta\D+(\d+).+",
                            re.DOTALL)
            result = ma.match(show_output)
            LOG.debug('Vyatta vRouter REST API: Result : %s', result)
            if result is not None:
                model_str = result.group(1)
                LOG.debug('Vyatta vRouter REST API: Result : %s',
                          model_str)
                model = int(model_str) / 100
                LOG.debug('Vyatta vRouter REST API: Result : %s',
                          model)
                if model in (self._VROUTER_VSE_MODEL, self._VROUTER_VR_MODEL):
                    self._vrouter_model = model

        LOG.debug('Vyatta vRouter REST API: Version : %s',
                  self._vrouter_model)
        if self._vrouter_model is None:
            raise VRouterOperationError(ip_address=self.address,
                                        reason='Unable to process vRouter '
                                        'model info: {0}'.format(model))

    def _sync_cache(self):

        show_output = self._show_cmd("configuration/all")

        system_gw = None
        gateway_str = self._get_config_block("protocols", show_output)
        if gateway_str is not None:
            system_gw = self._parse_system_gateway(gateway_str)

        interfaces_str = self._get_config_block("interfaces", show_output)
        if interfaces_str is not None:
            self._process_interfaces(interfaces_str, system_gw)

        if self._vrouter_model == self._VROUTER_VR_MODEL:
            show_output = self._get_config_block("service", show_output)

        nat_str = self._get_config_block("nat", show_output)
        if nat_str is not None:
            self._process_source_nat_rules(nat_str)

        LOG.info(_LI("Vyatta vRouter cache ext gw %s"),
                 self._external_gw_info)
        LOG.info(_LI("Vyatta vRouter cache router if dict %s"),
                 self._router_if_subnet_dict)
        LOG.info(_LI("Vyatta vRouter cache floating ip dict %s"),
                 self._floating_ip_dict)
        LOG.info(_LI("Vyatta vRouter cache NAT floating ip %s"),
                 self._nat_floating_ip_rule_num)
        LOG.info(_LI("Vyatta vRouter cache NAT subnet ip %s"),
                 self._nat_subnet_ip_rule_num)

    def _parse_system_gateway(self, search_str):

        system_gw_ip = None
        ma = re.compile(".+static.+route.+next-hop ([^ \n]+).+", re.DOTALL)
        result = ma.match(search_str)
        if result is not None:
            system_gw_ip = result.group(1)
        return system_gw_ip

    def _process_interfaces(self, search_str, system_gw_ip):

        for paragraph in search_str.split('}'):
            ma = re.compile(
                ".+ethernet (eth\d+).+address ([^ \n]+).+description ([^ \n]+)"
                ".+", re.DOTALL)
            result = ma.match(paragraph)
            if result is not None:
                eth_if_id = result.group(1)
                ip_address = result.group(2)
                description = result.group(3)
                if description == self._EXTERNAL_GATEWAY_DESCR:
                    ext_gw_info = InterfaceInfo(eth_if_id,
                                                ip_address, system_gw_ip)
                    self._external_gw_info = ext_gw_info
                elif description == self._ROUTER_INTERFACE_DESCR:
                    # Cache the router interface info using subnet
                    router_if_subnet = self._get_subnet_from_ip_address(
                        ip_address)
                    self._router_if_subnet_dict[router_if_subnet] = None

    def _process_source_nat_rules(self, search_str):

        for paragraph in search_str.split('rule'):
            ma = re.compile(
                ".(\d+).+outbound-interface.+source.+address ([^ \n]+)"
                ".+translation.+address ([^ \n]+).+", re.DOTALL)
            result = ma.match(paragraph)
            if result is not None:
                rule_num = int(result.group(1))
                src_addr = result.group(2)
                translation_addr = result.group(3)
                if (self._MAX_NAT_FLOATING_IP_RULE_NUM < rule_num <
                   self._MAX_NAT_SUBNET_IP_RULE_NUM and
                   src_addr in self._router_if_subnet_dict):
                    # Cache the SNAT rule for router interface
                    self._router_if_subnet_dict[src_addr] = rule_num
                    self._nat_subnet_ip_rule_num = rule_num

                elif rule_num < self._MAX_NAT_FLOATING_IP_RULE_NUM:
                    self._nat_floating_ip_rule_num = rule_num
                    floating_ip = translation_addr
                    fixed_ip = src_addr
                    # Store SNAT and DNAT rule in cache
                    dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
                    self._floating_ip_dict[dict_key] = rule_num

    def _get_config_block(self, input_str, search_str):

        if search_str is not None:
            index = search_str.find(input_str)
            if index >= 0:
                block_start = search_str[index + len(input_str):]
                block_str = []
                for line in block_start.split('\n'):
                    if line.startswith('}'):
                        break
                    block_str.append(line)
                return ''.join(block_str)

        return None


def retry(fn, args=None, kwargs=None, exceptions=None, limit=1, delay=0):
    args = args or []
    kwargs = kwargs or {}

    while limit > 0:
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if not exceptions or not isinstance(e, exceptions):
                raise
        if delay:
            greenthread.sleep(delay)
        limit -= 1
    raise

HWADDR = r'(?:[a-zA-Z0-9]{2}:){5}[a-zA-Z0-9]{2}'
IPv4_ADDR = r'(?:\d+\.){3}\d+'


EMPTY_LINE = re.compile(r'^\s+$')
IFACE = re.compile(r'^(\w+):')
LINK_ETHER = re.compile(r'\s+link/ether\s+({0})'.format(HWADDR))
IP_ADDR = re.compile(r'\s+inet\s+({0})'.format(IPv4_ADDR))


def _parse_interfaces(output):
    ifaces = []
    info = {}
    for line in output.splitlines():
        if not line or re.match(EMPTY_LINE, line):
            continue

        m = re.match(IFACE, line)
        if m:
            if info:
                ifaces.append(info)
            name = m.group(1)
            info = dict(name=name, ip_addrs=[], mac_address=None)
            continue

        m = re.match(LINK_ETHER, line)
        if m:
            info['mac_address'] = m.group(1).lower()

        m = re.match(IP_ADDR, line)
        if m:
            info['ip_addrs'].append(m.group(1))

    if info:
        ifaces.append(info)

    return ifaces


#    REST API command classes
class UserCmd(object):

    def __init__(self, cmd_type, cmd):
        self.cmd_type = cmd_type
        self.cmd = cmd

    def __repr__(self):
        return '{0} {1!r}'.format(self.cmd_type, self.cmd)

    def __eq__(self, other):
        if not isinstance(other, UserCmd):
            return NotImplemented
        return (self.cmd_type, self.cmd) == (other.cmd_type, other.cmd)

    def __ne__(self, other):
        return not self.__eq__(other)


class SetCmd(UserCmd):

    def __init__(self, cmd):
        super(SetCmd, self).__init__("set", cmd)


class DeleteCmd(UserCmd):

    def __init__(self, cmd):
        super(DeleteCmd, self).__init__("delete", cmd)


class InterfaceInfo(object):

    """Class for storing interface related info."""
    def __init__(self, ethernet_if_id, ip_address,
                 gateway_ip=None):
        self._ethernet_if_id = ethernet_if_id
        self._ip_address = ip_address
        self._gateway_ip = gateway_ip
        self._ip_addr_without_cidr = None

    def get_ethernet_if_id(self):
        return self._ethernet_if_id

    def get_ip_address(self):
        return self._ip_address

    def get_ip_addr_without_cidr(self):
        if self._ip_addr_without_cidr is None:
            # Find the subnet
            ip_network = netaddr.IPNetwork(self._ip_address)
            # Without CIDR format
            self._ip_addr_without_cidr = str(ip_network.ip)

        return self._ip_addr_without_cidr

    def get_gateway_ip(self):
        return self._gateway_ip

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return 'Eth if:{0} IP:{1} GW:{2}'.format(self._ethernet_if_id,
                                                 self._ip_address,
                                                 self._gateway_ip)

    def __repr(self):
        return self.__str__()


RouteRule = collections.namedtuple('RouteRule', 'dest_cidr, next_hop')


#    Vyatta vRouter Exceptions


class VRouterConnectFailure(exceptions.NeutronException):

    """Couldn't connect to instance."""
    message = _("Couldn't connect to Vyatta vRouter [%(ip_address)s].")


class VRouterOperationError(exceptions.NeutronException):

    """Internal Vyatta vRouter exception."""
    message = _("Internal Vyatta vRouter exception [%(ip_address)s]:"
                "%(reason)s.")


class InvalidVRouterInstance(exceptions.NeutronException):

    """Couldn't find the vrouter instance."""
    message = _("Couldn't find Vyatta vRouter instance %(router_id)s.")


class InvalidInstanceConfiguration(exceptions.NeutronException):

    """Invalid vRouter VM instance configuration."""
    message = _("Invalid Vyatta vRouter configuration: %(cause)s.")


class InvalidParameter(exceptions.NeutronException):

    """Invalid configuration parameter."""
    message = _("Invalid Parameter: %(cause)s.")


class WaitTimeoutError(exceptions.NeutronException):

    """Timeout error after waiting for Vyatta vRouter VM creation."""
    message = _("Timeout waiting for Vyatta vRouter instance creation.")


class InstanceSpawnError(exceptions.NeutronException):

    """vRouter VM instance spawning error."""
    message = _("Failed to spawn Vyatta vRouter VM instance.")
