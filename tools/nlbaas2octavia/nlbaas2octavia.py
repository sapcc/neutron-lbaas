# Copyright 2018 Rackspace, US Inc.
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

import datetime
import re
import sys

from icontrol import exceptions
from oslo_config import cfg
from oslo_db.sqlalchemy import enginefacade
import oslo_i18n as i18n
from oslo_log import log as logging
from f5.bigip import ManagementRoot

_translators = i18n.TranslatorFactory(domain='nlbaas2octavia')

# The primary translation function using the well-known name "_"
_ = _translators.primary

bigips = {}
agents = {}

CONF = cfg.CONF

cli_opts = [
    cfg.StrOpt('cleanup_vcmp_guest', help='Cleanup the BigIP guest if status == passive/offline'),
    cfg.StrOpt('cleanup_vcmp_host', help='Cleanup the BigIP host vlans of the vcmp_guest'),
    cfg.BoolOpt('all', default=False,
                help='Migrate all load balancers'),
    cfg.StrOpt('lb_id',
               help='Load balancer ID to migrate'),
    cfg.StrOpt('project_id',
               help='Migrate all load balancers owned by this project'),
    cfg.StrOpt('agent_id',
               help='Migrate all load balancers hosted on this agent'),
]

migration_opts = [
    cfg.BoolOpt('delete_after_migration', default=False,
                help='Delete the load balancer records from neutron-lbaas'
                     ' after migration'),
    cfg.BoolOpt('trial_run', default=False,
                help='Run without making changes.'),
    cfg.StrOpt('neutron_db_connection',
               required=True,
               help='The neutron database connection string'),
    cfg.StrOpt('octavia_db_connection',
               required=True,
               help='The octavia database connection string'),
    cfg.StrOpt('bigip_password',
               help='The bigip password'),
]

cfg.CONF.register_cli_opts(cli_opts)
cfg.CONF.register_opts(migration_opts, group='migration')


def get_device_name(bigip):
    devices = bigip.tm.cm.devices.get_collection()
    for device in devices:
        if device.selfDevice == 'true':
            return device.name

    return None


def cleanup_vcmp(bigip, vcmp_guest):
    guest = bigip.tm.vcmp.guests.guest.load(name=vcmp_guest)
    vlans = [vlan for vlan in guest.vlans]
    for vlan_name in guest.vlans:
        vlan = bigip.tm.net.vlans.vlan.load(name=vlan_name.split('/')[2], partition='Common')
        if not vlan.name.startswith('net-') and not vlan.name.startswith('cc-'):
            vlans.remove(vlan_name)
            guest.vlans = vlans
            guest.update()
            vlan.delete()


def cleanup_bigip(bigip):
    act = bigip.tm.cm.devices.device.load(
        name=get_device_name(bigip), partition='Common')
    active = act.failoverState.lower() == 'active'

    if active:
        raise Exception(_('BigIP is active, aborting cleanup'))

    ltm_types = [
        bigip.tm.ltm.virtuals,
        bigip.tm.ltm.virtual_address_s,
        bigip.tm.ltm.policys,
        bigip.tm.ltm.pools,
        bigip.tm.ltm.profile.client_ssls,
        bigip.tm.ltm.monitor.https,
        bigip.tm.ltm.monitor.https_s,
        bigip.tm.ltm.monitor.tcps,
        bigip.tm.ltm.monitor.gateway_icmps,
        bigip.tm.ltm.monitor.externals,
        bigip.tm.ltm.monitor.tcp_half_opens,
        bigip.tm.ltm.nodes,
        bigip.tm.ltm.snats,
        bigip.tm.ltm.snatpools,
        bigip.tm.ltm.snat_translations,
        bigip.tm.ltm.persistence.universals,
        bigip.tm.ltm.rules
    ]
    for ltm_type in ltm_types:
        [r.delete() for r in ltm_type.get_collection()
         if r.partition != 'Common']

    for sslprofile in bigip.tm.ltm.profile.client_ssls.get_collection():
        if sslprofile.raw['name'].startswith('Project_'):
            sslprofile.delete()

    for cert in bigip.tm.sys.file.ssl_certs.get_collection():
        if cert.raw['name'].startswith('Project_'):
            cert.delete()

    net_types = [
        bigip.tm.net.arps,
        bigip.tm.net.selfips,
        bigip.tm.net.vlans,
        bigip.tm.net.route_domains
    ]
    try:
        for net_type in net_types:
            [r.delete() for r in net_type.get_collection()
             if not r.name.startswith('cc') and not r.name == '0']
    except exceptions.iControlUnexpectedHTTPError:
        pass

    print([folder.name for folder in bigip.tm.sys.folders.get_collection()])
    for folder in bigip.tm.sys.folders.get_collection():
        if folder.name == '/' or folder.name == 'Common' or getattr(folder, 'partition', '') == 'Common':
            continue
        try:
            folder.delete()
        except:
            print("Deletion of {} failed".format(folder.name))
            try:
                draft = bigip.tm.sys.folders.folder.load(name='Drafts', partition=folder.name)
                draft.delete()
                folder.delete()
            except:
                pass

    for route in bigip.tm.net.routes.get_collection():
        route.delete()

    for selfip in bigip.tm.net.selfips.get_collection():
        if not selfip.name.startswith('cc'):
            selfip.delete()

    for route_domain in bigip.tm.net.route_domains.get_collection():
        if route_domain.id != 0:
            route_domain.delete()

    for vlan in bigip.tm.net.vlans.get_collection():
        if not vlan.name.startswith('cc'):
            vlan.delete()


def cascade_delete_neutron_lb(n_session, lb_id):
    listeners = n_session.execute(
        "SELECT id FROM lbaas_listeners WHERE loadbalancer_id = :lb_id;",
        {'lb_id': lb_id})
    for listener in listeners:
        l7policies = n_session.execute(
            "SELECT id FROM lbaas_l7policies WHERE listener_id = :list_id;",
            {'list_id': listener[0]})
        for l7policy in l7policies:
            # Delete l7rules
            n_session.execute(
                "DELETE FROM lbaas_l7rules WHERE l7policy_id = :l7p_id;",
                {'l7p_id': l7policy[0]})
        # Delete l7policies
        n_session.execute(
            "DELETE FROM lbaas_l7policies WHERE listener_id = :list_id;",
            {'list_id': listener[0]})
        # Delete SNI records
        n_session.execute(
            "DELETE FROM lbaas_sni WHERE listener_id = :list_id;",
            {'list_id': listener[0]})

    # Delete the listeners
    n_session.execute(
        "DELETE FROM lbaas_listeners WHERE loadbalancer_id = :lb_id;",
        {'lb_id': lb_id})

    pools = n_session.execute(
        "SELECT id, healthmonitor_id FROM lbaas_pools "
        "WHERE loadbalancer_id = :lb_id;", {'lb_id': lb_id}).fetchall()
    for pool in pools:
        # Delete the members
        n_session.execute(
            "DELETE FROM lbaas_members WHERE pool_id = :pool_id;",
            {'pool_id': pool[0]})
        # Delete the session persistence records
        n_session.execute(
            "DELETE FROM lbaas_sessionpersistences WHERE pool_id = :pool_id;",
            {'pool_id': pool[0]})

        # Delete the pools
        n_session.execute(
            "DELETE FROM lbaas_pools WHERE id = :pool_id;",
            {'pool_id': pool[0]})

        # Delete the health monitor
        if pool[1]:
            result = n_session.execute("DELETE FROM lbaas_healthmonitors "
                                       "WHERE id = :id", {'id': pool[1]})
            if result.rowcount != 1:
                raise Exception(_('Failed to delete health monitor: '
                                  '%s') % pool[1])
    # Delete the lb stats
    n_session.execute(
        "DELETE FROM lbaas_loadbalancer_statistics WHERE "
        "loadbalancer_id = :lb_id;", {'lb_id': lb_id})

    # Delete provider record
    n_session.execute(
        "DELETE FROM providerresourceassociations WHERE "
        "resource_id = :lb_id;", {'lb_id': lb_id})

    # Delete the load balanacer
    n_session.execute(
        "DELETE FROM lbaas_loadbalancers WHERE id = :lb_id;", {'lb_id': lb_id})


def process_health_monitor(LOG, n_session, o_session, project_id,
                           pool_id, hm_id):
    hm = n_session.execute(
        "SELECT type, delay, timeout, max_retries, http_method, url_path, "
        "expected_codes, admin_state_up, provisioning_status, name, "
        "max_retries_down FROM lbaas_healthmonitors WHERE id = :hm_id AND "
        "provisioning_status != 'DELETED';", {'hm_id': hm_id}).fetchone()
    LOG.debug('Migrating health manager: %s', hm_id)

    if hm is None:
        raise Exception(_('Health monitor %s has invalid '
                          'provisioning_status.'), hm_id)

    hm_op_status = 'ONLINE' if hm[7] else 'OFFLINE'

    result = o_session.execute(
        "INSERT INTO health_monitor (id, project_id, pool_id, type, delay, "
        "timeout, fall_threshold, rise_threshold, http_method, url_path, "
        "expected_codes, enabled, provisioning_status, name, created_at, "
        "updated_at, operating_status) VALUES (:id, :project_id, :pool_id, "
        ":type, :delay, :timeout, :fall_threshold, :rise_threshold, "
        ":http_method, :url_path, :expected_codes, :enabled, "
        ":provisioning_status, :name, :created_at, :updated_at, "
        ":operating_status);",
        {'id': hm_id, 'project_id': project_id, 'pool_id': pool_id,
         'type': hm[0], 'delay': hm[1], 'timeout': hm[2],
         'fall_threshold': hm[10] if hm[10] else 3, 'rise_threshold': hm[3],
         'http_method': hm[4], 'url_path': hm[5], 'expected_codes': hm[6],
         'enabled': hm[7], 'provisioning_status': hm[8], 'name': hm[9],
         'operating_status': hm_op_status,
         'created_at': datetime.datetime.utcnow(),
         'updated_at': datetime.datetime.utcnow()})
    if result.rowcount != 1:
        raise Exception(_('Unable to create health monitor in the Octavia '
                          'database.'))


def process_session_persistence(n_session, o_session, pool_id):
    # Setup session persistence if it is configured
    sp = n_session.execute(
        "SELECT type, cookie_name FROM lbaas_sessionpersistences "
        "WHERE pool_id = :pool_id;", {'pool_id': pool_id}).fetchone()
    if sp:
        result = o_session.execute(
            "INSERT INTO session_persistence (pool_id, type, cookie_name) "
            "VALUES (:pool_id, :type, :cookie_name);",
            {'pool_id': pool_id, 'type': sp[0], 'cookie_name': sp[1]})
        if result.rowcount != 1:
            raise Exception(_('Unable to create session persistence in the '
                              'Octavia database.'))


def process_members(LOG, n_session, o_session, project_id, pool_id):
    # Handle members
    members = n_session.execute(
        "SELECT id, subnet_id, address, protocol_port, weight, "
        "admin_state_up, provisioning_status, operating_status, name FROM "
        "lbaas_members WHERE pool_id = :pool_id;",
        {'pool_id': pool_id}).fetchall()
    for member in members:
        LOG.debug('Migrating member: %s', member[0])

        if member[6] == 'DELETED':
            continue
        elif member[6] != 'ACTIVE':
            raise Exception(_('Member %s for pool %s is invalid state of %s.'),
                            member[0],
                            pool_id,
                            member[6])

        result = o_session.execute(
            "INSERT INTO member (id, pool_id, project_id, subnet_id, "
            "ip_address, protocol_port, weight, operating_status, enabled, "
            "created_at, updated_at, provisioning_status, name, backup) "
            "VALUES (:id, :pool_id, :project_id, :subnet_id, :ip_address, "
            ":protocol_port, :weight, :operating_status, :enabled, "
            ":created_at, :updated_at, :provisioning_status, :name, :backup);",
            {'id': member[0], 'pool_id': pool_id, 'project_id': project_id,
             'subnet_id': member[1], 'ip_address': member[2],
             'protocol_port': member[3], 'weight': member[4],
             'operating_status': member[7], 'enabled': member[5],
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'provisioning_status': member[6], 'name': member[8],
             'backup': False})
        if result.rowcount != 1:
            raise Exception(
                _('Unable to create member in the Octavia database.'))


def process_SNI(n_session, o_session, listener_id):
    SNIs = n_session.execute(
        "SELECT tls_container_id, position FROM lbaas_sni WHERE "
        "listener_id = :listener_id;", {'listener_id': listener_id}).fetchall()
    for SNI in SNIs:
        result = o_session.execute(
            "INSERT INTO sni (listener_id, tls_container_id, position) VALUES "
            "(:listener_id, :tls_container_id, :position);",
            {'listener_id': listener_id, 'tls_container_id': SNI[0],
             'position': SNI[1]})
        if result.rowcount != 1:
            raise Exception(_('Unable to create SNI record in the Octavia '
                              'database.'))


def process_L7policies(LOG, n_session, o_session, listener_id, project_id):
    l7policies = n_session.execute(
        "SELECT id, name, description, listener_id, action, "
        "redirect_pool_id, redirect_url, position, "
        "provisioning_status, admin_state_up FROM "
        "lbaas_l7policies WHERE listener_id = :listener_id AND "
        "provisioning_status != 'DELETED';",
        {'listener_id': listener_id}).fetchall()
    for l7policy in l7policies:
        LOG.debug('Migrating L7 policy: %s', l7policy[0])

        if l7policy[8] == 'DELETED':
            continue
        elif l7policy[8] != 'ACTIVE':
            raise Exception(_('L7 policy is invalid state of %s.'),
                            l7policy[8])

        L7p_op_status = 'ONLINE' if l7policy[9] else 'OFFLINE'

        result = o_session.execute(
            "INSERT INTO l7policy (id, name, description, listener_id, "
            "action, redirect_pool_id, redirect_url, position, enabled, "
            "provisioning_status, created_at, updated_at, project_id, "
            "operating_status) VALUES (:id, :name, :description, "
            ":listener_id, :action, :redirect_pool_id, :redirect_url, "
            ":position, :enabled, :provisioning_status, :created_at, "
            ":updated_at, :project_id, :operating_status);",
            {'id': l7policy[0], 'name': l7policy[1],
             'description': l7policy[2], 'listener_id': listener_id,
             'action': l7policy[4], 'redirect_pool_id': l7policy[5],
             'redirect_url': l7policy[6], 'position': l7policy[7],
             'enabled': l7policy[9], 'provisioning_status': l7policy[8],
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'project_id': project_id, 'operating_status': L7p_op_status})
        if result.rowcount != 1:
            raise Exception(_('Unable to create L7 policy in the Octavia '
                              'database.'))
        # Handle L7 rules
        if n_session.bind.name == 'postgresql':
            query = "SELECT id, type, compare_type, invert, key, value, provisioning_status, admin_state_up FROM lbaas_l7rules WHERE l7policy_id = :l7policy_id AND provisioning_status != 'DELETED';"
        else:
            query = "SELECT id, type, compare_type, invert, `key`, value, provisioning_status, admin_state_up FROM lbaas_l7rules WHERE l7policy_id = :l7policy_id AND provisioning_status != 'DELETED';"
        l7rules = n_session.execute(query,
                                    {'l7policy_id': l7policy[0]}).fetchall()
        for l7rule in l7rules:
            LOG.debug('Migrating L7 rule: %s', l7policy[0])

            if l7rule[6] == 'DELETED':
                continue
            elif l7rule[6] != 'ACTIVE':
                raise Exception(_('L7 rule is invalid state of %s.'),
                                l7rule[6])

            L7r_op_status = 'ONLINE' if l7rule[7] else 'OFFLINE'

            result = o_session.execute(
                "INSERT INTO l7rule (id, l7policy_id, type, compare_type, "
                "`key`, value, invert, provisioning_status, created_at, "
                "updated_at, project_id, enabled, operating_status) VALUES "
                "(:id, :l7policy_id, :type, :compare_type, :key, :value, "
                ":invert, :provisioning_status, :created_at, :updated_at, "
                ":project_id, :enabled, :operating_status);",
                {'id': l7rule[0], 'l7policy_id': l7policy[0],
                 'type': l7rule[1], 'compare_type': l7rule[2],
                 'key': l7rule[4], 'value': l7rule[5], 'invert': l7rule[3],
                 'provisioning_status': l7rule[6],
                 'created_at': datetime.datetime.utcnow(),
                 'updated_at': datetime.datetime.utcnow(),
                 'project_id': project_id, 'enabled': l7rule[7],
                 'operating_status': L7r_op_status})
            if result.rowcount != 1:
                raise Exception(_('Unable to create L7 policy in the Octavia '
                                  'database.'))


def migrate_lb(LOG, n_session_maker, o_session_maker, lb_id):
    n_session = n_session_maker(autocommit=False)
    o_session = o_session_maker(autocommit=False)

    LOG.info('Migrating load balancer: %s', lb_id)
    try:
        # Lock the load balancer in neutron DB
        result = n_session.execute(
            "UPDATE lbaas_loadbalancers SET "
            "provisioning_status = 'PENDING_UPDATE' WHERE id = :id",
            {'id': lb_id})
        if result.rowcount != 1:
            raise Exception(_('Load balancer is not provisioning_status '
                              'ACTIVE'))

        # Get the load balancer record from neutron
        n_lb = n_session.execute(
            "SELECT b.provider_name, a.project_id, a.name, a.description, "
            "a.admin_state_up, a.operating_status, a.flavor_id, "
            "a.vip_port_id, a.vip_subnet_id, a.vip_address, c.agent_id "
            "FROM lbaas_loadbalancers a "
            "JOIN providerresourceassociations b "
            "ON a.id = b.resource_id "
            "JOIN lbaas_loadbalanceragentbindings c "
            "ON a.id = c.loadbalancer_id "
            "WHERE ID = :id;",
            {'id': lb_id}).fetchone()

        # F5 lbaas specifics
        if not n_lb[0] == 'f5networks':
            raise Exception(_('Skipping {}, wrong provider {}'.format(
                lb_id, n_lb[0]
            )))

        # Migrate the port and security groups to Octavia
        vip_port = n_session.execute(
            "SELECT a.device_owner, a.project_id, b.host "
            "FROM ports a JOIN ml2_port_bindings b ON "
            "a.id = b.port_id  where id = :id;",
            {'id': n_lb[7]}).fetchone()

        # F5 lbaas specifics
        # No need to migrate ports, new f5 ml2 plugin can handle old ports
        """
        if vip_port[0] == 'network:f5lbaasv2':
            result = n_session.execute(
                "UPDATE ports SET device_owner = 'network:f5listener' WHERE "
                "id = :id;", {'id': n_lb[7]})
            if result.rowcount != 1:
                raise Exception(_('Unable to update VIP port in the neutron '
                                  'database.'))

            selfip_ports = n_session.execute(
                "SELECT a.id, a.device_owner, a.project_id, b.host, "
                "a.device_id, a.name, a.standard_attr_id FROM ports a JOIN ml2_port_bindings b ON "
                "a.id = b.port_id  WHERE name in :names AND device_owner = 'network:f5lbaasv2';",
                {'names': ['local-{}-{}'.format(hostname, n_lb[8]) for hostname in CONF.migration.bigip_hosts]}).fetchall()


            if len(selfip_ports) < 2:
                LOG.error("Found %d selfips", len(selfip_ports))
            else:
                LOG.info("Found %d selfips", len(selfip_ports))

            for selfip in selfip_ports:
                LOG.warning("{}, {}".format(selfip[3], selfip[4]))

            for selfip in selfip_ports:
                p = re.compile('local-(.*)-{}'.format(n_lb[8]), re.IGNORECASE)
                match = p.match(selfip[5])
                if match:
                    def is_bigip_active(host):
                        global bigips

                        if host not in bigips:
                            bigip = ManagementRoot(host, "admin", CONF.migration.bigip_password)

                            act = bigip.tm.cm.devices.device.load(
                                name=get_device_name(bigip), partition='Common')

                            bigips[host] = act.failoverState.lower() == 'active'
                        return bigips[host]

                    # Only migrate passive selfips
                    # TODO!!!!1111111
                    #if not is_bigip_active(match.group(1)):
                    if True:
                        if selfip[3] != CONF.migration.bigip_hosts[match.group(1)]:
                            raise Exception(_('Wrong host for VIP'))

                        LOG.info("Migrating selfip of passive device {}".format(
                            match.group(1)))
                        result = n_session.execute(
                            "UPDATE ports SET device_owner = 'network:f5selfip', "
                            "device_id = :dev_id, project_id = :proj_id WHERE "
                            "id = :id;", {'id': selfip[0],
                                          'dev_id': n_lb[7],
                                          'proj_id': CONF.migration.octavia_account_id})
                        if result.rowcount != 1:
                            raise Exception(_('Unable to update SELFIP port in the neutron '
                                              'database.'))
                        result = n_session.execute(
                            "UPDATE standardattributes SET description = :desc "
                            "WHERE id = :id;", {'id': selfip[6],
                                                'desc': match.group(1)})
                        if result.rowcount != 1:
                            raise Exception(_('Unable to update SELFIP port in the neutron '
                                              'database.'))
        """
        def get_agent_host(agent):
            global agents

            if agent not in agents:
                n_agent = n_session.execute(
                    "SELECT agent_type, host FROM agents "
                    "WHERE id = :id;",
                    {'id': agent}).fetchone()

                LOG.debug("Found agent '%s' at host '%s'",
                          n_agent[0], n_agent[1])
                agents[agent] = n_agent[1]

            return agents[agent]

        # Octavia driver load balancers are now done, next process the other
        # provider driver load balancers
        if n_lb[0] != 'octavia':
            # Create the load balancer
            result = o_session.execute(
                "INSERT INTO load_balancer (id, project_id, name, "
                "description, provisioning_status, operating_status, enabled, "
                "created_at, updated_at, provider, server_group_id) "
                "VALUES (:id, :project_id, "
                ":name, :description, :provisioning_status, "
                ":operating_status, :enabled, :created_at, :updated_at, "
                ":provider, :server_group_id);",
                {'id': lb_id, 'project_id': n_lb[1], 'name': n_lb[2],
                 'description': n_lb[3], 'provisioning_status': 'PENDING_UPDATE',
                 'operating_status': n_lb[5], 'enabled': n_lb[4],
                 'created_at': datetime.datetime.utcnow(),
                 'updated_at': datetime.datetime.utcnow(),
                 'provider': 'f5', 'server_group_id': get_agent_host(n_lb[10])})
            if result.rowcount != 1:
                raise Exception(_('Unable to create load balancer in the '
                                  'Octavia database.'))

            # Get the network ID for the VIP
            subnet = n_session.execute(
                "SELECT network_id FROM subnets WHERE id = :id;",
                {'id': n_lb[8]}).fetchone()

            # Create VIP record
            result = o_session.execute(
                "INSERT INTO vip (load_balancer_id, ip_address, port_id, "
                "subnet_id, network_id) VALUES (:lb_id, :ip_address, "
                ":port_id, :subnet_id, :network_id);",
                {'lb_id': lb_id, 'ip_address': n_lb[9], 'port_id': n_lb[7],
                 'subnet_id': n_lb[8], 'network_id': subnet[0]})
            if result.rowcount != 1:
                raise Exception(_('Unable to create VIP in the Octavia '
                                  'database.'))

            # Create pools
            pools = n_session.execute(
                "SELECT id, name, description, protocol, lb_algorithm, "
                "healthmonitor_id, admin_state_up, provisioning_status, "
                "operating_status FROM lbaas_pools WHERE loadbalancer_id "
                " = :lb_id;",
                {'lb_id': lb_id}).fetchall()
            for pool in pools:
                LOG.debug('Migrating pool: %s', pool[0])

                if pool[7] == 'DELETED':
                    continue
                elif pool[7] != 'ACTIVE':
                    raise Exception(_('Pool is invalid state of %s.'), pool[7])

                result = o_session.execute(
                    "INSERT INTO pool (id, project_id, name, description, "
                    "protocol, lb_algorithm, operating_status, enabled, "
                    "load_balancer_id, created_at, updated_at, "
                    "provisioning_status) VALUES (:id, :project_id, :name, "
                    ":description, :protocol, :lb_algorithm, "
                    ":operating_status, :enabled, :load_balancer_id,"
                    ":created_at, :updated_at, :provisioning_status);",
                    {'id': pool[0], 'project_id': n_lb[1], 'name': pool[1],
                     'description': pool[2], 'protocol': pool[3],
                     'lb_algorithm': pool[4], 'operating_status': pool[8],
                     'enabled': pool[6], 'load_balancer_id': lb_id,
                     'created_at': datetime.datetime.utcnow(),
                     'updated_at': datetime.datetime.utcnow(),
                     'provisioning_status': pool[7]})
                if result.rowcount != 1:
                    raise Exception(_('Unable to create pool in the '
                                      'Octavia database.'))

                # Create health monitor if there is one
                if pool[5] is not None:
                    process_health_monitor(LOG, n_session, o_session,
                                           n_lb[1], pool[0], pool[5])

                # Handle the session persistence records
                process_session_persistence(n_session, o_session, pool[0])

                # Handle the pool memebers
                process_members(LOG, n_session, o_session, n_lb[1], pool[0])

            lb_stats = n_session.execute(
                "SELECT bytes_in, bytes_out, active_connections, "
                "total_connections FROM lbaas_loadbalancer_statistics WHERE "
                "loadbalancer_id = :lb_id;", {'lb_id': lb_id}).fetchone()
            # Handle missing loadblaancer statistics
            if not lb_stats:
                lb_stats = (0, 0, 0, 0)
            listeners = n_session.execute(
                "SELECT id, name, description, protocol, protocol_port, "
                "connection_limit, default_pool_id, admin_state_up, "
                "provisioning_status, operating_status, "
                "default_tls_container_id FROM lbaas_listeners WHERE "
                "loadbalancer_id = :lb_id;", {'lb_id': lb_id}).fetchall()
            for listener in listeners:
                LOG.debug('Migrating listener: %s', listener[0])

                if listener[8] == 'DELETED':
                    continue
                elif listener[8] != 'ACTIVE':
                    raise Exception(_('Listener is invalid state of %s.'),
                                    listener[8])

                result = o_session.execute(
                    "INSERT INTO listener (id, project_id, name, description, "
                    "protocol, protocol_port, connection_limit, "
                    "load_balancer_id, tls_certificate_id, default_pool_id, "
                    "provisioning_status, operating_status, enabled, "
                    "created_at, updated_at) VALUES (:id, :project_id, :name, "
                    ":description, :protocol, :protocol_port, "
                    ":connection_limit, :load_balancer_id, "
                    ":tls_certificate_id, :default_pool_id, "
                    ":provisioning_status, :operating_status, :enabled, "
                    ":created_at, :updated_at);",
                    {'id': listener[0], 'project_id': n_lb[1],
                     'name': listener[1], 'description': listener[2],
                     'protocol': listener[3], 'protocol_port': listener[4],
                     'connection_limit': listener[5],
                     'load_balancer_id': lb_id,
                     'tls_certificate_id': listener[10],
                     'default_pool_id': listener[6],
                     'provisioning_status': listener[8],
                     'operating_status': listener[9], 'enabled': listener[7],
                     'created_at': datetime.datetime.utcnow(),
                     'updated_at': datetime.datetime.utcnow()})
                if result.rowcount != 1:
                    raise Exception(_('Unable to create listener in the '
                                      'Octavia database.'))

                # Convert load balancer stats to listener stats
                # This conversion may error on the low side due to
                # the division
                result = o_session.execute(
                    "INSERT INTO listener_statistics (listener_id, bytes_in, "
                    "bytes_out, active_connections, total_connections, "
                    "amphora_id, request_errors) VALUES (:listener_id, "
                    ":bytes_in, :bytes_out, :active_connections, "
                    ":total_connections, :amphora_id, :request_errors);",
                    {'listener_id': listener[0],
                     'bytes_in': int(lb_stats[0] / len(listeners)),
                     'bytes_out': int(lb_stats[1] / len(listeners)),
                     'active_connections': int(lb_stats[2] / len(listeners)),
                     'total_connections': int(lb_stats[3] / len(listeners)),
                     'amphora_id': listener[0], 'request_errors': 0})
                if result.rowcount != 1:
                    raise Exception(_('Unable to create listener statistics '
                                      'in the Octavia database.'))

                # Handle SNI certs
                process_SNI(n_session, o_session, listener[0])

                # Handle L7 policy records
                process_L7policies(LOG, n_session, o_session,
                                   listener[0], n_lb[1])

        # Delete the old neutron-lbaas records
        if (CONF.migration.delete_after_migration and not
        CONF.migration.trial_run):
            cascade_delete_neutron_lb(n_session, lb_id)

        if CONF.migration.trial_run:
            o_session.rollback()
            n_session.rollback()
            LOG.info('Simulated migration of load balancer %s successful.',
                     lb_id)
        else:
            o_session.commit()
            n_session.commit()
            LOG.info('Migration of load balancer %s successful.', lb_id)
        return 0
    except Exception as e:
        n_session.rollback()
        o_session.rollback()
        LOG.exception("Skipping load balancer %s due to: %s.", lb_id, str(e))
        return 1


def main():
    if len(sys.argv) == 1:
        print('Error: Config file must be specified.')
        print('nlbaas2octavia --config-file <filename>')
        return 1
    logging.register_options(cfg.CONF)
    cfg.CONF(args=sys.argv[1:],
             project='nlbaas2octavia',
             version='nlbaas2octavia 1.0')
    logging.set_defaults()
    logging.setup(cfg.CONF, 'nlbaas2octavia')
    LOG = logging.getLogger('nlbaas2octavia')
    CONF.log_opt_values(LOG, logging.DEBUG)

    #if (CONF.cleanup_vcmp_guest and not CONF.cleanup_vcmp_host) or (
    #        not CONF.cleanup_vcmp_guest and CONF.cleanup_vcmp_host):
    #    print('Error: both --cleanup_vcmp_guest and --cleanup_vcmp_host must be specified.')
    #    return 1

    if CONF.cleanup_vcmp_guest: # and CONF.cleanup_vcmp_host:
        guest = ManagementRoot(CONF.cleanup_vcmp_guest, "admin", CONF.migration.bigip_password)
        #vcmp = ManagementRoot(CONF.cleanup_vcmp_host, "admin", CONF.migration.bigip_password)
        cleanup_bigip(guest)
        #cleanup_vcmp(vcmp, CONF.cleanup_vcmp_guest)
        return 0

    if not CONF.all and not CONF.lb_id and not CONF.project_id and not CONF.agent_id:
        print('Error: One of --all, --lb_id, --project_id, --agent_id must be specified.')
        return 1

    if ((CONF.all and (CONF.lb_id or CONF.project_id)) or
            (CONF.lb_id and CONF.project_id)):
        print('Error: Only one of --all, --lb_id, --project_id, --agent_id allowed.')
        return 1

    neutron_context_manager = enginefacade.transaction_context()
    neutron_context_manager.configure(
        connection=CONF.migration.neutron_db_connection)
    n_session_maker = neutron_context_manager.writer.get_sessionmaker()

    octavia_context_manager = enginefacade.transaction_context()
    octavia_context_manager.configure(
        connection=CONF.migration.octavia_db_connection)
    o_session_maker = octavia_context_manager.writer.get_sessionmaker()

    LOG.info('Starting migration.')

    n_session = n_session_maker(autocommit=True)
    lb_id_list = []

    if CONF.lb_id:
        lb_id_list = [[CONF.lb_id]]
    elif CONF.project_id:
        lb_id_list = n_session.execute(
            "SELECT id FROM lbaas_loadbalancers WHERE "
            "project_id = :id AND provisioning_status != 'DELETED';",
            {'id': CONF.project_id}).fetchall()
    elif CONF.agent_id:
        lb_id_list = n_session.execute(
            "SELECT loadbalancer_id FROM lbaas_loadbalanceragentbindings WHERE "
            "agent_id = :id",
            {'id': CONF.agent_id}).fetchall()
    else:  # CONF.ALL
        lb_id_list = n_session.execute(
            "SELECT id FROM lbaas_loadbalancers WHERE "
            "provisioning_status != 'DELETED';").fetchall()

    failure_count = 0
    for lb in lb_id_list:
        failure_count += migrate_lb(LOG, n_session_maker,
                                    o_session_maker, lb[0])
    if failure_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
