#!/usr/bin/env python

import click
from f5.bigip import ManagementRoot

bigips = {}
agents = {}

def get_device_name(bigip):
    devices = bigip.tm.cm.devices.get_collection()
    for device in devices:
        if device.selfDevice == 'true':
            return device.name

    return None

@click.command()
@click.argument('hostname')
@click.option('--username', default='admin', help='bigip username (default: "admin")')
@click.option('--password', prompt=True, help='bigip password (omit to be prompted)', hide_input=True)
def cleanup_vcmp_guest(hostname, username, password):
    bigip = ManagementRoot(hostname, username, password)
    print("Cleaning up {}".format(bigip.hostname))
    act = bigip.tm.cm.devices.device.load(
        name=get_device_name(bigip), partition='Common')
    active = act.failoverState.lower() == 'active'

    if active:
        raise Exception('BigIP is active, aborting cleanup')

    ltm_types = [
        bigip.tm.ltm.virtuals,
        bigip.tm.ltm.virtual_address_s,
        bigip.tm.ltm.policys,
        bigip.tm.ltm.pools,
        bigip.tm.ltm.monitor.https,
        bigip.tm.ltm.monitor.https_s,
        bigip.tm.ltm.monitor.tcps,
        bigip.tm.ltm.monitor.gateway_icmps,
        bigip.tm.ltm.monitor.externals,
        bigip.tm.ltm.monitor.tcp_half_opens,
        bigip.tm.ltm.profile.client_ssls,
        bigip.tm.ltm.profile.server_ssls,
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


if __name__ == "__main__":
    cleanup_vcmp_guest()
