#!/usr/bin/env python

# Copyright: (c) 2020, Yiğit Can Başalma <yigit.basalma@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

from pyzabbix import ZabbixAPI
from datetime import datetime

import traceback
import re

APPLICATION_INFO = {}
ACTUAL_HOSTNAME = ""
FQDN = ""
VISIBLE_NAME = ""
IP_ADDRESS = ""
DEFAULTS = {}
Z_API = None
RESULT = dict(
    changed=False,
    error="",
    output="",
    interfaces=dict(agent=False, jmx=False, snmp=False, ipmi=False)
)


def dummy_for_tags(*args):
    return args[-1]


def get_interfaces():
    interfaces = []
    for template in APPLICATION_INFO["templates"]:
        if re.search(".*snmp.*", template, re.IGNORECASE):
            if not RESULT["interfaces"].get("snmp"):
                RESULT["interfaces"]["snmp"] = True

                interfaces.append(
                    dict(type=2, main=1, useip=1, dns="", ip=f"{IP_ADDRESS}",
                         port=DEFAULTS["snmp"]["port"],
                         details=dict(version=3, securityname=f"{{$SECURITY_NAME}}", securitylevel=2, authprotocol=1,
                                      authpassphrase=f"{{$AUTH_PASSPHRASE}}", privpassphrase=f"{{$PRIV_PASSPHRASE}}",
                                      bulk=0, privprotocol=DEFAULTS["snmp"]["priv_protocol"]))
                )
        elif re.search(".*jmx.*", template, re.IGNORECASE):
            if not RESULT["interfaces"].get("jmx"):
                RESULT["interfaces"]["jmx"] = True

                interfaces.append(
                    dict(type=4, main=1, useip=1, dns=FQDN, ip=f"{IP_ADDRESS}",
                         port=DEFAULTS["jmx"]["port"])
                )
        elif re.search(".*ipmi.*", template, re.IGNORECASE):
            if not RESULT["interfaces"].get("ipmi"):
                RESULT["interfaces"]["ipmi"] = True

                interfaces.append(
                    dict(type=3, main=1, useip=1, dns=FQDN, ip=f"{IP_ADDRESS}",
                         port=DEFAULTS["ipmi"]["port"])
                )
        else:
            if not RESULT["interfaces"].get("agent"):
                RESULT["interfaces"]["agent"] = True

                interfaces.append(
                    dict(type=1, main=1, useip=1, dns=FQDN, ip=f"{IP_ADDRESS}",
                         port=DEFAULTS["agent"]["port"])
                )

    return interfaces


def find_application_info(applications_info):
    for application in applications_info:
        if application.get("rules"):
            for rule in application["rules"]:
                for pattern in rule["patterns"]:
                    if re.search(pattern, ACTUAL_HOSTNAME) and IP_ADDRESS not in application.get("exclude_ip", []):
                        application["teams"] = rule["teams"]
                        return application
                    if re.search(pattern, IP_ADDRESS):
                        application["teams"] = rule["teams"]
                        return application
    return applications_info[0]  # Return "Other Servers" application


def zabbix_create_host_group(name):
    argument_dict = {
        "name": f"{name}"
    }
    # noinspection PyTypeChecker,PyUnresolvedReferences
    return Z_API.do_request(
        "hostgroup.create",
        params=argument_dict
    )


def zabbix_get_template_id(name):
    argument_dict = dict(filter=dict(name=name))
    # noinspection PyTypeChecker,PyUnresolvedReferences
    results = Z_API.do_request(
        "template.get",
        params=argument_dict
    )

    return results["result"][0]["templateid"]


def zabbix_get_proxy_id(name):
    argument_dict = dict(filter=dict(host=name))
    # noinspection PyTypeChecker,PyUnresolvedReferences
    results = Z_API.do_request(
        "proxy.get",
        params=argument_dict
    )

    return results["result"][0]["proxyid"]


def zabbix_get_host_group_id(name):
    argument_dict = dict(filter=dict(name=name))
    # noinspection PyTypeChecker,PyUnresolvedReferences
    results = Z_API.do_request(
        "hostgroup.get",
        params=argument_dict
    )

    if not results["result"]:
        new_host_group = zabbix_create_host_group(name=name)
        return new_host_group["result"]["groupids"][0]

    return results["result"][0]["groupid"]


def zabbix_get_host_id(name):
    argument_dict = dict(filter=dict(host=name))
    # noinspection PyTypeChecker,PyUnresolvedReferences
    results = Z_API.do_request(
        "host.get",
        params=argument_dict
    )

    if not results["result"]:
        return

    return results["result"][0]["hostid"]


def zabbix_get_hosts_by_ip(ip):
    argument_dict = dict(filter=dict(ip=ip))
    # noinspection PyTypeChecker,PyUnresolvedReferences
    results = Z_API.do_request(
        "host.get",
        params=argument_dict
    )

    if not results["result"]:
        return

    return results["result"]


def zabbix_create_host(host):
    # noinspection PyTypeChecker,PyUnresolvedReferences
    Z_API.do_request(
        "host.create",
        params=host
    )


def zabbix_update_host(host):
    # noinspection PyTypeChecker,PyUnresolvedReferences
    Z_API.do_request(
        "host.update",
        params=host
    )


def zabbix_delete_host(_id):
    # noinspection PyTypeChecker,PyUnresolvedReferences
    Z_API.do_request(
        "host.delete",
        params=[
            _id
        ]
    )


def get_environment(_):
    return dict(d="test", q="qa", s="staging", p="production").get(ACTUAL_HOSTNAME[-1],
                                                                   APPLICATION_INFO.get("environment", "unknown"))


def get_teams(_):
    return APPLICATION_INFO["teams"]


def get_application_type(_):
    return APPLICATION_INFO["name"]


def run(**kwargs):
    # Variables
    zabbix_server_name = kwargs["zabbix_server"]
    host_tags = kwargs["host_tags"]
    update = kwargs["update"]
    remove_before_update = kwargs["remove_before_update"]

    new_host = dict(
        host=f"{FQDN}",
        name=f"{VISIBLE_NAME}",
        description=f"This host created by auto register playbook at {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        interfaces=get_interfaces(),
        groups=[
            dict(groupid=zabbix_get_host_group_id(name=group))
            for group in APPLICATION_INFO["groups"]
        ],
        tags=[
            dict(tag=k, value=globals().get(v, "dummy_for_tags")(v))
            for k, v in host_tags.items()
        ] if host_tags else [],
        macros=[
            dict(macro=f"{{${k.upper()}}}", value=v)
            for k, v in APPLICATION_INFO["macros"].items()
        ] if APPLICATION_INFO.get("macros") else [],
        templates=[
            dict(templateid=zabbix_get_template_id(name=template))
            for template in APPLICATION_INFO["templates"]
        ] if APPLICATION_INFO.get("templates") else [],
        inventory_mode=1  # Automatic inventory mode
    )

    RESULT["output"] = f"{new_host}"

    if zabbix_server_name:
        new_host["proxy_hostid"] = zabbix_get_proxy_id(name=zabbix_server_name)

    # Create host
    host_id = zabbix_get_host_id(name=FQDN)

    # Duplication control
    dup_hosts = zabbix_get_hosts_by_ip(ip=IP_ADDRESS)

    if dup_hosts:
        for host in dup_hosts:
            if host["host"] != FQDN:
                zabbix_delete_host(_id=host["hostid"])

    if host_id:
        if update:
            del new_host["interfaces"]
            del new_host["description"]

            new_host["hostid"] = host_id

            zabbix_update_host(host=new_host)

            return

        if remove_before_update:
            zabbix_delete_host(_id=host_id)
        else:
            return

    zabbix_create_host(host=new_host)


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        zabbix_api=dict(type="str", required=True),
        zabbix_username=dict(type="str", required=True),
        zabbix_password=dict(type="str", required=True, no_log=True),
        target_ip=dict(type="str", required=True),
        target_dns=dict(type="str"),
        zabbix_server=dict(type="str", default=""),
        applications_info=dict(type="list", required=True),
        host_tags=dict(type="dict", default={}),
        defaults=dict(type="dict", required=True),
        service_name=dict(type="str", default="agent"),
        snmp_priv_protocol=dict(type="int"),
        update=dict(type="bool", default=False),
        remove_before_update=dict(type="bool", default=False)
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Globals
    global FQDN
    FQDN = module.params["target_dns"].strip()

    global IP_ADDRESS
    IP_ADDRESS = module.params["target_ip"].strip()

    global VISIBLE_NAME
    VISIBLE_NAME = f"{FQDN}".replace("_", "-").replace(" ", "-")
    if module.params["service_name"] in ("snmp", ):
        VISIBLE_NAME = f"{FQDN}-{IP_ADDRESS}".replace("_", "-").replace(" ", "-")
        FQDN = f"{FQDN}-{IP_ADDRESS}".replace("_", "-").replace(" ", "-")

    global ACTUAL_HOSTNAME
    ACTUAL_HOSTNAME = FQDN.split(".")[0]

    global APPLICATION_INFO
    APPLICATION_INFO = find_application_info(applications_info=module.params["applications_info"])

    global DEFAULTS
    DEFAULTS = module.params["defaults"]
    DEFAULTS["snmp"]["priv_protocol"] = module.params["snmp_priv_protocol"]

    global Z_API
    Z_API = ZabbixAPI(server=f"{module.params['zabbix_api']}/api_jsonrpc.php")
    Z_API.login(user=module.params["zabbix_username"], password=module.params["zabbix_password"])

    # Defaults
    if APPLICATION_INFO["name"] in ("Others", ):
        APPLICATION_INFO["templates"] = DEFAULTS[module.params["service_name"]]["templates"]
        APPLICATION_INFO["groups"] = DEFAULTS[module.params["service_name"]]["groups"]
        APPLICATION_INFO["teams"] = DEFAULTS[module.params["service_name"]]["teams"]

    if not APPLICATION_INFO.get("macros"):
        APPLICATION_INFO["macros"] = {}

    # Add system macros
    APPLICATION_INFO["macros"]["responsible"] = APPLICATION_INFO["teams"]

    # noinspection PyBroadException
    try:
        run(**module.params)
    except Exception:
        RESULT["failed"] = True
        RESULT["error"] = traceback.format_exc()

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**RESULT)


def main():
    run_module()


if __name__ == "__main__":
    main()
