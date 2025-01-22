#!/usr/bin/python -tt
# Project: port_selfservice_apocalypse
# Filename: 1_Find_My_Device.py
# claudiadeluna
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "1/4/25"
__copyright__ = "Copyright (c) 2025 Claudia"
__license__ = "Python"

import os
import re
import pandas as pd
import streamlit as st
import requests
import yaml
import sys
from pathlib import Path
from typing import Dict, Any
import streamlit_authenticator as stauth

# Add the frontend directory to the path if needed
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.append(str(root_dir))

import utils


def main():

    st.set_page_config(
        layout="wide", page_title="Self Service Fantasy", page_icon="images/favicon.ico"
    )

    # Load configuration file
    with open("config/config.yaml") as file:
        config = yaml.load(file, Loader=yaml.SafeLoader)

    authenticator = stauth.Authenticate(
        config["credentials"],
        config["cookie"]["name"],
        config["cookie"]["key"],
        config["cookie"]["expiry_days"],
    )

    if (
        "authentication_status" not in st.session_state
        or not st.session_state["authentication_status"]
    ):
        if not st.session_state["authentication_status"]:
            st.switch_page("SelfServiceApocalypseHome.py")

    # Check authentication
    if not st.session_state.get("authentication_status"):
        st.error("Please login from the home page")
        st.stop()

    if st.session_state["authentication_status"]:
        st.title("Find Device")

        # st.write(st.session_state['sq_access_token'])

        # Set Device Search Dictionary
        if "dev_search_dict" not in st.session_state:
            st.session_state.dev_search_dict = dict()

        # Display navigation image in sidebar
        randomf = utils.get_random_file(
            dir_path=os.path.join(root_dir, "images"), ext=".jpeg"
        )
        if randomf:
            try:
                st.sidebar.image(randomf, use_container_width=True)
            except Exception as e:
                st.sidebar.error(f"Error loading image: {randomf}")
                st.sidebar.error(f"Error details: {str(e)}")
        else:
            st.sidebar.write("No images found")

        if not os.getenv("SQ_API_TOKEN"):
            st.error(
                "SuzieQ Token cannot be found in an environment variable. "
                "Make sure your .env file has been updated with a valid Bearer Token for the SuzieQ REST API!"
            )

        # Trick to get a unique list of namespaces for the pull down
        namespace_list = utils.get_namespace_list()

        # Proceed if we have a response from SuzieQ and we have a list of namespaces/locations
        if namespace_list:

            # include_history_bool = st.checkbox("Include History", value=True)
            include_history_bool = False

            # User interactive Selectbox to Select Namespace
            namespace = st.selectbox("Select Location", namespace_list, index=None)

            dev_input = st.text_input(
                "Enter FQDN, IP, or MAC of device you would like to locate on the network",
                value="",
            )

            button_label = f"Find Device {dev_input}"
            with st.form(key="DEVICE_LOOKUP"):

                lookup_option = st.form_submit_button(label=button_label)

                # -------
                res = list()
                dev_ip = ""
                dev_fqdn = ""
                dev_mac = ""
                dev_vlan = ""
                dev_critical_vlan = False
                dev_sw = ""
                dev_intf = ""
                dev_timestamp = ""
                dev_is_alive = False
                ping_result = False
                is_wlan = False

                # Initialize dev_search_dict which has all the info on the MAC
                dev_search_dict = dict()

                if lookup_option and (dev_input is not None and namespace):

                    st.markdown(
                        f"### Searching Site {namespace} for Device {dev_input}"
                    )

                    # ----
                    # Figure out what was provided in dev_input
                    input_type_dict = utils.check_input(dev_input, namespace)
                    # st.write(input_type_dict)

                    # if not input_type_dict['valid_ip_mac_input']:
                    #     st.warning(f"Missing information. Device not currently on the network. All information will be historical over the last 3 months.")
                    #     # st.write(input_type_dict)

                    if input_type_dict["dev_fqdn"]:
                        dev_fqdn = input_type_dict["dev_fqdn"]

                    if input_type_dict["dev_ip"]:
                        addr = input_type_dict["dev_ip"]
                    elif input_type_dict["dev_mac"]:
                        addr = str(input_type_dict["dev_mac"])
                    else:
                        addr = False
                    # st.write(f"addr is {addr}")

                    if not addr:
                        st.error(f"Cannot resolve {dev_fqdn} to an IP or a MAC")

                    st.info("Skipping Device Tracking check")
                    # Try dtrack with view=latest
                    # res_addr = utils.check_dtrack(addr, namespace, debug=False)
                    # st.write(res_dtrack.json())

                    # dtrack with view=latest did not return anything
                    # if not res_addr.json():
                    #     # Try dtrack with view=all
                    #     res_addr = utils.check_dtrack(addr, namespace, view="all", debug=False)

                    # dtrack with view=all did not return anything
                    # if we got a MAC address, lets look for the mac
                    if input_type_dict["dev_mac"]:
                        # This returns a dict

                        res_addr = utils.find_mac(
                            input_type_dict["dev_mac"],
                            namespace,
                            start_time="1 day ago",
                        )
                        # st.write(res_addr)
                    if type(res_addr) == dict:
                        # st.write(res_addr)
                        addr_dict = res_addr
                        dev_mac = addr_dict["original_mac"]
                        dev_ip = addr_dict["ip_from_mac"]
                        dev_vlan = addr_dict["vlan"]
                        dev_sw = addr_dict["hn"]
                        dev_intf = addr_dict["oif"]
                        dev_type = addr_dict["flag"]
                        dev_timestamp = utils.unix_to_human_local(
                            addr_dict["timestamp"]
                        )
                    else:
                        if len(res_addr.json()) == 1:
                            # st.write(res_addr.json())
                            addr_dict = res_addr.json()[0]
                            dev_mac = addr_dict["macaddr"]
                            dev_ip = addr_dict["ipAddress"]
                            dev_vlan = addr_dict["vlan"]
                            dev_sw = addr_dict["hostname"]
                            dev_intf = addr_dict["ifname"]
                            dev_type = addr_dict["type"]
                            dev_timestamp = utils.unix_to_human_local(
                                addr_dict["timestamp"]
                            )
                        elif len(res_addr.json()) > 1:
                            st.error("Multiple records found!")
                            st.write(res_addr.json())
                            st.stop()
                        else:
                            st.error("No records found!")
                            # st.write(res_addr.json())
                            st.stop()

                        if re.search("dhcp", dev_type):
                            st.info(
                                f"Device is configured to obtain its IP Address via DHCP"
                            )
                        else:
                            st.info(f"Device IP Address may be hardcoded")

                    # Show Vlan and Vlan Name
                    vlan_name = ""
                    _, vlan_rsp = utils.find_vlan_on_switch(dev_vlan, dev_sw)

                    if vlan_rsp.json():
                        vlan_name = vlan_rsp.json()[0]["vlanName"]
                    st.info(f"Device is on vlan **{dev_vlan}** ***{vlan_name}***")
                    if re.search(r"3\d\d\d", str(dev_vlan)):
                        is_wlan = True
                        st.info(f"📶 Device {dev_input} is Wireless.")

                    # Check to see if the Vlan is a Critical Vlan
                    st.info("Skipping critical vlan check")
                    # if dev_vlan:
                    #     crit_vlan_res = utils.check_critical_vlan(dev_vlan, namespace, debug=False)
                    #     # st.write(crit_vlan_res.json())
                    #     critical_vlan_list = list()
                    #     if crit_vlan_res.json():
                    #         # st.write(crit_vlan_res.json())
                    #         for line in crit_vlan_res.json():
                    #             critical_vlan_list.append(line['critical_vlan'])
                    #     if dev_vlan in critical_vlan_list:
                    #         # st.write(critical_vlan_list)
                    #         st.error(
                    #             f"Vlan {dev_vlan} is a critical vlan for the site. Self service changes are not supported. Please follow the normal process for any changes.")

                    # else:
                    #     pass

                    if dev_ip and not is_wlan:
                        ping_result = utils.icmplib_ping(dev_ip)
                    # st.write(ping_result.is_alive)

                    dev_oui = utils.get_oui(dev_mac)

                    if dev_fqdn:
                        dev_fqdn_msg = (
                            f"Found FQDN **{dev_fqdn}** in DNS for IP  {dev_ip}"
                        )
                    else:
                        dev_fqdn_msg = f"Unable to find DNS record for IP {dev_ip}"
                    st.info(f"DNS: {dev_fqdn_msg}")

                    if dev_mac:
                        st.info(f"MAC Address: **{dev_mac}** of type **{dev_oui}**")
                        if not is_wlan:
                            st.info(
                                f"Network Location: MAC Address **{dev_mac}** on switch **{dev_sw}** and interface **{dev_intf}**"
                            )

                            # Show Interface Configuration
                            st.info(f"Current Interface Configuration")
                            intf_cfg = utils.get_intf_config(dev_sw, dev_intf)
                            st.write(intf_cfg.json())
                    else:
                        st.error("Unable to find MAC on Network!")

                    if ping_result:
                        if ping_result.is_alive:
                            st.success(f"Device Pings!")
                            st.write(ping_result)
                            st.info(f"Device Last Seen: Now")
                        else:
                            st.warning(f"Device does not Ping!")
                            st.info(f"Device Last Seen: {dev_timestamp}")
                    else:
                        st.warning(f"Unable to ping {dev_ip}")

                    # Check for neighbors on port
                    nei_bool, nei_res = utils.find_lldp_nei_on_intf(dev_sw, dev_intf)
                    if nei_bool and not is_wlan:
                        st.error("Unexpected devices (CDP/LLDP) on interface!")
                        nei_df = pd.DataFrame(nei_res.json())
                        nei_df = nei_df.drop(columns=["timestamp"])
                        st.write(nei_df)
                    else:
                        if not is_wlan:
                            st.success(
                                f"No unexpected CDP/LLDP devices on switch {dev_sw} interface {dev_intf}"
                            )

                    # Get the configuration of the interface
                    # intf_res = utils.get_intf_config(dev_sw, dev_intf)
                    # if intf_res.json():
                    #     intf_cfg = intf_res.json()[0]["config"]
                    # else:
                    #     intf_cfg = ""
                    # st.write(intf_res.json())
                    # st.write(intf_cfg)

                    # Check ISE Posture
                    st.info("Skipping NAC Posture check")

                    st.info("Skipping Device History check")
                    if include_history_bool:

                        st.markdown("---")

                        res_allip = utils.check_dtrack(
                            dev_ip, namespace, view="all", debug=False
                        )
                        st.write(res_allip.json())

                        if dev_ip and res_allip.json():

                            # res_allip = utils.check_dtrack(dev_ip, namespace, view="all", debug=False)
                            # st.write(res_allip.json())
                            dfipall = pd.DataFrame(res_allip.json())
                            dfipall["lastStateChange"] = dfipall["timestamp"].apply(
                                utils.unix_to_human_local
                            )
                            dfipall = dfipall.drop(columns=["timestamp"])
                            st.markdown(f"### Device IP History (Last 3 Months)")
                            st.write(dfipall)
                        else:
                            if dev_ip:
                                # Look up ARP
                                arp_res = utils.check_arp_ip(
                                    dev_ip, namespace, view="all"
                                )
                                st.markdown(
                                    f"### Device ARP IP History (Last 3 Months)"
                                )
                                st.write(pd.DataFrame(arp_res.json()))

                        if dev_mac:

                            if type(res_addr) == dict:
                                dfmacall = pd.DataFrame(res_addr["user_int_lod"])
                                if dfmacall.empty:
                                    # st.warning(f"MAC {dev_mac} not found")
                                    mac_res = utils.check_arp_mac(
                                        dev_mac, namespace, view="all"
                                    )
                                    st.write(pd.DataFrame(mac_res.json()))
                                else:
                                    dfmacall["lastStateChange"] = dfmacall[
                                        "timestamp"
                                    ].apply(utils.unix_to_human_local)
                                    dfmacall.sort_values(
                                        by=["lastStateChange"], inplace=True
                                    )
                                    dfmacall = dfmacall.drop(columns=["timestamp"])
                                    st.markdown(
                                        f"### Device MAC History (Last 3 Months)"
                                    )
                                    st.write(dfmacall)
                            else:
                                res_allmac = utils.check_dtrack(
                                    dev_mac, namespace, view="all"
                                )
                                dfmacall = pd.DataFrame(res_allmac.json())
                                dfmacall["lastStateChange"] = dfmacall[
                                    "timestamp"
                                ].apply(utils.unix_to_human_local)
                                sfmacall = dfmacall["timestamp"].sort_values()
                                dfmacall = dfmacall.drop(columns=["timestamp"])
                                st.markdown(f"### Device MAC History (Last 3 Months)")
                                st.write(dfmacall)

                    # Find if device uses DHCP
                    st.info("Skipping check to see if device uses DHCP")
                    # dhcp_res, dev_uses_dhcp_bool = utils.check_dhcp_mac(dev_mac, namespace)
                    # st.write(dhcp_res.json())

                    # Build
                    if ping_result:
                        dev_is_alive = ping_result.is_alive

                    dev_search_dict.update(
                        {
                            "namespace_list": namespace_list,
                            "namespace": namespace,
                            "dev_input": dev_input,
                            "dev_ip": dev_ip,
                            "dev_mac": dev_mac,
                            "dev_fqdn": dev_fqdn,
                            "dev_is_alive": dev_is_alive,
                            "dev_oui": dev_oui,
                            "nei_bool": nei_bool,
                            "nei_res": nei_res,
                            "dev_sw": dev_sw,
                            "dev_intf": dev_intf,
                            # "intf_cfg": intf_cfg,
                            # "dev_uses_dhcp_bool": dev_uses_dhcp_bool,
                            # "dhcp_res": dhcp_res,
                            # "intf_access": intf_access,
                            # "intf_trunk": intf_trunk,
                            "dev_vlan": dev_vlan,
                            "vlan_name": vlan_name,
                            # "nac_posture": nac_posture,
                            "dev_dtrack_type": dev_type,
                            "dev_dtrack_timestamp": dev_timestamp,
                        }
                    )

                    st.session_state.dev_search_dict = dev_search_dict

                else:
                    st.error(
                        f"Make sure to Select a Location and Enter and IP, MAC, or FQDN"
                    )
        # Add helpful examples
        with st.expander("See Examples"):
            st.markdown(
                """
            ### Valid Input Examples:
            - **IP Address**: 
                - 192.168.1.1
                - 203.0.113.51 (Laptop)
                - 203.0.113.52 (Camera)
                - 198.51.100.50 (NUC Mini)
            - **FQDN**: server1.uwaco.net
            - **MAC Address**: 
                - AA:BB:CC:DD:EE:FF
                - AA-BB-CC-DD-EE-FF
                - AABBCCDDEEFF
                - 0080.f083.2f08 (Camera)
                - 00e0.4c36.019e (Laptop)
                - e0:51:d8:15:71:22 (NUC Mini)

            """
            )


# Standard call to the main() function.
if __name__ == "__main__":
    main()
