#!/usr/bin/python -tt
# Project: port_selfservice_apocalypse
# Filename: frontend_utils.py
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
import yaml
import streamlit as st
import requests
import sys
import dotenv
import netmiko
import logging
import pandas as pd
from pathlib import Path
import streamlit_authenticator as stauth

from infrahub_sdk import Config, InfrahubClientSync

# Add the frontend directory to the path if needed
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.append(str(root_dir))

import utils


# Define a function to extract the last part of the interface using regex
def sort_key(interface):
    match = re.search(r"/(\d+)$", interface)  # Match the last numerical part after "/"
    if match:
        return int(match.group(1))  # Extract the matched number as an integer
    return float("inf")  # Default value if no match is found (unlikely here)


def main():
    # Use the full page instead of a narrow central column
    st.set_page_config(
        layout="wide", page_title="Self Service Fantasy", page_icon="images/favicon.ico"
    )

    # Set Session State
    if "dev_search_dict" in st.session_state:
        dev_dict = st.session_state.dev_search_dict
    else:
        dev_dict = dict()

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
            st.switch_page("UserSelfService.py")

    # Check authentication
    if not st.session_state.get("authentication_status"):
        st.error("Please login from the home page")
        st.stop()

    if st.session_state["authentication_status"]:

        st.title("Find Device")

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

        # Proceed if we have a response
        if namespace_list:

            use_findmydev = st.checkbox("Use results from Find My Device", value=True)

            if use_findmydev and dev_dict:

                st.markdown(f"Using data from Find My Device")
                ns = dev_dict["namespace"]
                sw = dev_dict["dev_sw"]
                intf = dev_dict["dev_intf"]
                # intf_config = dev_dict['intf_cfg']
                intf_vlan = dev_dict["dev_vlan"]
                vlan_name = dev_dict["vlan_name"]
                # nac_posture = dev_dict['nac_posture']

                ns_index = namespace_list.index(ns)

                if re.search("WLAN", intf):
                    st.write(f"Wireless Device. No Interface Configuration available.")
                    st.stop()

            else:
                sw = ""
                intf = ""
                # intf_config = ""
                intf_vlan = ""
                vlan_name = ""
                # nac_posture = ""
                ns_index = None

            # User interactive Selectbox to Select Namespace
            namespace = st.selectbox(
                "Select Location/Site", namespace_list, index=ns_index
            )
            if namespace:
                # Get swtiches in namespace
                sw_list_response = utils.get_switches_in_namespace(namespace)

                # Extract the list of 'hostname' values
                sw_list = [item["hostname"] for item in sw_list_response.json()]

                if use_findmydev and sw_list and sw and sw != "NOT FOUND":
                    sw_index = sw_list.index(sw)
                else:
                    sw_index = None

                sw = st.selectbox("Select Switch", sw_list, index=sw_index)
            else:
                st.warning("Please select a namespace to continue")
                st.stop()

            if sw:
                # Get switches interfaces
                intf_list_response = utils.get_sw_intf_list(sw)

                # Filter the list to include only elements with "Ethernet" in the hostname
                filtered_data = [
                    item
                    for item in intf_list_response.json()
                    if "Ethernet" in item["ifname"]
                ]
                unsorted_intf_list = [item["ifname"] for item in filtered_data]

                # TODO: Remove management and uplink interfaces
                # Filter interfaces that match the pattern
                filtered_interfaces = [
                    iface
                    for iface in unsorted_intf_list
                    if re.search(r"thernet(\d)/0/(\d{1,2})$", iface)
                ]

                # Sort the remaining interfaces numerically
                intf_list = sorted(filtered_interfaces, key=sort_key)

                if use_findmydev and intf_list and intf:
                    intf_index = intf_list.index(intf)
                else:
                    intf_index = None

                intf = st.selectbox("Select Interface", intf_list, index=intf_index)
            else:
                st.warning("Please select a switch to continue")
                st.stop()

            # Find all the vlans
            vlans_resp = utils.find_vlans_on_switch(sw)
            vlan_df = pd.DataFrame(vlans_resp.json())

            if vlan_df.empty:
                st.stop()

            vlan_df["humanTimestamp"] = vlan_df["timestamp"].apply(
                utils.unix_to_human_local
            )
            vlan_df = vlan_df.drop(columns=["timestamp"])
            vlan_df["Vlan"] = vlan_df["vlan"].astype(str).str.replace(",", "")
            vlan_df = vlan_df.drop(vlan_df[vlan_df["state"] == "unsupported"].index)
            # Allowing Vlan1 for lab - Normally this is removed in production
            # vlan_df = vlan_df.drop(vlan_df[vlan_df['Vlan'] == '1'].index)
            # This is an example of removing a vlan based on a name. For example here we remove the RSPAN vlans
            # This is based on the vlan name so your milage may vary
            vlan_df = vlan_df[
                ~vlan_df["vlanName"].str.contains("RSPAN", case=False, na=False)
            ]

            # Sort the vlans numerically
            sorted_df = vlan_df.sort_values(by="vlan")
            st.markdown(f"### Available Vlans on Switch {sw}")
            st.write(
                sorted_df[
                    ["namespace", "hostname", "Vlan", "vlanName", "state", "interfaces"]
                ]
            )

            # Concatenate vlan and name to provide friendly pick list
            sorted_df["pick_list"] = sorted_df[["Vlan", "vlanName"]].agg(
                " - ".join, axis=1
            )
            vlan_picklist = list(sorted_df["pick_list"])

            new_vlan_picked = st.selectbox("Enter New Vlan", vlan_picklist, index=None)

            if new_vlan_picked:
                newvlan_df = sorted_df[
                    sorted_df["pick_list"] == new_vlan_picked
                ].reset_index()
                # newvlan_df = newvlan_df.reindex([1])
                st.write(newvlan_df)
                new_vlan = str(newvlan_df["vlan"])
                new_vlan = newvlan_df.loc[0, "vlan"]

                # Check to make sure they are not moving it to the same vlan
                if intf_vlan == new_vlan:
                    st.error(f"This inteface is already configured for vlan {new_vlan}")
                    st.stop()

                # Check to see if the Vlan is a Critical Vlan
                current_sw_intf_details = utils.get_sw_intf_details(sw,intf)

                if current_sw_intf_details.status_code == 200:
                    if len(current_sw_intf_details.json()) == 1:
                        intf_dict = current_sw_intf_details.json()[0]
                        intf_vlan = intf_dict["vlan"]
                else:
                    st.error(f"Unable to get interface details for {intf}")
                    st.stop()

                st.info(f"Critical vlan check - Current Interface Vlan ({intf_vlan})")

                critical_vlan_dict = utils.check_critical_vlan_infrahub(intf_vlan)
                if critical_vlan_dict["is_critical_vlan"]:
                    st.error(f"Interface is on a critical vlan (Vlan {intf_vlan})! {critical_vlan_dict['role']}. Self service not allowed.")
                    st.stop()
                else:
                    st.markdown(f"*Vlan {intf_vlan} is not a critical vlan*")

                st.info(f"Critical vlan check - New Interface Vlan ({new_vlan})")
                critical_vlan_dict = utils.check_critical_vlan_infrahub(new_vlan)

                if critical_vlan_dict["is_critical_vlan"]:
                    st.error(f"Vlan {new_vlan} is a critical vlan! {critical_vlan_dict['role']}. Self service not allowed.")
                    st.stop()
                else:
                    st.markdown(f"*Vlan {new_vlan} is not a critical vlan*")

                st.info("Skipping Spanning Tree Check")

                reason = st.text_input("Reason for Change:", value="")

                st.warning(
                    f"Please confirm Vlan interface change on interface {intf} from vlan {intf_vlan} {vlan_name} to NEW vlan {new_vlan_picked}"
                )

                confirm = st.selectbox("Confirm Change", ["Confirm", "Cancel"], index=1)

                if reason and confirm == "Confirm":  # and stp_check:

                    button_label = f"Change Port Vlan"
                    with st.form(key="CHANGE_PORT_VLAN"):

                        change_vlan = st.form_submit_button(label=button_label)

                        if change_vlan:

                            # Service Now Change Control

                            cr_response = utils.create_std_cr_snow(short_desc=f"Cisco DevNet User Self Service Fantasy Change Port Vlan  {sw} {intf} to vlan {new_vlan}")

                            if cr_response:
                                st.write(cr_response.json()["result"]["task_effective_number"])
                            else:
                                st.write("Change Request Not Created")
                            cfg_update = utils.intf_vlan_update_cfg(intf, new_vlan)
                            st.write(
                                f"Sending the following configuration update to {sw} {intf} and saving configuration to device:"
                            )
                            for line in cfg_update:
                                st.text(line)

                            # Get Credentials
                            uname, pwd = utils.get_credentials()

                            # Enable logging
                            logging.basicConfig(
                                filename="netmiko_session.log",  # Log to this file
                                level=logging.DEBUG,  # Log debug and higher
                                format="%(asctime)s %(levelname)s: %(message)s",
                                datefmt="%Y-%m-%d %H:%M:%S",
                            )

                            # Create a logger object
                            logger = logging.getLogger("netmiko")

                            device = {
                                "device_type": "cisco_ios",
                                "host": sw,
                                "username": uname,
                                "password": pwd,
                                "session_log": "netmiko_session.log",  # This enables session logging
                            }

                            conn = netmiko.ConnectHandler(**device)

                            # Get the interface number and subtract 1
                            port = int(re.search(r"/(\d+)$", intf).group(1))
                            show_int_status = conn.send_command(
                                f"show interface status", use_textfsm=True
                            )
                            st.info("Current State of Port:")
                            st.write(show_int_status[port - 1])

                            if conn:
                                # Create connection object with environment variables
                                # Send configuration commands
                                st.info(
                                    f"Executing configuration commands to move interface into vlan {new_vlan}..."
                                )
                                result = conn.send_config_set(cfg_update)

                                st.write("Configuration output:")
                                st.text(result)

                                st.info("Verifying Port Configuration...")
                                show_int_status = conn.send_command(
                                    f"show interface status", use_textfsm=True
                                )
                                st.write(show_int_status[port - 1])

                                st.success("Port configuration changed!")

                                st.text("- Interface is on new vlan")

                                st.success("Port configuration Verified!")

                                st.info(
                                    "IP Addressing Method not determined so no further testing is possible. Please verify system is functional."
                                )
                                conn.disconnect()


# Standard call to the main() function.
if __name__ == "__main__":
    main()
