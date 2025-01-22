#!/usr/bin/python -tt
# Project: self_service
# Filename: utils.py
# claudiadeluna
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "1/19/25"
__copyright__ = "Copyright (c) 2023 Claudia"
__license__ = "Python"


import dotenv
import os
import re
import sys
import netaddr
import datetime
import time
import pytz
import requests
import streamlit as st
import pandas as pd
import socket
import random
import pathlib
import icmplib

from urllib import parse

# Disable  Unverified HTTPS request is being made to host messages
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def get_ip(fqdn):
    """
    This method returns the IP for a given FQDN
    """
    try:
        data = socket.gethostbyname(fqdn)
        host = repr(data)
        return host
    except Exception:
        # fail gracefully
        return False


def get_host(ip):
    """
    This method returns the 'True Host' name for a
    given IP address
    """
    try:
        data = socket.gethostbyaddr(ip)
        host = repr(data[0])
        return host
    except Exception:
        # fail gracefully
        return False


# From utils_logical_networking
def get_numeric_part_of_intf(intf, debug=False):
    """
    For a given interface
    TwoGigabitEthernet1/0/43    return 1/0/43
    GigabitEthernet1/2/1        return 1/2/1
    TwentyFiveGigE1/0/1         return 1/0/1
    Ethernet1/0/2               retur n1/0/2
    Gi2/0/12                    return 2/0/12
    2/0/12
    FastEthernet1/23
    GigabitEthernet0/9
    GigabitEthernet0/12
    """

    numeric_intf = ""

    intf_num = re.search(r"\d(\/\d)?\/\d{1,2}", intf)

    if intf_num:
        numeric_intf = intf_num.group()

    return numeric_intf


def try_strptime(s, fmts=["%d-%b-%y", "%m/%d/%Y"]):
    for fmt in fmts:
        try:
            return datetime.datetime.strptime(s, fmt)
        except:
            continue
    return None  # or reraise the ValueError if no format matched, if you prefer


def convert_string_to_time(date_string, timezone):
    """
    https://stackoverflow.com/questions/466345/convert-string-jun-1-2005-133pm-into-datetime
    :param date_string:
    :param timezone:
    :return:
    """

    date_time_obj = datetime.datetime.strptime(date_string[:26], "%Y-%m-%d %H:%M:%S.%f")
    date_time_obj_timezone = pytz.timezone(timezone).localize(date_time_obj)

    return date_time_obj_timezone


def calculate_execution_time(startt, endt):

    execution_time = endt - startt

    # Calculate minutes and seconds
    total_seconds = execution_time.total_seconds()
    minutes = int(total_seconds // 60)
    seconds = total_seconds % 60

    return minutes, seconds


def mac_format(mac_addr, dialect):
    # Dialect =
    # mac_cisco, mac_unix, mac_bare, mac_unix_expanded, mac_eui48
    # 0123.4567.890a, 1:23:45:67:89:a, 01234567890A, 01:23:45:67:89:0a, 01-23-45-67-89-0A
    # 'CC46D6367BF4'
    # WLC MAC cc:46:d6:37:e0:d0
    # WLC AP Default Name APcc46.d636.7d70

    mac = ""

    try:
        mac = netaddr.EUI(mac_addr)
    except Exception:
        st.error("ERROR: MAC Address {} lookup failed with exception:".format(mac_addr))
        for e in sys.exc_info():
            st.error(e)

    dialect = dialect.lower()

    if dialect == "mac_cisco":
        mac.dialect = netaddr.mac_cisco
    elif dialect == "mac_unix":
        mac.dialect = netaddr.mac_unix
    elif dialect == "mac_bare":
        mac.dialect = netaddr.mac_bare
    elif dialect == "mac_unix_expanded":
        mac.dialect = netaddr.mac_unix_expanded
    elif dialect == "mac_eui48":
        mac.dialect = netaddr.mac_eui48
    else:
        st.error("Invalid Dialect")

    return mac


def create_autodetect_devobj(dev, auth_timeout=20, session_log=False, debug=False):
    """
        dev = {
        'device_type': 'cisco_nxos',
        'ip' : 'sbx-nxos-mgmt.cisco.com',
        'username' : user,
        'password' : pwd,
        'secret' : sec,
        'port' : 8181,
        "fast_cli": False,
    }
    """

    dotenv.load_dotenv()
    dev_obj = {}

    if "NET_USR" in os.environ.keys():
        usr = os.environ["NET_USR"]
    else:
        usr = ""
    if "NET_PWD" in os.environ.keys():
        pwd = os.environ["NET_PWD"]
    else:
        pwd = ""

    core_dev = r"(ar|as|ds|cs){1}\d\d"
    dev_obj.update({"ip": dev.strip()})
    dev_obj.update({"username": usr.strip()})
    dev_obj.update({"password": pwd.strip()})
    dev_obj.update({"secret": pwd.strip()})
    dev_obj.update({"port": 22})
    dev_obj.update({"auth_timeout": auth_timeout})
    dev_obj.update({"device_type": "autodetect"})
    if session_log:
        dev_obj.update({"session_log": "netmiko_session_log.txt"})

    return dev_obj


def os_is():
    # Determine OS to set ping arguments
    local_os = ""
    if sys.platform == "linux" or sys.platform == "linux2":
        local_os = "linux"
    elif sys.platform == "darwin":
        local_os = "linux"
    elif sys.platform == "win32":
        local_os = "win"

    return local_os


def icmplib_ping(ipx):
    """
    Send a ping to a device to determine if it is reachable

    Args:
        ipx (str): The IP address of the device

    Returns:
        A named tuple with the following elements:
            * reply: True if the device responded, False if it did not
            * rtt: The time it took for the device to respond, in seconds
    """
    return icmplib.ping(ipx, count=10, interval=0.2, privileged=False)


def load_sq_api_key():
    """
    Load the SuzieQ API Key from Environment Variable
    """
    dotenv.load_dotenv()


def try_sq_rest_call(uri_path, url_options, debug=False):
    """
    SuzieQ API REST Call

    """

    # UWACO Lab
    API_ACCESS_TOKEN = os.getenv("SQ_API_TOKEN")
    API_ENDPOINT = "10.1.10.141"
    API_PORT = "8000"

    payload = "\r\n"

    url = f"http://{API_ENDPOINT}:{API_PORT}{uri_path}?{url_options}&access_token={API_ACCESS_TOKEN}"

    if debug:
        st.write(url)

    # Send API request, return as JSON
    response = dict()

    try:
        # response = requests.get(url).json()
        # st.write(url)
        response = requests.get(url, verify=False)

    except Exception as e:
        print(e)
        st.error(
            "Connection to SuzieQ REST API Failed.  Please confirm the REST API is running!"
        )
        st.text(e)
        response = False

    if debug:
        st.write(f"Response is {response}")
        if response.json():
            st.write(response.json())
        else:
            st.write("No data returned for REST call")

    # Returns full response object
    return response


def find_mac(macx, namespacex, start_time="3 months ago"):
    """
    Function to find a given MAC and all of its attributes
    - switch
    - interface
    - vlan

    :param macx:
    :return:
    """
    debug = False
    result = dict()
    # Put into MAC format in case its not
    mac_eui = str(netaddr.EUI(macx))
    mac = str(mac_eui).lower().strip()
    mac_url_encoded = parse.quote(mac)

    query_string = "oif.str.contains('Ethernet')"
    query_string_url_encoded = parse.quote(query_string)

    oif_string = "!~.+channel.+"
    oif_url_encoded = parse.quote(oif_string)

    start_time_url_encoded = parse.quote(start_time)

    columns = "default"
    col_list = [
        "active",
        "namespace",
        "hostname",
        "oif",
        "macaddr",
        "vlan",
        "flags",
        "timestamp",
    ]
    columns_str = "".join([f"&columns={i}" for i in col_list])

    columns_list_str = columns

    view = "latest"
    URI_PATH = "/api/v2/mac/show"
    URL_OPTIONS = f"view={view}&namespace={namespacex}{columns_str}&macaddr={mac_url_encoded}&query_str={query_string_url_encoded}"

    if macx:
        # Start with result as "NOT FOUND" and then process MAC via SuzieQ REST Call
        msg = "NOT FOUND"
        on_net_now = False
        valid_switch = True

        # Send API request, return as JSON, using view=latests
        sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=False)

        # --------------------------------------------------------- VIEW ALL ---------------------------------------------------
        if not sq_api_response.json() or not valid_switch:
            # Look for view=all
            # oif.str.contains('Ethernet')
            # https://localhost:8000/api/v2/mac/show?format=68%3A05%3Aca%3A12%3A7a%3Af9&view=latest&columns=default&query_str=oif.str.contains%28%27Ethernet%27%29&reverse=false&include_deleted=false

            view = "all"
            URL_OPTIONS = f"view={view}&namespace={namespacex}{columns_str}&macaddr={mac_url_encoded}&start_time={start_time_url_encoded}&oif={oif_url_encoded}&reverse=false&include_deleted=false"
            sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

        # Now find the Interface
        # Function process_mac_ports takes the API response and processes it to find all the relevant MAC attributes
        # returns a dictionary of attributes
        mac_result_dict = process_mac_port(sq_api_response, macx, start_time=start_time)

        if not mac_result_dict["result"]:
            mac_result_dict["result"] = msg

        # Add On Network Now to dictionary
        mac_result_dict.update({"on_net_now": on_net_now})
        mac_result_dict.update({"start_time": start_time})

        result = mac_result_dict

        if debug:
            st.write("RETURNING mac_result_dict from process_mac_port")

    return result


def process_mac_port(api_response, macx, start_time="6 months ago"):
    """_summary_
    Process the mac port SuzieQ Query to find the interface the MAC is on
    Args:
        api_response (_type_): _description_
    """

    # Put into MAC format in case its not
    macx = str(netaddr.EUI(macx))
    mac_eui = str(netaddr.EUI(macx))
    mac = str(mac_eui).lower().strip()
    mac_dict = dict()

    hn = "NOT FOUND"
    vlan = 0
    flag = "NOT FOUND"
    timestamp = ""
    oif = ""
    ip_from_mac = ""
    result = ""
    multi_user_intf = False
    found_dict = dict()
    if re.search("nan", mac, re.IGNORECASE):
        mac = ""
        result = "BLANK MAC"
        st.write(f"MAC QA: BLANK MAC - MAC not provided in PPB")

    # List of Dictionaries that are not Port channels
    filtered_response_all = list()

    # st.write(f"in process_mac_port with response {api_response}")
    if api_response and mac:

        # The most unambiguous case is a user port x/0/x that is static due to ISE
        for line in api_response.json():

            if re.search(r"spare", line["hostname"], re.IGNORECASE):
                continue

            if (
                re.search(r"(\d\/)?(0|1)\/\d", line["oif"])
                or line["flags"] == "wcclient"
            ):
                if line not in filtered_response_all:
                    filtered_response_all.append(line)

            # Catches Catalyst wired NAC Authenticated (Cisco)
            if re.search(r"\d\/(0|1)\/\d", line["oif"]) and line["flags"] == "static":
                oif = line["oif"]
                hn = line["hostname"]
                vlan = line["vlan"]
                flag = line["flags"]
                timestamp = line["timestamp"]
                found_dict = line
                result = "FOUND"

            # Catches older Catalyst IOS switches wired and NAC Authenticated
            elif re.search(r"net0\/\d", line["oif"]) and line["flags"] == "static":
                oif = line["oif"]
                hn = line["hostname"]
                vlan = line["vlan"]
                flag = line["flags"]
                timestamp = line["timestamp"]
                found_dict = line
                result = "FOUND"

            # This should catch wireless clients (SQ Enterprise Only)
            elif line["flags"] == "wcclient":
                oif = line["oif"]
                hn = line["hostname"]
                vlan = line["vlan"]
                flag = line["flags"]
                timestamp = line["timestamp"]
                found_dict = line
                result = "FOUND"

        # Check for user port but flag dynamic!!
        if result == "NOT FOUND":
            for line in api_response:
                # st.write(line)
                if (
                    re.search(r"\d\/(0|1)\/\d", line["oif"])
                    and line["flags"] == "dynamic"
                ):
                    oif = line["oif"]
                    hn = line["hostname"]
                    vlan = line["vlan"]
                    flag = line["flags"]
                    timestamp = line["timestamp"]
                    found_dict = line
                    result = "FOUND"

        # If there are no standard user ports look for CX ports
        if result == "NOT FOUND":
            for line in api_response:
                # st.write(line)
                if re.search(r"0\/\d", line["oif"]):
                    oif = line["oif"]
                    hn = line["hostname"]
                    vlan = line["vlan"]
                    flag = line["flags"]
                    timestamp = line["timestamp"]
                    found_dict = line
                    result = "FOUND"

        # If there are no standard, dynamic, or CX ports look see what we got
        if result == "NOT FOUND" and len(api_response) == 1:
            line = api_response[0]
            oif = line["oif"]
            hn = line["hostname"]
            vlan = line["vlan"]
            flag = line["flags"]
            timestamp = line["timestamp"]
            found_dict = line
            result = "FOUND"

    # At this point there are likely multiple user interfaces with "dynamic"
    # Take each entry in filtered_response which is a lod and try to find the one without an lldp neighbor
    #
    # Deduplicate Filtered Response
    # https://stackoverflow.com/questions/71873504/create-unique-list-of-dictionaries-using-dict-keys
    # they need to be tuples, otherwise you wouldn't be able to cast the list to a set
    # st.write(filtered_response_all)
    dict_items = [tuple(d.items()) for d in filtered_response_all]
    filtered_response_dedup = set(dict_items)
    filtered_response = [dict(i) for i in filtered_response_dedup]

    # Look for the interface without LLDP neighbors
    if not result:
        for line in filtered_response:
            has_lldp_neighbor = find_lldp_nei_on_intf(line["hostname"], line["oif"])

            # If the interface does not have LLDP Neighbors set switch and interface of device
            # and break out of the loop
            if not has_lldp_neighbor:
                oif = line["oif"]
                hn = line["hostname"]
                vlan = line["vlan"]
                flag = line["flags"]
                timestamp = line["timestamp"]
                if len(filtered_response) == 1:
                    multi_user_intf = False
                elif len(filtered_response) > 1:
                    multi_user_intf = True
                result = "FOUND"
                break

    # Last Resort is likely a user interface WITH LLDP neighbor like an Industrial switch
    if not result:
        if len(filtered_response) == 1:
            for line in filtered_response:
                oif = line["oif"]
                hn = line["hostname"]
                vlan = line["vlan"]
                flag = line["flags"]
                timestamp = line["timestamp"]
                multi_user_intf = True
                result = "FOUND with LLDP Neighbor"

    mac_dict.update(
        {
            "original_mac": macx,
            "lower_mac": mac,
            "normalized_mac": "",
            "oif": oif,
            "hn": hn,
            "vlan": vlan,
            "flag": flag,
            "timestamp": timestamp,
            "human_local_timestamp": unix_to_human_local(timestamp),
            "matched_result_row_dict": found_dict,
            "ip_from_mac": find_ip_from_mac(mac),
            "result": result,
            "user_int_lod": filtered_response,
            "multi_user_intf": multi_user_intf,
        }
    )

    return mac_dict


def find_ip_from_mac(macx):
    """_summary_
        Find the IP Associated to the MAC in the PPB
    [
      {
        "namespace": "",
        "hostname": "",
        "ipAddress": "172.21.225.197",
        "oif": "Vlan224",
        "macaddr": "00:e0:8d:05:15:41",
        "state": "reachable",
        "remote": false,
        "timestamp": 1665320285972
      }
    ]
        Args:
            mac (_type_): _description_
    """

    mac = mac_format(macx, "mac_unix_expanded")

    URI_PATH = "/api/v2/arpnd/show"
    URL_OPTIONS = f"view=latest&columns=default&macaddr={mac}"

    if mac:

        found_ip = ""
        sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)
        if sq_api_response.json():

            if type(sq_api_response.json()) == list:
                if "ipAddress" in sq_api_response.json()[0].keys():
                    # for now return the first entry
                    found_ip = sq_api_response.json()[0]["ipAddress"]
                else:
                    st.error(
                        f"No Results: ARP search for MAC {mac} Response {sq_api_response} URL {URL_OPTIONS}"
                    )
    else:
        found_ip = "BLANK MAC"

    return found_ip


def find_lldp_nei_on_intf(sw, intf):
    # Given a switch and interface see if there is an LLDP neighobr on that interface
    # If there is an LLD neighbor its not a user interface
    # Return True

    URI_PATH = "/api/v2/lldp/show"
    URL_OPTIONS = f"&columns=default&view=latest&hostname={sw}&ifname={intf}"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    if sq_api_response.json():
        lldp_nei_bool = True
    else:
        lldp_nei_bool = False

    return lldp_nei_bool, sq_api_response


def get_intf_config(sw, intf, view="latest"):
    """
    API call to get the configuration of an interface

    https://localhost:8000/api/v2/devconfig/show?hostname=na-us-240-2c-as01&view=latest
    &columns=default&section=interface%20TenGigabitEthernet1%2F0%2F48&reverse=false&include_deleted=false

    """

    section_encoded = parse.quote(f"interface {intf}")

    URI_PATH = "/api/v2/devconfig/show"
    URL_OPTIONS = (
        f"&columns=default&view={view}&hostname={sw}&section={section_encoded}"
    )

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    if sq_api_response.json():
        lldp_nei_bool = True
    else:
        lldp_nei_bool = False

    return sq_api_response


def check_dhcp_mac(macx, namespacex, view="latest", add_dtrack="true"):
    """
    https://localhost:8000/api/v2/dhcp/show?view=latest&namespace=240_Menominee
    &columns=default&macaddr=60%3A95%3A32%3A0e%3A86%3A3c&add_dtrack=true&include_deleted=false&reverse=false

    """

    device_uses_dhcp = False

    URI_PATH = "/api/v2/dhcp/show"
    URL_OPTIONS = f"&columns=default&view={view}&namespace={namespacex}&macaddr={macx}&add_dtrack={add_dtrack}&reverse=false&include_deleted=false"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    if sq_api_response.json():
        if sq_api_response.json()[0]["type"] == "dhcp-snooping":
            device_uses_dhcp = True
    else:
        device_uses_dhcp = False

    return sq_api_response, device_uses_dhcp


def check_dhcp_ip(ipx, namespacex, view="latest", add_dtrack="true"):
    """
    https://localhost:8000/api/v2/dhcp/show?view=latest&namespace=240_Menominee
    &columns=default&macaddr=60%3A95%3A32%3A0e%3A86%3A3c&add_dtrack=true&include_deleted=false&reverse=false

    """

    URI_PATH = "/api/v2/dhcp/show"
    URL_OPTIONS = f"&columns=default&view={view}&namespace={namespacex}&ipAddress={ipx}&add_dtrack={add_dtrack}&reverse=false&include_deleted=false"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    # st.write(sq_api_response.json())

    if sq_api_response.json():
        lldp_nei_bool = True
    else:
        lldp_nei_bool = False

    return sq_api_response


def check_arp_ip(ipx, namespacex, view="latest"):
    """
    Check the ARP Table by IP
    """

    URI_PATH = "/api/v2/arpnd/show"
    URL_OPTIONS = f"view={view}&namespace={namespacex}&columns=default&ipAddress={ipx}"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    return sq_api_response


def check_arp_mac(macx, namespacex, view="latest"):
    """
    Check the ARP Table by MAC
    """

    URI_PATH = "/api/v2/arpnd/show"
    URL_OPTIONS = f"view={view}&namespace={namespacex}&columns=default&macaddr={macx}"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    return sq_api_response


def check_dtrack(addrx, namespacex, view="latest", debug=False):
    """
    https://localhost:8000/api/v2/dtrack/show?view=latest&namespace=232_Malaga&columns=%2A
    &ipAddress=10.82.189.149&reverse=false&include_deleted=false

    https://localhost:8000/api/v2/dtrack/show?view=latest&namespace=232_Malaga&columns=%2A
    &macaddr=b4%3Ab0%3A24%3A80%3Ab3%3A2c&reverse=false&include_deleted=false

    https://localhost:8000/api/v2/dtrack/show?view=latest&namespace=240_Menominee&columns=%2A
    &ipAddress=10.233.95.86&ifname=~.%2BE.%2A&reverse=false&include_deleted=false

    https://localhost:8000/api/v2/dtrack/show?view=all
    &columns=%2A&macaddr=ac%3A1a%3A3d%3A9f%3A51%3A90&reverse=false&include_deleted=false

    https://localhost:8000/api/v2/dtrack/show?view=all
    &columns=%2A&macaddr=ac%3A1a%3A3d%3A9f%3A51%3A90&reverse=false&include_deleted=false

    https://localhost:8000/api/v2/dtrack/show?view=all
    &namespace=1137_Tianjin&columns=%2A&macaddr=ac%3A1a%3A3d%3A9f%3A51%3A90&reverse=false&include_deleted=false


    Example output from API
            [
        {
            "namespace": "a",
            "hostname": "1",
            "ipAddress": "1",
            "macaddr": "b4:b0:24:80:b3:2c",
            "type": "dhcpv4",
            "vlan": 7,
            "ifname": "GigabitEthernet2/0/44",
            "timestamp": 1724332552992,
            "flags": "0025",
            "state": "reachable",
            "oui": "TP-Link Corporation Limited",
            "fqdn": "",
            "active": true
        }
        ]

    """
    ip_address = False
    mac_address = False

    # Check if its IP or MAC
    # If its an IP
    if re.search(
        r"\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        addrx,
    ):
        ip_address = True
        addrx = addrx.replace("'", "")

    # is it a MAC
    elif re.search(
        r"(([a-fA-F0-9]{2}-){5}[a-fA-F0-9]{2}|([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}|([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})?",
        addrx,
        re.IGNORECASE,
    ):
        mac_address = True
        mac_url_encoded = parse.quote(addrx)

    URI_PATH = "/api/v2/dtrack/show"

    if ip_address and not mac_address:
        URL_OPTIONS = f"&columns=default&view={view}&namespace={namespacex}&ipAddress={addrx}&ifname=~.%2BE.%2A&reverse=false&include_deleted=false"
    elif mac_address and not ip_address:
        URL_OPTIONS = f"view={view}&namespace={namespacex}&macaddr={mac_url_encoded}&ifname=~.%2BE.%2A&reverse=false&include_deleted=false"
    else:
        st.error("Can't be both IP and MAC! Something has gone horribly wrong!")
        st.stop()

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=False)

    if debug:
        st.info(f"Debugging in check_dtrack")
        st.write(f"ip address is {ip_address}")
        st.write(
            f"mac address is {mac_address} and url encoded mac is {mac_url_encoded}"
        )
        st.write(f"URL OPTIONS {URL_OPTIONS}")
        st.write(sq_api_response.json())

    return sq_api_response


def find_mac_from_ip(ip, ns):

    dev_mac = False
    # Open Source - does not have endpoint locator so moved to get IP from ARP by the MAC
    endpt_resp = check_arp_ip(ip, ns)

    # if endpt_resp:
    mac_list = list()
    for ldict in endpt_resp.json():
        mac_list.append(ldict["macaddr"])

    uniq_mac_list = list(set(mac_list))

    if len(uniq_mac_list) == 1:
        dev_mac = uniq_mac_list[0]
    elif len(uniq_mac_list) == 0:
        st.error(f"No MAC found for IP {ip} ")
        st.stop()
    else:
        st.error(f"Multiple MACs {uniq_mac_list} found for IP {ip}")
        st.stop()

    return dev_mac


def check_input(dev_input, namespacex, domain="uwaco.com"):
    """
    Given an input that could be an IP, MAC, or FQDN try to figure out what it is

    """

    input_provided = ""
    valid_ip_mac_input = False
    result_dict = dict()
    dev_ip = ""
    dev_mac = ""
    dev_fqdn = ""

    # Is it a FQDN
    if re.search(domain, dev_input):
        # FQDN was provided
        # Lookup FQDN and Get IP
        dev_ip = get_ip(dev_input)
        dev_fqdn = dev_input.strip().lower()
        st.write(f"FQDN provided, resolves to IP {dev_ip}")
        # ping_result = utils.icmplib_ping(dev_input)

        # Find the MAC from the IP
        # dev_mac = find_mac_from_ip(dev_ip, namespacex)
        if dev_ip:
            input_provided = "FQDN"

    # is it an IP
    elif re.search(
        r"\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        dev_input,
    ):
        dev_ip = dev_input.strip().lower()
        dev_fqdn = get_host(dev_input)
        st.write(f"IP Address provided, resolves to FQDN {dev_fqdn}")
        # ping_result = utils.icmplib_ping(dev_input)

        # Find the MAC from the IP
        dev_mac = find_mac_from_ip(dev_ip, namespacex)
        if dev_ip:
            input_provided = "IPAddress"

    # is it a MAC
    elif re.search(
        r"(([a-fA-F0-9]{2}-){5}[a-fA-F0-9]{2}|([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}|([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})?",
        dev_input,
        re.IGNORECASE,
    ):
        dev_ip = find_ip_from_mac(dev_input)
        dev_mac = mac_format(dev_input, "mac_unix_expanded")
        dev_fqdn = get_host(dev_ip)
        st.write(f"MAC Address provided, resolves to IP {dev_ip}")
        # ping_result = utils.icmplib_ping(dev_ip)
        if dev_mac:
            input_provided = "MACAddress"

    # is it a mac without all leading zeros
    elif re.search(r"(\.|\-|:)", dev_input):
        dev_mac = mac_format(dev_input, "mac_unix_expanded")
        if dev_mac:
            dev_ip = find_ip_from_mac(dev_input)
            dev_fqdn = get_host(dev_ip)
            st.write(f"MAC Address {dev_input} provided, resolves to IP {dev_ip}")
            # ping_result = utils.icmplib_ping(dev_ip)
            input_provided = "MACAddress"
        else:
            st.error(f"Invalid mac format")

    else:
        st.error(
            f"Input for Device is not recognized!  Please enter Fully qualified Domain name, IP Address, or MAC Address."
        )

    if dev_ip and dev_mac:
        valid_ip_mac_input = True

    result_dict.update(
        {
            "input_value": dev_input,
            "input_provided": input_provided,
            "valid_ip_mac_input": valid_ip_mac_input,
            "dev_ip": dev_ip,
            "dev_mac": dev_mac,
            "dev_fqdn": dev_fqdn,
        }
    )

    return result_dict


def get_oui(mac):
    """
    Get OUT from netaddr....good if you don't have internet access.
    :param mac:
    :return:
    """

    try:
        maco = netaddr.EUI(mac)
        macf = maco.oui.registration().org
    except netaddr.core.NotRegisteredError:
        macf = "Not available"
    except netaddr.core.AddrFormatError:
        macf = "00:00:00:00:00:00"
        print(f"Incomplete")

    return macf


def name_split(x):
    """
    Used to create a new Dataframe column with a hostname without a domain
    :param x:
    :return:
    """
    # Check for Blank Domain Values
    hostname_only = ""
    if not pd.isna(x):
        # Split on first "." only
        if type(x) == str:
            hostname_only = x.split(".", 1)[0]
        else:
            hostname_only = f"{str(x)} Not a String"
    else:
        hostname_only = "EMPTY Not a Value NAN"

    return hostname_only


def domain_split(x):
    """
    Used to create a new Dataframe column with a domain or missing
    :param x:
    :return:
    """
    # st.write(pd.isna(x))
    # Check for Blank Domain Values
    if not pd.isna(x):
        if type(x) == str:
            x_split = x.split(".", 1)
            if len(x_split) == 2:
                xdomain = x_split[1]
            elif len(x_split) == 1:
                xdomain = "NO DOMAIN PROVIDED"
            else:
                xdomain = "ERROR"
        else:
            xdomain = f"Not a string value {str(x)}"
    else:
        xdomain = "EMPTY Not a Value NAN"

    return xdomain


def get_namespace_list():
    # Initialize
    namespace_list = list()

    # Trick to get a unique list of namespaces for the pull down
    # http://10.1.10.141:8000/api/v2/device/show?view=latest&columns=default&access_token=496157e6e869ef7f3d6ecb24a6f6d847b224ee4f
    # http://10.1.10.141:8000/api/v2/device/unique?view=latest&columns=default&access_token=496157e6e869ef7f3d6ecb24a6f6d847b224ee4f
    # http://10.1.10.141:8000/api/v2/device/unique?view=latest&columns=namespace&access_token=496157e6e869ef7f3d6ecb24a6f6d847b224ee4f
    URI_PATH = "/api/v2/device/unique"
    URL_OPTIONS = f"columns=namespace&view=latest"
    ns_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    # Create a list of namespaces from the list of dictionaries
    if ns_response.status_code == 200:
        if ns_response.json():
            namespace_list = [line["namespace"] for line in ns_response.json()]
    else:
        st.error(f"Problem with accessing SuzieQ REST API")
        st.write(f"OK Response: {ns_response.ok}")
        st.write(f"Status Code: {ns_response.status_code}")
        st.write(f"Reason: {ns_response.reason}")
        st.write(ns_response.json())

    # Initialize a new dictionary that will have a location index
    # and the value will be the namespace name
    ns_dict = dict()
    ns_dict = {f"{i + 1:03d}": loc for i, loc in enumerate(namespace_list)}

    # Sort the dictionary by its keys and put into a new dict
    sorted_ns_dict = dict(sorted(ns_dict.items()))
    # Extract the sorted values for the namespace_list
    sorted_ns_list = list(sorted_ns_dict.values())

    return sorted_ns_list


def unix_to_human_local(ts):
    human_local_time = ""
    if ts:
        unix_timestamp = int(ts / 1000)
        utc_time = time.gmtime(unix_timestamp)
        local_time = time.localtime(unix_timestamp)
        human_local_time = f"{time.strftime('%Y-%m-%d %H:%M:%S', local_time)}"
    return human_local_time


def find_vlan_on_switch(vlanx, switch):
    vlan_configured_on_sw = False

    URI_PATH = "/api/v2/vlan/show"
    URL_OPTIONS = f"hostname={switch}&view=latest&columns=default&vlan={vlanx}"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=False)

    if not re.search("NOT FOUND", switch):
        if sq_api_response.json():
            vlan_configured_on_sw = True
        else:
            st.error(f"Vlan {vlanx} is NOT configured on switch {switch}")
    else:
        st.error("Switch is NOT FOUND")

    return vlan_configured_on_sw, sq_api_response


def find_vlans_on_switch(switch):

    URI_PATH = "/api/v2/vlan/show"
    URL_OPTIONS = f"hostname={switch}&view=latest&columns=default"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    if not re.search("NOT FOUND", switch):
        pass
    else:
        st.error("Switch is NOT FOUND")

    return sq_api_response


def get_vlans_in_namespace(ns):
    """
    Get all the vlans on all the swtiches in namespace
    # https://localhost:8000/api/v2/vlan/show?view=latest&namespace=240_Menominee&columns=default&reverse=false&include_deleted=false
    """

    URI_PATH = "/api/v2/vlan/show"
    URL_OPTIONS = f"namespace={ns}&view=latest&columns=default&reverse=false&include_deleted=false"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    return sq_api_response


def build_vlan_df(resp):

    # Find all the vlans

    vlan_df = pd.DataFrame(resp.json())

    vlan_df["humanTimestamp"] = vlan_df["timestamp"].apply(unix_to_human_local)
    vlan_df = vlan_df.drop(columns=["timestamp"])
    vlan_df["Vlan"] = vlan_df["vlan"].astype(str).str.replace(",", "")
    vlan_df = vlan_df.drop(vlan_df[vlan_df["state"] == "unsupported"].index)
    vlan_df = vlan_df.drop(vlan_df[vlan_df["Vlan"] == "1"].index)
    vlan_df = vlan_df.drop(vlan_df[vlan_df["Vlan"] == "888"].index)
    vlan_df = vlan_df[~vlan_df["vlanName"].str.contains("RSPAN", case=False, na=False)]

    sorted_df = vlan_df.sort_values(by="vlan")

    # Concatenate vlan and name to provide friendly pick list
    sorted_df["pick_list"] = sorted_df[["Vlan", "vlanName"]].agg(" - ".join, axis=1)

    return sorted_df


def check_stp_switch(vlanx, switch):
    """
    [
        0:{
            "namespace":""
            "hostname":""
            "vlan":70
            "port":"Port-channel7"
            "bridgeId":"5049.21dc.5900"
            "bridgePrio":"33184"
            "portRole":"root"
            "portState":"forwarding"
            "portCost":2000
            "portPrio":128
            "portType":"network"
            "portLinkType":"p2p"
            "mlagType":""
            "isRoot":false
            "errorType":""
            "timestamp":1697829617607
        }
    ]
    """

    # Set Boolean indicating the provided vlan has root on an interface
    vlan_has_stp_root = False

    URI_PATH = "/api/v2/stp/show"
    URL_OPTIONS = f"hostname={switch}&view=latest&columns=default&vlan={vlanx}&portType=network&reverse=false&include_deleted=false"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=False)

    response_json = sq_api_response.json()
    root_lod = list()

    if not re.search("NOT FOUND", switch):
        if sq_api_response.ok:

            for line in response_json:
                if line["portRole"] == "root":
                    vlan_has_stp_root = True
                    root_lod.append(line)
                    break

            if not vlan_has_stp_root:
                st.error(
                    f"Vlan {vlanx} has {len(response_json)} interfaces in STP for vlan {vlanx} but no root interfaces on {switch}"
                )
        else:
            st.error(f"NO RESULTS from API Call")
            st.text(response_json)
    else:
        st.error("Switch is NOT FOUND")

    return vlan_has_stp_root, root_lod


def check_critical_vlan(vlanx, nsx, debug=False):
    """
    Check that a given vlanx is not in the critical_vlan extdb.
    If it is a critical vlan then it cannot be changed via self service.

    Return True if it is a crticial vlan and False if not

    """

    # https://localhost:8000/api/v2/extdb/show?ext_table=critical_vlans&view=latest&namespace=1420_Dubai
    # &columns=default&reverse=false&include_deleted=false&show_exceptions=false

    URI_PATH = "/api/v2/extdb/show"

    URL_OPTIONS = f"ext_table=critical_vlans&view=latest&namespace={nsx}&columns=default&reverse=false&include_deleted=false&show_exceptions=false"

    # Send API request, return as JSON
    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=debug)
    if debug:
        st.write(f"check_critical_vlan passed {vlanx} and namespace {nsx}")
        st.write(URI_PATH)
        st.write(URL_OPTIONS)

    return sq_api_response


def get_switches_in_namespace(ns, filter=None):

    URI_PATH = "/api/v2/device/show"
    URL_OPTIONS = f"namespace={ns}&view=latest&columns=default"

    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS)

    if filter:
        # filter based on provided filter
        filtered_resp_lod = list()
        for ldict in sq_api_response.json():
            if re.search(filter, ldict["hostname"]):
                filtered_resp_lod.append(ldict)
        return filtered_resp_lod
    else:
        return sq_api_response


def get_sw_intf_list(swx, debug=False):
    """
    Get a list of all the interfaces on a switch

    https://localhost:8000/api/v2/interface/unique?hostname=na-us-240-2a-as01
    &view=latest&columns=ifname&ignore_missing_peer=false&reverse=false&include_deleted=false
    """
    URI_PATH = "/api/v2/interface/unique"

    URL_OPTIONS = f"hostname={swx}&view=latest&columns=ifname&ignore_missing_peer=false&reverse=false&include_deleted=false"

    # Send API request, return as JSON
    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=False)
    if debug:
        st.write(f"get_sw_intf_list passed {swx} and debug {debug}")
        st.write(URI_PATH)
        st.write(URL_OPTIONS)

    return sq_api_response


def get_sw_intf_details(swx, intfx, debug=False):
    """
    Get a list of the details for a specific interface

    https://localhost:8000/api/v2/interface/show?hostname=na-us-240-2a-as01
    &view=latest&columns=%2A&ifname=GigabitEthernet1%2F0%2F16&ignore_missing_peer=false&reverse=false&include_deleted=false

    """
    URI_PATH = "/api/v2/interface/show"

    URL_OPTIONS = f"hostname={swx}&ifname={intfx}&view=latest&columns=%2A&i&ignore_missing_peer=false&reverse=false&include_deleted=false"

    # Send API request, return as JSON
    sq_api_response = try_sq_rest_call(URI_PATH, URL_OPTIONS, debug=False)
    if debug:
        st.write(f"get_sw_intf_details passed {swx} and debug {debug}")
        st.write(URI_PATH)
        st.write(URL_OPTIONS)

    return sq_api_response


def get_credentials():
    """
    Get credentials from environment variables.

    Returns:
        tuple: (username, password)

    Raises:
        ValueError: If required environment variables are not set
    """

    # Load ENV variables
    dotenv.load_dotenv()

    username = os.getenv("NET_USR")
    password = os.getenv("NET_PWD")

    # Validation to ensure variables exist
    if not all([username, password]):
        st.error("Required environment variables NET_USR and NET_PWD must be set")
        st.stop()

    return username, password


def st_download_file(file_name, file_data_list, button_text="Download File"):
    """
    This function will take a list of content, turn it into a new line separated string,
    and make it avaialble for download via a Stramlit page using the st.download_button
    """
    if file_data_list:
        # Turn msg_lines into a string with new lines
        lines_str = "\n".join(file_data_list)

        with open(file_name, "w") as f:
            st.download_button(
                f"📥 {button_text}",
                data=lines_str,
                file_name=file_name,
            )  # Defaults to 'text/plain'


def find_my_dev(dev_input, namespace, include_history_bool=True):

    # -------
    res = list()
    dev_ip = ""
    dev_fqdn = ""
    dev_mac = ""
    dev_vlan = ""
    dev_sw = ""
    dev_intf = ""
    dev_type = ""
    dev_timestamp = ""
    dev_is_alive = False
    ping_result = False
    is_wlan = False

    # Initialize dev_search_dict which has all the info on the MAC
    dev_search_dict = dict()
    dev_search_dict.update(
        {
            # "namespace_list": namespace_list,
            "namespace": namespace,
            "dev_input": dev_input,
            "dev_ip": dev_ip,
            "dev_mac": dev_mac,
            "dev_fqdn": dev_fqdn,
            "dev_is_alive": dev_is_alive,
            "dev_oui": "",
            "nei_bool": False,
            "nei_res": list(),
            "dev_sw": dev_sw,
            "dev_intf": dev_intf,
            "intf_cfg": "",
            "dev_uses_dhcp_bool": False,
            "dhcp_res": list(),
            "intf_access": "",
            "intf_trunk": "",
            "dev_vlan": dev_vlan,
            "vlan_name": "",
            "nac_posture": "",
            "dev_dtrack_type": dev_type,
            "dev_dtrack_timestamp": dev_timestamp,
        }
    )

    if dev_input is not None and namespace:

        st.markdown(f"### Searching Site {namespace} for Device {dev_input}")

        # ----
        # Figure out what was provided in dev_input
        input_type_dict = check_input(dev_input, namespace)

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
            return dev_search_dict

        res_addr = check_dtrack(addr, namespace, debug=False)
        # st.write(res_dtrack.json())

        # dtrack with view=latest did not return anything
        if not res_addr.json():
            # Try dtrack with view=all
            res_addr = check_dtrack(addr, namespace, view="all", debug=False)

        # dtrack with view=all did not return anything
        # if we got a MAC address, lets look for the mac
        if not res_addr.json() and input_type_dict["dev_mac"]:
            # This returns a dict
            res_addr = find_mac(
                input_type_dict["dev_mac"], namespace, start_time="3 months ago"
            )

        if type(res_addr) == dict:
            # st.write(res_addr)
            addr_dict = res_addr
            dev_mac = addr_dict["original_mac"]
            dev_ip = addr_dict["ip_from_mac"]
            dev_vlan = addr_dict["vlan"]
            dev_sw = addr_dict["hn"]
            dev_intf = addr_dict["oif"]
            dev_type = addr_dict["flag"]
            dev_timestamp = unix_to_human_local(addr_dict["timestamp"])
        else:
            if len(res_addr.json()) == 1:
                addr_dict = res_addr.json()[0]
                dev_mac = addr_dict["macaddr"]
                dev_ip = addr_dict["ipAddress"]
                dev_vlan = addr_dict["vlan"]
                dev_sw = addr_dict["hostname"]
                dev_intf = addr_dict["ifname"]
                dev_type = addr_dict["type"]
                dev_timestamp = unix_to_human_local(addr_dict["timestamp"])
            elif len(res_addr.json()) > 1:
                st.error("Multiple records found!")
                st.write(res_addr.json())

            else:
                st.error("No records found!")
                # st.write(res_addr.json())

            if dev_type:
                if re.search("dhcp", dev_type):
                    st.info(f"Device is configured to obtain its IP Address via DHCP")
                else:
                    st.info(f"Device IP Address may be hardcoded")

        # Show Vlan and Vlan Name
        vlan_name = ""
        _, vlan_rsp = find_vlan_on_switch(dev_vlan, dev_sw)

        if vlan_rsp.json():
            vlan_name = vlan_rsp.json()[0]["vlanName"]
        st.info(f"Device is on vlan **{dev_vlan}** ***{vlan_name}***")
        if re.search(r"3\d\d\d", str(dev_vlan)):
            is_wlan = True
            st.info(f"📶 Device {dev_input} is Wireless.")

        if dev_ip and not is_wlan:
            ping_result = icmplib_ping(dev_ip)
        # st.write(ping_result.is_alive)

        dev_oui = get_oui(dev_mac)

        if dev_fqdn:
            dev_fqdn_msg = f"Found FQDN **{dev_fqdn}** in DNS for IP  {dev_ip}"
        else:
            dev_fqdn_msg = f"Unable to find DNS record for IP {dev_ip}"
        st.info(f"DNS: {dev_fqdn_msg}")

        if dev_mac:
            st.info(f"MAC Address: **{dev_mac}** of type **{dev_oui}**")
            if not is_wlan:
                st.info(
                    f"Network Location: MAC Address **{dev_mac}** on switch **{dev_sw}** and interface **{dev_intf}**"
                )
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
        nei_bool, nei_res = find_lldp_nei_on_intf(dev_sw, dev_intf)
        if nei_bool and not is_wlan:
            st.error("Unexpected devices (CDP/LLDP) on interface!")
            nei_df = pd.DataFrame(nei_res.json())
            nei_df = nei_df.drop(columns=["timestamp"])
            st.write(nei_df)
            nei_res_list = list(nei_res.json())
        else:
            nei_res_list = list()
            if not is_wlan:
                st.success(
                    f"No unexpected CDP/LLDP devices on switch {dev_sw} interface {dev_intf}"
                )

        # Get the configuration of the interface
        intf_res = get_intf_config(dev_sw, dev_intf)
        if intf_res.json():
            intf_cfg = intf_res.json()[0]["config"]
        else:
            intf_cfg = ""
        # st.write(intf_res.json())
        # st.write(intf_cfg)

        # Check ISE Posture
        nac_posture = "Undetermined"
        intf_access = False
        intf_trunk = False
        if not is_wlan:
            for line in intf_cfg.splitlines():
                if re.search("ip access-group ISE-ACL-ALLOW", line):
                    nac_posture = f"interface {dev_intf} in **MONITOR** mode"
                if re.search("ip access-group ISE-ACL-DEFAULT", line):
                    nac_posture = f"interface {dev_intf} in **ENFORCEMENT** mode"
                if re.search("switchport mode access", line):
                    intf_access = True
                if re.search("switchport mode trunk", line):
                    intf_trunk = True

            st.info(f"ISE NAC Posture: {nac_posture}")

        if include_history_bool:

            st.markdown("---")

            res_allip = check_dtrack(dev_ip, namespace, view="all", debug=False)
            # st.write(res_allip.json())

            if dev_ip and res_allip.json():

                # res_allip = utils.check_dtrack(dev_ip, namespace, view="all", debug=False)
                # st.write(res_allip.json())
                dfipall = pd.DataFrame(res_allip.json())
                dfipall["lastStateChange"] = dfipall["timestamp"].apply(
                    unix_to_human_local
                )
                dfipall = dfipall.drop(columns=["timestamp"])
                dfipall["vlan"] = dfipall["vlan"].astype(str).str.replace(",", "")
                st.markdown(f"### Device IP History (Last 3 Months)")
                st.write(dfipall)
            else:
                if dev_ip:
                    # Look up ARP
                    arp_res = check_arp_ip(dev_ip, namespace, view="all")
                    st.markdown(f"### Device ARP IP History (Last 3 Months)")
                    st.write(pd.DataFrame(arp_res.json()))

            if dev_mac:

                if type(res_addr) == dict:
                    dfmacall = pd.DataFrame(res_addr["user_int_lod"])
                    if dfmacall.empty:
                        # st.warning(f"MAC {dev_mac} not found")
                        mac_res = check_arp_mac(dev_mac, namespace, view="all")
                        st.write(pd.DataFrame(mac_res.json()))
                    else:
                        dfmacall["lastStateChange"] = dfmacall["timestamp"].apply(
                            unix_to_human_local
                        )
                        dfmacall.sort_values(by=["lastStateChange"], inplace=True)
                        dfmacall = dfmacall.drop(columns=["timestamp"])
                        dfmacall["vlan"] = (
                            dfmacall["vlan"].astype(str).str.replace(",", "")
                        )
                        st.markdown(f"### Device MAC History (Last 3 Months)")
                        st.write(dfmacall)
                else:
                    res_allmac = check_dtrack(dev_mac, namespace, view="all")
                    dfmacall = pd.DataFrame(res_allmac.json())
                    dfmacall["lastStateChange"] = dfmacall["timestamp"].apply(
                        unix_to_human_local
                    )
                    sfmacall = dfmacall["timestamp"].sort_values()
                    dfmacall = dfmacall.drop(columns=["timestamp"])
                    st.markdown(f"### Device MAC History (Last 3 Months)")
                    st.write(dfmacall)

        # Find if device uses DHCP
        if dev_mac:
            dhcp_res, dev_uses_dhcp_bool = check_dhcp_mac(dev_mac, namespace)
            st.write(dhcp_res.json())
            dhcp_res_list = list(dhcp_res.json())
        else:
            dhcp_res_list = list()
            dev_uses_dhcp_bool = False

        # Build
        if ping_result:
            dev_is_alive = ping_result.is_alive

        dev_search_dict.update(
            {
                # "namespace_list": namespace_list,
                "namespace": namespace,
                "dev_input": dev_input,
                "dev_ip": dev_ip,
                "dev_mac": dev_mac,
                "dev_fqdn": dev_fqdn,
                "dev_is_alive": dev_is_alive,
                "dev_oui": dev_oui,
                "nei_bool": nei_bool,
                "nei_res": nei_res_list,
                "dev_sw": dev_sw,
                "dev_intf": dev_intf,
                "intf_cfg": intf_cfg,
                "dev_uses_dhcp_bool": dev_uses_dhcp_bool,
                "dhcp_res": dhcp_res_list,
                "intf_access": intf_access,
                "intf_trunk": intf_trunk,
                "dev_vlan": dev_vlan,
                "vlan_name": vlan_name,
                "nac_posture": nac_posture,
                "dev_dtrack_type": dev_type,
                "dev_dtrack_timestamp": dev_timestamp,
            }
        )

    return dev_search_dict


def intf_vlan_update_cfg(intf, vlan):

    new_intf = f"""
interface {intf}
  switchport access vlan {vlan}
  shutdown
  no shutdown
    """

    return new_intf.strip().split("\n")


def get_random_file(dir_path="assets", ext=".jpeg"):
    """
    Get a random image file path from the specified directory, handling calls
    from both the frontend directory and its subdirectories.

    Args:
        dir_path (str): Path to the directory to search (default: 'assets')
        ext (str): File extension to filter by (default: '.jpeg')

    Returns:
        str: Full path to a randomly selected image file, or None if no files found
    """
    # Get the directory where utils.py is located (frontend directory)
    frontend_dir = pathlib.Path(__file__).parent.resolve()

    # Construct the full path to the assets directory
    assets_path = frontend_dir / dir_path

    # Get all files with the specified extension
    files = list(assets_path.glob(f"*{ext}"))

    if not files:
        return None

    chosen_file = random.choice(files)
    return str(chosen_file.absolute())


def main():
    pass


# Standard call to the main() function.
if __name__ == "__main__":
    main()
