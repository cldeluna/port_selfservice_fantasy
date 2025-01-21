#!/usr/bin/python -tt
# Project: port_selfservice_apocalypse
# Filename: SelfServiceApocalypseHome.py
# claudiadeluna
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "1/4/25"
__copyright__ = "Copyright (c) 2025 Claudia"
__license__ = "Python"

import os
import streamlit as st
import yaml
import dotenv

import utils
from pathlib import Path
import requests
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth



def main():
    st.set_page_config(layout="wide", page_title="Self Service Apocalypse", page_icon="🧟‍")

    # Initialize session state for authentication status and username
    if 'authentication_status' not in st.session_state:
        st.session_state['authentication_status'] = None
    if 'username' not in st.session_state:
        st.session_state['username'] = None
    if 'user_role' not in st.session_state:
        st.session_state['user_role'] = None
    if 'sq_access_token' not in st.session_state:
        st.session_state['sq_access_token'] = None
    if "dev_search_dict" not in st.session_state:
        st.session_state.dev_search_dict = dict()

    # Load configuration file
    with open('config/config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    # Create the authenticator object
    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days'],
    )

    # Create login widget
    try:
        authenticator.login()
    except Exception as e:
        st.error(e)

    # st.write(st.session_state['authentication_status'])
    # st.write(st.session_state['username'])
    # st.write(st.session_state['roles'])

    if st.session_state['authentication_status']:
        # Successful login
        authenticator.logout('Logout', 'sidebar')
        # authenticator.logout()
        st.write(f'Welcome *{st.session_state["name"]}*')

        # Display navigation image in sidebar
        randomf = utils.get_random_file(dir_path="images", ext=".jpeg")
        if randomf:
            try:
                st.sidebar.image(randomf, use_container_width=True)
            except Exception as e:
                st.sidebar.error(f"Error loading image: {randomf}")
                st.sidebar.error(f"Error details: {str(e)}")
        else:
            st.sidebar.write("No images found")

        # Load the SuzieQ API Key from Environment Variable
        dotenv.load_dotenv()

        if not os.getenv("SQ_API_TOKEN"):
            st.error(
                "SuzieQ Token cannot be found in an environment variable. "
                "Make sure your .env file has been updated with a valid API Access Token for the SuzieQ REST API!"
            )
            st.stop()
        else:
            st.success("SuzieQ Token found in environment variable")
            st.session_state['sq_access_token'] = os.getenv("SQ_API_TOKEN")

        # Main content
        st.title("Self Service Port Change Apocalypse")
        st.write("""
        Welcome to the Self Service Port Change App!  This can only lead to the apocalypse. 
        Use the navigation menu on the left to:
        - Find devices by IP, FQDN, or MAC address
        - Change VLAN configurations
        - Check campus VLANs
        - Verify VLAN status on switches
        """)

    elif st.session_state['authentication_status'] is False:
        st.error('Username/password is incorrect')
    elif st.session_state['authentication_status'] is None:
        st.warning('Please enter your username and password')



# Standard call to the main() function.
if __name__ == '__main__':
    main()