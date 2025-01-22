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
import streamlit as st
import yaml
import bcrypt
from pathlib import Path
import streamlit_authenticator as stauth
from typing import List, Dict

import sys

# Add the frontend directory to the path if needed
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.append(str(root_dir))

import utils


def load_config():
    with open("config/config.yaml") as file:
        return yaml.safe_load(file)


def save_config(config):
    with open("config/config.yaml", "w") as file:
        yaml.dump(config, file, default_flow_style=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def is_admin(data: dict, username: str) -> bool:
    """
    Check if a user has admin role in the credentials data structure.

    Args:
        data (dict): The credentials data structure
        username (str): Username to check

    Returns:
        bool: True if user is an admin, False if not or if user not found
    """
    try:
        user_data = data["credentials"]["usernames"].get(username)
        if user_data and "role" in user_data:
            return "admin" in user_data["role"]
        return False
    except KeyError:
        return False


def add_new_user(
    config: Dict,
    username: str,
    email: str,
    name: str,
    password: str,
    role: str = "user",
) -> bool:
    if username in config["credentials"]["usernames"]:
        return False

    config["credentials"]["usernames"][username] = {
        "email": email,
        "name": name,
        "password": hash_password(password),
        "role": role,
    }
    save_config(config)
    return True


def main():

    st.set_page_config(
        layout="wide", page_title="Self Service Fantasy", page_icon="images/favicon.ico"
    )

    if not st.session_state.get("authentication_status"):
        st.error("Please log in to access this page")
        return

    st.title("Password Management")

    config = load_config()
    current_user = st.session_state["username"]

    # Check if user is admin
    admin_access = is_admin(config, current_user)

    if admin_access:
        st.write(f"{current_user} you have admin privileges")

    # Change Own Password Section
    st.header(f"Change Your Password")
    with st.form("change_password"):
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submit_change = st.form_submit_button("Change Password")

        if submit_change:
            if not verify_password(
                current_password,
                config["credentials"]["usernames"][current_user]["password"],
            ):
                st.error("Current password is incorrect")
            elif new_password != confirm_password:
                st.error("New passwords do not match")
            elif len(new_password) < 8:
                st.error("Password must be at least 8 characters long")
            else:
                config["credentials"]["usernames"][current_user]["password"] = (
                    hash_password(new_password)
                )
                save_config(config)
                st.success("Password changed successfully")

    # Admin Section
    if admin_access:
        st.header("Admin Management")

        # Set Session State
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

        # Add New User Section
        st.subheader("Add New User")
        with st.form("add_user"):
            new_username = st.text_input("Username")
            new_user_email = st.text_input("Email")
            new_user_name = st.text_input("Full Name")
            new_user_password = st.text_input("Password", type="password")
            new_user_confirm_password = st.text_input(
                "Confirm Password", type="password"
            )
            new_user_role = st.selectbox("Role", ["user", "admin"])
            submit_new_user = st.form_submit_button("Add User")

            if submit_new_user:
                if not all(
                    [new_username, new_user_email, new_user_name, new_user_password]
                ):
                    st.error("All fields are required")
                elif new_user_password != new_user_confirm_password:
                    st.error("Passwords do not match")
                elif len(new_user_password) < 8:
                    st.error("Password must be at least 8 characters long")
                elif "@" not in new_user_email:
                    st.error("Please enter a valid email address")
                elif new_username in config["credentials"]["usernames"]:
                    st.error("Username already exists")
                else:
                    if add_new_user(
                        config,
                        new_username,
                        new_user_email,
                        new_user_name,
                        new_user_password,
                        new_user_role,
                    ):
                        st.success(f"User {new_username} added successfully")
                        st.rerun()
                    else:
                        st.error("Failed to add user")

        # User Password Management
        st.subheader("User Password Management")
        with st.form("admin_set_password"):
            users = list(config["credentials"]["usernames"].keys())
            selected_user = st.selectbox("Select User", users)
            new_admin_password = st.text_input(
                "New Password", type="password", key="admin_new"
            )
            confirm_admin_password = st.text_input(
                "Confirm Password", type="password", key="admin_confirm"
            )
            user_role = st.selectbox(
                "User Role",
                ["user", "admin"],
                index=(
                    0
                    if config["credentials"]["usernames"][selected_user].get("role")
                    != "admin"
                    else 1
                ),
            )
            submit_admin = st.form_submit_button("Update User")

            if submit_admin:
                if new_admin_password:
                    if new_admin_password != confirm_admin_password:
                        st.error("Passwords do not match")
                    elif len(new_admin_password) < 8:
                        st.error("Password must be at least 8 characters long")
                    else:
                        config["credentials"]["usernames"][selected_user][
                            "password"
                        ] = hash_password(new_admin_password)

                # Update role
                config["credentials"]["usernames"][selected_user]["role"] = user_role
                save_config(config)
                st.success(f"User {selected_user} updated successfully")

        # Authorized Email Management
        st.subheader("Authorized Email Management")
        with st.form("email_management"):
            # Display current authorized emails
            current_emails = config.get("authorized_emails", [])
            st.write("Current Authorized Emails:")
            for email in current_emails:
                st.text(email)

            # Add new email
            new_email = st.text_input("Add New Email")
            add_email = st.form_submit_button("Add Email")

            if add_email and new_email:
                if "@" not in new_email:
                    st.error("Please enter a valid email address")
                elif new_email in current_emails:
                    st.error("Email already in authorized list")
                else:
                    if "authorized_emails" not in config:
                        config["authorized_emails"] = []
                    config["authorized_emails"].append(new_email)
                    save_config(config)
                    st.success(f"Added {new_email} to authorized emails")
                    st.rerun()

        # Remove authorized email
        with st.form("remove_email"):
            email_to_remove = st.selectbox("Select Email to Remove", current_emails)
            remove_email = st.form_submit_button("Remove Email")

            if remove_email:
                config["authorized_emails"].remove(email_to_remove)
                save_config(config)
                st.success(f"Removed {email_to_remove} from authorized emails")
                st.rerun()


if __name__ == "__main__":
    main()
