# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.


"""Manage IVRE authentication: users, groups, and API keys."""

import argparse
import sys

from ivre import config
from ivre.db import db


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser("init", help="Initialize auth collections and indexes")

    # user management
    p_add = sub.add_parser("add-user", help="Create a user")
    p_add.add_argument("email")
    p_add.add_argument("--admin", action="store_true", help="Make user an admin")
    p_add.add_argument("--groups", nargs="*", default=[], help="Groups to assign")

    p_del = sub.add_parser("del-user", help="Delete a user")
    p_del.add_argument("email")

    p_activate = sub.add_parser("activate-user", help="Activate a pending user")
    p_activate.add_argument("email")

    p_deactivate = sub.add_parser("deactivate-user", help="Deactivate a user")
    p_deactivate.add_argument("email")

    p_admin = sub.add_parser("set-admin", help="Grant admin to a user")
    p_admin.add_argument("email")

    p_unadmin = sub.add_parser("unset-admin", help="Revoke admin from a user")
    p_unadmin.add_argument("email")

    # groups
    p_addgrp = sub.add_parser("add-group", help="Add a user to a group")
    p_addgrp.add_argument("email")
    p_addgrp.add_argument("group")

    p_rmgrp = sub.add_parser("del-group", help="Remove a user from a group")
    p_rmgrp.add_argument("email")
    p_rmgrp.add_argument("group")

    # list
    sub.add_parser("list-users", help="List all users")

    # API keys
    p_key = sub.add_parser("create-api-key", help="Create an API key for a user")
    p_key.add_argument("email")
    p_key.add_argument("name", help="Label for the API key")

    args = parser.parse_args()

    if not config.WEB_AUTH_ENABLED:
        sys.exit("Error: WEB_AUTH_ENABLED is not set to True in your configuration")

    if db.auth is None:
        sys.exit("Error: Authentication backend not available (check DB configuration)")

    if args.command == "init":
        db.auth.init()
        print("Auth collections initialized.")

    elif args.command == "add-user":
        if db.auth.get_user_by_email(args.email):
            sys.exit(f"Error: User {args.email} already exists")
        db.auth.create_user(
            args.email,
            is_admin=args.admin,
            is_active=True,
            groups=args.groups,
        )
        print(f"User {args.email} created.")

    elif args.command == "del-user":
        user = db.auth.get_user_by_email(args.email)
        if user is None:
            sys.exit(f"Error: User {args.email} not found")
        db.auth.delete_user(args.email)
        print(f"User {args.email} deleted.")

    elif args.command == "activate-user":
        _require_user(args.email)
        db.auth.update_user(args.email, is_active=True)
        print(f"User {args.email} activated.")

    elif args.command == "deactivate-user":
        _require_user(args.email)
        db.auth.update_user(args.email, is_active=False)
        print(f"User {args.email} deactivated.")

    elif args.command == "set-admin":
        _require_user(args.email)
        db.auth.update_user(args.email, is_admin=True)
        print(f"User {args.email} is now an admin.")

    elif args.command == "unset-admin":
        _require_user(args.email)
        db.auth.update_user(args.email, is_admin=False)
        print(f"User {args.email} is no longer an admin.")

    elif args.command == "add-group":
        _require_user(args.email)
        db.auth.add_user_group(args.email, args.group)
        print(f"User {args.email} added to group {args.group}.")

    elif args.command == "del-group":
        _require_user(args.email)
        db.auth.remove_user_group(args.email, args.group)
        print(f"User {args.email} removed from group {args.group}.")

    elif args.command == "list-users":
        users = db.auth.list_users()
        if not users:
            print("No users.")
            return
        for user in users:
            status = "active" if user.get("is_active") else "pending"
            admin = " [admin]" if user.get("is_admin") else ""
            groups = f" groups={user.get('groups', [])}" if user.get("groups") else ""
            print(f"  {user['email']} ({status}{admin}{groups})")

    elif args.command == "create-api-key":
        _require_user(args.email)
        key = db.auth.create_api_key(args.email, args.name)
        print(f"API key created: {key}")
        print("Store this key securely — it cannot be retrieved later.")

    else:
        parser.print_help()


def _require_user(email: str) -> None:
    if db.auth.get_user_by_email(email) is None:
        sys.exit(f"Error: User {email} not found")
