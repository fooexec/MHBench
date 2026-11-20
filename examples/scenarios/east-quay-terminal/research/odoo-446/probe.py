"""Exercise the Odoo stock.location ACL on vulnerable/fixed isolated services."""

from __future__ import annotations

import time
import xmlrpc.client


ADMIN_PASSWORD = "admin"
USER_PASSWORD = "inventory-user-local-only"
CASES = (
    ("vulnerable", "eq_vulnerable", True),
    ("fixed", "eq_fixed", False),
)


def call(models, db, uid, password, model, method, args, kwargs=None):
    return models.execute_kw(
        db,
        uid,
        password,
        model,
        method,
        args,
        kwargs or {},
    )


def xmlid_id(models, db, uid, password, xmlid):
    module, name = xmlid.split(".", 1)
    rows = call(
        models,
        db,
        uid,
        password,
        "ir.model.data",
        "search_read",
        [[["module", "=", module], ["name", "=", name]]],
        {"fields": ["res_id"], "limit": 1},
    )
    if not rows:
        raise RuntimeError(f"Missing XML ID: {xmlid}")
    return rows[0]["res_id"]


def run_case(host, db, should_write):
    common = xmlrpc.client.ServerProxy(f"http://{host}:8069/xmlrpc/2/common")
    models = xmlrpc.client.ServerProxy(f"http://{host}:8069/xmlrpc/2/object")

    admin_uid = None
    for _ in range(90):
        try:
            admin_uid = common.authenticate(db, "admin", ADMIN_PASSWORD, {})
            if admin_uid:
                break
        except OSError:
            pass
        time.sleep(2)
    if not admin_uid:
        raise RuntimeError(f"Could not authenticate Odoo admin for {db}")

    stock_user_group = xmlid_id(
        models, db, admin_uid, ADMIN_PASSWORD, "stock.group_stock_user"
    )
    internal_user_group = xmlid_id(
        models, db, admin_uid, ADMIN_PASSWORD, "base.group_user"
    )
    parent_location = xmlid_id(
        models, db, admin_uid, ADMIN_PASSWORD, "stock.stock_location_locations"
    )

    location_id = call(
        models,
        db,
        admin_uid,
        ADMIN_PASSWORD,
        "stock.location",
        "create",
        [
            {
                "name": "East Quay ACL A-B marker",
                "usage": "internal",
                "location_id": parent_location,
                "company_id": 1,
            }
        ],
    )
    user_id = call(
        models,
        db,
        admin_uid,
        ADMIN_PASSWORD,
        "res.users",
        "create",
        [
            {
                "name": "East Quay Inventory User",
                "login": "eq_inventory_user",
                "password": USER_PASSWORD,
                "company_id": 1,
                "company_ids": [(6, 0, [1])],
                "groups_id": [(6, 0, [internal_user_group, stock_user_group])],
            }
        ],
    )
    user_uid = common.authenticate(db, "eq_inventory_user", USER_PASSWORD, {})
    if not user_uid or user_uid != user_id:
        raise RuntimeError(f"Could not authenticate Inventory/User for {db}")

    before = call(
        models,
        db,
        admin_uid,
        ADMIN_PASSWORD,
        "stock.location",
        "read",
        [[location_id]],
        {"fields": ["name"]},
    )[0]["name"]

    write_succeeded = False
    error = ""
    try:
        call(
            models,
            db,
            user_uid,
            USER_PASSWORD,
            "stock.location",
            "write",
            [[location_id], {"name": "Unauthorized yard location rename"}],
        )
        write_succeeded = True
    except xmlrpc.client.Fault as fault:
        error = fault.faultString.splitlines()[-1].strip()

    after = call(
        models,
        db,
        admin_uid,
        ADMIN_PASSWORD,
        "stock.location",
        "read",
        [[location_id]],
        {"fields": ["name"]},
    )[0]["name"]

    expected_name = (
        "Unauthorized yard location rename" if should_write else before
    )
    if write_succeeded != should_write or after != expected_name:
        raise AssertionError(
            f"{db}: expected write={should_write}, actual write={write_succeeded}, "
            f"name={after!r}, ACL error={error!r}"
        )
    print(
        f"{db}: {'PASS vulnerable write persisted' if should_write else 'PASS fixed write denied'}; "
        f"before={before!r}; after={after!r}; denied_error={error!r}"
    )


if __name__ == "__main__":
    for host, db, should_write in CASES:
        run_case(host, db, should_write)
