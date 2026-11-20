# Odoo #446 isolated component A/B

This research-only Compose lab checks the `stock.location` write ACL cited by
candidate-pool row #446. It is not part of the East Quay service graph or Harbor
task.

- `fixed` uses the pinned official `odoo:18.0` image, whose ACL is read-only
  for `stock.group_stock_user`.
- `vulnerable` derives from the same pinned official image and changes only
  that ACL from `perm_write=0` to `perm_write=1`, reconstructing the upstream
  vulnerable ACL present at Odoo 18.0 commit
  `11483aeb22c65e4fe5f27b6c29d8707b43204838`.
- The source fix on the Odoo 18.0 branch is
  `afae9f6c16fc8ada2bfb6721bf8f7b345d7a58a0`; it changes the ACL back to
  read-only. The master fix named in the candidate row is
  `02a36c65279775928010ab27a3432d53e75c6b8b`.
- Both variants use separate databases on a private, internal-only Docker
  network, with no published ports. The probe creates an Inventory/User
  account and an internal stock location, attempts a rename, and checks the
  persisted name as administrator.

Run:

```bash
bash examples/scenarios/east-quay-terminal/research/odoo-446/verify.sh
```

The run is reproducible and cleans up its temporary containers, network, and
database volume on success or failure.

The vulnerable case is expected to persist the rename; the fixed case must
deny it. This controlled ACL reconstruction demonstrates the permission effect,
not the complete historical Odoo image pair, second-order picking/dispatch
impact, or an agent-to-Odoo credential bridge. Keep #446 unselected until those
gates and the business-graph decision are resolved.
