# Upstream source provenance

Base application: `PratibhaAwasthi/Shipping-Port-Management-Sys`
Upstream commit reviewed: `67da2e92975995810714e18b77469df8f6152a78` (2023-03-20).

For this benchmark integration, the `frontEnd/` and `backEnd/` PHP files were
merged as directed by the upstream README, `testCase/test.php` was installed as
the include expected by `database.php`, and hard-coded database connection
literals were replaced with `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`
environment lookups. The image uses a local MariaDB service and synthetic seed
data. No upstream external database endpoint or credentials are used.

The base build is the corrected control: the request list is restricted to
Operations, the carrier status lookup uses prepared statements, the Operations
account has a distinct secret, and the legacy direct status endpoint refuses
to alter a held shipment. Selected vulnerable variants are applied explicitly
through `weakness-catalog.yaml` from `weakness-overlays/`; unselected variants
are not part of the rendered task.

For Linux/MariaDB portability, the integration uses the actual lower-case
`country` and `ships` table names. The selected SQLi overlay preserves the
upstream unsafe `shipnumber` interpolation while using those real table names.
The selected credential-reuse overlay changes only the scenario seed so the
Operations and carrier accounts share a password; that is not an upstream
behavior.
