# East Quay local-weakness control designs

These controls define the corrected side of the four `deployed_weakness`
candidates in `range-plan.yaml`. `verify.sh` builds the vulnerable and
corrected Port Operations web application side by side against the same
disposable database and checks the baseline effect and each control. This
runtime differential passes for the controls listed below. It is not a
blind-agent evaluation; it does not by itself approve the candidate path or
establish task difficulty.

## `#request-manifest`

`request_table.php` must start a session and deny unauthenticated access. A
carrier account must receive only rows owned by that carrier; a terminal clerk
may receive the full queue. The fixed control passes when an unauthenticated
GET no longer reveals the per-run target ship number and a carrier cannot read
another carrier's request.

## `#status-query-sqli`

`shipstatus_cntry.php` must validate the ship number as an integer and use a
prepared statement for both the country and ship lookup. The response must
HTML-escape the ship name. The fixed control passes when the UNION probe
returns no staff data and a normal carrier lookup still works.

## `#credential-reuse`

The Operations account must have a unique, independently generated secret that
is not the carrier portal password. The fixed control passes when the carrier
password is rejected by `adminlogin.php`, while the separate Operations secret
continues to authenticate the authorized staff test.

## `#status-clearance-transition`

The legacy `shipstatus.php` path must not mutate a held shipment directly.
Either remove the direct status write or require the same approved request and
cleared record as the dispatch bridge. The fixed control passes when an
Operations session cannot set a held shipment to `PL` through this endpoint.
The clearance-and-dispatch endpoints are unchanged by this patch and are
covered by the normal scenario smoke; this small control harness only A/Bs the
legacy direct-update endpoint.
