# East Quay Open WES integration feasibility

**Disposition:** technically runnable, but not ready to add to the Harbor task.
The first local Compose trial confirmed that the upstream warehouse system can
serve a dynamic UI and its API, but its build/runtime footprint and optional AI
dependencies need deliberate adaptation. No Open WES files or services have
been added to the East Quay task yet.

## Source and build evidence

- Upstream: `jingsewu/open-wes`, snapshot
  `c85c6ac50cbc1cf5e39e222e4b81ecebc97d7e34` (2026-11-03).
- The source archive is about 14 MiB before build outputs. The backend source
  is about 11 MiB; the frontend is about 4 MiB.
- On the local JDK 17 toolchain,
  `./gradlew --no-daemon :server:wes-server:bootJar
  :server:gateway-server:bootJar :server:station-server:bootJar` completed
  successfully (93 Gradle tasks, 30 seconds).
- The minimally runnable upstream stack has seven services: frontend,
  gateway, WES API, station API, MySQL, Redis, and Nacos. The upstream Compose
  file also contains a separate monitoring stack; it was not needed for this
  feasibility run.
- Nacos uses the SQL initialization files in `initdb.d`. Removing that mount
  causes startup failure (`Unknown database 'nacos_config'`); preserving the
  initialization mount made Nacos healthy.

## Frontend build and runtime

- The unmodified frontend build failed because its `html-webpack-plugin` 4.x
  dependency resolved alongside webpack 5 and attempted to load the removed
  `webpack/lib/LoaderTargetPlugin`.
- In the temporary feasibility archive only, changing that dependency to
  `html-webpack-plugin` `^5.6.4` allowed the production build to complete. It
  took about 145 seconds and emitted 52 webpack warnings; the generated JS/CSS
  is about 35 MiB.
- With the frontend-to-gateway Docker DNS alias and an explicit Compose
  dependency on the gateway, the UI returned HTTP 200. A deliberately invalid
  sign-in request traversed the frontend and gateway and received the
  application's expected wrong-credentials response (HTTP 200 with an
  application error body). This proves the UI/API path, not successful
  warehouse workflow seeding.
- The frontend initially exited because Nginx resolved `api-gateway` before
  the alias was available. Ordering the frontend after the gateway fixed that
  trial; the task Compose will need an explicit startup dependency or a
  retry-capable resolver.

## Resource and startup constraints

- The default JVM sizing used about 4.6 GiB RSS for the seven-service stack on
  this host, before useful warehouse data or the Harbor verifier is included.
- With 512 MiB limits and reduced heaps, the WES API failed with
  `OutOfMemoryError: Metaspace` before registering in Nacos.
- With 768 MiB limits for each Java service and Nacos, the UI and invalid-login
  API smoke succeeded. However, the WES API and Nacos approached their
  respective 768 MiB limits (about 756 and 767 MiB), so this is not a safe
  portable resource profile. A lower-footprint configuration still needs to
  be demonstrated.
- The current upstream WES configuration also initializes AI and vector-store
  clients. Empty provider keys prevent the WES process from starting. Dummy
  local values allowed this trial to start, but they are not an acceptable
  task integration; AI features should be disabled/configured without external
  credentials before packaging.

## Security and integration gates

1. Do not copy the upstream Compose file or Nacos SQL unreviewed. Sanitize
   bootstrap values and remove monitoring/admin ports not required by the
   East Quay workflow.
2. The known Open WES CVE-2026-111721 candidate was rejected as a scored node
   because its public reproduction and ordinary REST/JSON path fail this
   benchmark's difficulty gate. If Open WES is included as an unscored
   warehouse subsystem, the affected cross-warehouse operation must be fixed
   and regression-tested so it does not become a shortcut.
3. Add Open WES to the business workflow only after its warehouse records are
   genuinely connected to East Quay's request/clearance/dispatch process;
   mere co-deployment is not a business relationship.
4. Before inclusion, rerun a stock-Harbor trial with the complete seven-service
   stack under the actual task resource limits and verify both the API workflow
   and the network/file-system boundaries.

The feasibility containers and their data volumes were removed after the
trial. This document records the test evidence; it does not claim that Open WES
is integrated or that an Open WES vulnerability has been selected.
