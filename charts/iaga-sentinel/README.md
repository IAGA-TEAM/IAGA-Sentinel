# IAGA Sentinel Helm chart

Deploys the sidecar. Nothing here is required to try the product — a single
binary and `iaga serve` is enough — this is for running it as a service.

```sh
# NOTE: from 2.0.2 `image.tag` has NO default and the render refuses without it.
# `image.repository` still defaults to ghcr.io/iaga-team/iaga-sentinel, a package
# that DOES NOT EXIST yet — so with the default repository the pod still lands in
# ImagePullBackOff. Build and push to your own registry first and add
# --set image.repository=<your-registry>/iaga-sentinel. See the root README.
helm install sentinel ./charts/iaga-sentinel \
  --set image.repository=<your-registry>/iaga-sentinel \
  --set image.tag=v2.0.2 \
  --set postgres.enabled=true \
  --set postgres.url=postgres://…
```

> There is no top-level `env` value in this chart. `--set env.DATABASE_URL=…` is
> accepted by Helm and then ignored by every template, so the pod comes up on
> SQLite while the command reads as if it were on Postgres. Use `postgres.url`
> as above, or `config.databaseUrl` — but not `config.extraEnv.DATABASE_URL`,
> which would duplicate the `DATABASE_URL` the deployment already emits.

## `image.tag` has no default, on purpose

Through 2.0.1 `values.yaml` defaulted `image.tag` to the product version. That
made `helm install` with shipped values render a perfectly valid reference to an
image that has never been published, so the first sign of trouble was a pod in
`ImagePullBackOff` — a failure that looks like a cluster problem and is not.

From 2.0.2 the tag is empty and the template calls `required`, so the render
fails with a message that names the value and says what to do. **You must pass
`--set image.tag=<tag>`** (and, until the package exists, `--set
image.repository=<your-registry>/iaga-sentinel`).

`Chart.yaml: appVersion` still labels every object the chart creates, and
**nothing enforces that it agrees with the tag you pass**. A deployment can
therefore claim one version and run another — a shape that shipped as recently
as 2.0.0, where every object was labelled `2.0.0` while the pod pulled `v1.8.1`
from a namespace CI had stopped publishing to at 1.9.0.

`deploy/kubernetes/deployment.yaml` (the plain kustomize path) pins the image a
second time, with no relationship to the chart at all.

Before releasing, check they resolve to the same tag:

```sh
grep appVersion charts/iaga-sentinel/Chart.yaml
grep 'image:' deploy/kubernetes/deployment.yaml
helm template sentinel ./charts/iaga-sentinel --set image.tag=v2.0.2 | grep 'image:'
kubectl kustomize deploy/kubernetes | grep 'image:'
```

The last two are the ones that matter — they are what actually gets applied.

`Chart.yaml: version` is the CHART's own version and is deliberately *not* the
product version; bump it when the templates change, not when the product does.

## Upgrading to 2.0.2: migration 0007 is additive

`0007_audit_read_path_indexes` adds two composite indexes on `audit_events` and
drops nothing. Both statements are `IF NOT EXISTS`, no column or row changes, so
the upgrade is a normal rolling one and needs none of the ceremony below.
Verified on both backends: a database created by a 2.0.1 binary, then started
under 2.0.2, comes up with `_sqlx_migrations` running 1→7, its rows intact and
the API answering.

The reverse direction is the usual sqlx rule: a 2.0.1 binary meeting a 2.0.2
schema refuses to start, for the same reason spelled out for `0006` below.

## Upgrading to 2.0.1: migration 0006 is one-way in practice

2.0.1 ships migration `0006_tool_trust`, which adds the `tool_trust` column to
the agent profile table.

**A 2.0.0 binary meeting a 2.0.1 schema does not start.** sqlx's migrator
validates the applied set before it applies anything, and this repo never calls
`set_ignore_missing`, so the older binary refuses with "migration 6 was
previously applied but is missing in the resolved migrations". It is not a
graceful degradation and not a warning: the pod restarts forever. In a rolling
update with `maxUnavailable > 0` you will see new pods healthy and old pods in
`CrashLoopBackOff` at the same time, which reads like an image problem and is not.

Note that `serve` prints its startup banner **before** the storage error, so a
rollback that skips the script below looks briefly like a healthy start and then
dies.

So a rollback is **not** "redeploy the previous image". It is four steps, in this
order:

1. **Scale to zero.** `kubectl scale deploy/sentinel --replicas=0`. Do not run
   the rollback SQL against a live 2.0.1 process — it writes the column you are
   about to drop.
2. **Apply the rollback script for your backend**, from a maintenance pod or
   `psql`/`sqlite3` against the same database:
   - `scripts/rollback_0006.postgres.sql`
   - `scripts/rollback_0006.sqlite.sql`
3. **Confirm the migration ledger no longer claims 0006.** The binary decides
   what to run from this table, not from the schema:
   ```sql
   SELECT version, description, success FROM _sqlx_migrations ORDER BY version;
   ```
   `0006` must be absent. If the column is gone but the row remains, the 2.0.0
   binary starts and the *next* 2.0.1 upgrade silently skips the migration —
   the worst of the three states.
4. **Redeploy the 2.0.0 image** and scale back up.

**What the rollback costs you:** every configured `tool_trust` other than the
`0.7` default. On a 2.0.0 binary those profiles were being scored *as if* they
were 0.7 anyway, so no verdict changes — the deployment returns to the state
where the knob is accepted and ignored. The script prints the values it is about
to discard before it drops the column, so an empty result is a deliberate
observation rather than a silent one.

This was run, not just written: against a live Postgres 16 the script printed the
one non-default value it was about to discard, dropped the column, deleted the
ledger row, and a subsequent `iaga migrate` re-applied the migration cleanly with
every profile back at `0.7`.

**Keep the rollback scripts with the release you deployed.** They are versioned
in `scripts/`, not baked into the image, so a cluster running 2.0.1 has no copy
of the script that undoes its own schema. Copy them into whatever holds your
runbooks before you need them at 3am.

### Checking where you actually are

There is no `iaga migrate --status`. `migrate` takes no flags at all: it
**applies** whatever is pending. To read the state without changing it, query the
same ledger the binary decides from (step 3 above), with `psql`/`sqlite3` against
the pod's database:

```sql
SELECT version, description, success FROM _sqlx_migrations ORDER BY version;
```

`iaga migrate` is idempotent, so it is a safe way to *reach* the current schema —
it just will not tell you where you were beforehand:

```sh
kubectl exec deploy/sentinel -- iaga migrate
```

Receipts written before the rollback stay valid — `0006` does not touch the
receipt tables, and no receipt field changed in 2.0.1. Verification is
unaffected:

```sh
iaga-verify chain.json --key <pubkey-hex>
```

## `iaga replay` reads SQLite only

Even when the receipt store is Postgres, `iaga replay` accepts `sqlite:` URLs
only — `cmd_replay` binds the SQLite store concretely rather than dispatching on
the URL scheme the way `pipeline/receipts.rs` does. On a Postgres deployment,
export the chain from a process that can read it, or verify from the audit API.
