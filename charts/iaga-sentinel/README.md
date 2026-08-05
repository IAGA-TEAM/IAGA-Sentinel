# IAGA Sentinel Helm chart

Deploys the sidecar. Nothing here is required to try the product — a single
binary and `iaga serve` is enough — this is for running it as a service.

```sh
helm install sentinel ./charts/iaga-sentinel \
  --set image.tag=v2.0.1 \
  --set env.DATABASE_URL=postgres://…
```

## The image tag is pinned in two independent places

`Chart.yaml: appVersion` and `values.yaml: image.tag` are separate strings and
**nothing enforces that they agree**. The chart labels every object it creates
with `appVersion`, so a stale `image.tag` produces a deployment that *claims* one
version and *runs* another — a shape that has shipped before and is invisible in
`kubectl get all`. It shipped as recently as 2.0.0: every object was labelled
`2.0.0` while the pod pulled `v1.8.1`, from a registry namespace CI had stopped
publishing to at 1.9.0. Fixed in 2.0.1, which is exactly why this section exists.

`deploy/kubernetes/deployment.yaml` (the plain kustomize path) pins the image a
**third** time, with no relationship to the chart at all.

Before releasing, check all three resolve to the same tag:

```sh
grep appVersion charts/iaga-sentinel/Chart.yaml
grep -A1 'repository:' charts/iaga-sentinel/values.yaml
grep 'image:' deploy/kubernetes/deployment.yaml
helm template sentinel ./charts/iaga-sentinel | grep 'image:'
kubectl kustomize deploy/kubernetes | grep 'image:'
```

The last two are the ones that matter — they are what actually gets applied.

`Chart.yaml: version` is the CHART's own version and is deliberately *not* the
product version; bump it when the templates change, not when the product does.

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

```sh
kubectl exec deploy/sentinel -- iaga migrate --status
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
