# Argo CD deployment

This is a single-replica Kubernetes sample. SQLite requires exactly one replica
and a persistent volume.

Before applying the Argo CD `Application`, create the namespace and secrets:

```bash
kubectl create namespace vault-backup

kubectl -n vault-backup create secret generic vault-server-env  --from-literal=db-password='use-a-long-random-password'

kubectl -n vault-backup create secret tls vault-server-tls --cert=server.crt  --key=server.key
```

If `registry.vn.eit.zone/hr-digi/vault-server` requires authentication, create
and reference an image pull secret in the pod spec.

For a private cluster registry, replace `registry.vn.eit.zone/hr-digi/vault-server:latest`
with an immutable image tag or digest and use `imagePullPolicy: IfNotPresent`.

The deployment uses two persistent volumes:

- `vault-server-data` stores the live database, key, yearly audit databases,
  separate encrypted secrets database, its key, and server state.
- `vault-server-backups` is mounted at `/backups` and can store backup archives.

Generate a backup inside the running pod with:

```bash
kubectl -n vault-backup exec deploy/vault-server -- \
  /app/scripts/backup-vault-server.sh \
  --db /data/vault.db \
  --secrets-db /data/vault-secrets.db \
  --audit-db /data/audit.db \
  --output /backups/vault-server-backup.tar.gz
```

Stop or quiesce the pod before creating a consistent SQLite backup. The
separate backup volume protects archives from changes to the live data volume,
but it is not an off-cluster copy; replicate or snapshot it according to the
cluster's disaster-recovery policy.

Apply the application:

```bash
kubectl apply -f deploy/application.yaml
```
