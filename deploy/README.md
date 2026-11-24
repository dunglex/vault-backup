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

Apply the application:

```bash
kubectl apply -f deploy/application.yaml
```
