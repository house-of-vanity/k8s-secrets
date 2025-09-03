# Secret Reader

Kubernetes secret viewer with TOTP support.

## Features

- View Kubernetes secrets in web UI
- Auto-generate TOTP codes from otpauth:// URLs
- Copy values with one click

## Deploy

```bash
kubectl apply -f service-account.yaml
kubectl apply -f rbac.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

## Configuration

Edit `deployment.yaml` to specify which secrets to display:

```yaml
args:
  - "--secrets"
  - "secret1,secret2"
  - "--namespace"
  - "k8s-secrets"
```
