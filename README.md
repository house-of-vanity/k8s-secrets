# Secret Reader

Kubernetes secret viewer with TOTP support.


<img height="250" alt="image" src="https://github.com/user-attachments/assets/a16b4d8e-b51b-4e2f-934a-8699bbdd90e3" />

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
