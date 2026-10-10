# Deployment

`git push` to `main` deploys the photography app to the homelab cluster. Nothing connects *into* the machine.

1. **Build** (GitHub-hosted runner): build the image, push `stefanmhall/photography` to Docker Hub, export the image digest.
2. **Deploy** (self-hosted runner `homelab-photography`, environment `homelab`, `main` only):
   - sync `photography-secrets` / `tls-certs` from GitHub secrets (server-side apply; reports "same as cluster" / "DIFFERS" first)
   - `kubectl apply` the pvc, deployment and service; `rollout restart`; wait for the rollout
   - **verify every running pod's image digest equals the digest the build just pushed** (`.github/scripts/verify-image.sh`)
   - check the NodePort (31055) and `/health` over TLS

The runner uses a namespace-scoped ServiceAccount that can only update the named objects above: it cannot create or
delete anything, read `db-secrets`, exec into pods or touch postgres. See `kubernetes/ci/README.md` on the host.

Validate a deploy without changing anything: Actions -> Build & Deploy Photography -> Run workflow -> `dry_run: true`.

`photography-ingress.yaml` is deliberately not applied by the pipeline: that ingress is not live (traffic reaches the app
through the Cloudflare tunnel to NodePort 31055).
