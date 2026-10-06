# deploy

What a deployment needs from this repository to run the worker, and what
anyone needs to check that it runs this code.

- `worker.json`: the confidential container group profile workers run from,
  the worker and Microsoft's SKR sidecar. A deployment generates its CCE policy
  from this template with its own parameters, using
  `az confcom acipolicygen -a worker.json -p <parameters> -y`, which writes the
  policy into the template, and deploys the result as it is. It's plain ARM
  JSON with literal sizes, because confcom evaluates parameters but not other
  template functions.
- `reference-values.schema.json`: the schema of the signed manifest a
  deployment publishes, which lists the host data, keys and images it approves.

## Checking a deployment

A deployment publishes each manifest next to the configuration its policy was
generated with. From its API host, `GET /v1/reference-values` returns the
manifest, a compact JWS. The deployment's storage also serves
`reference-values/{environment}/{sequence}.jws` and
`{sequence}.config.json`.

1. Verify the manifest's signature against the deployment's published
   manifest key, and read its `provenance.commit` and `images.worker`.
2. Rebuild the image at that commit (`just image` or
   `nix build .#packages.x86_64-linux.image`). CI builds it on two runners and
   checks that they match, so the rebuild is bit-identical.
3. Run confcom on `worker.json` at that commit with the parameters from
   `{sequence}.config.json`. The Log Analytics key is withheld there, and the
   deployment checks before publishing that the policy comes out the same
   without it.
4. The SHA-256 of the generated policy is the host data, which the manifest's
   `claim_sets` must list, and which an attested worker reports in its MAA token
   (`GET /v1/attestation`).
