# Operating GLCI at SAP

This document is for the Garden Linux team operating GLCI in production. It assumes you have read the [GLCI guide](https://github.com/gardenlinux/glci/blob/main/README.md).

## Where things live

- **GLCI** and its **public documentation** live in [gardenlinux/glci on github.com](https://github.com/gardenlinux/glci).
- The GitHub Actions **workflow**, and internal deployment **configurations**, and **internal documentation** (this document) live in [gardenlinux/release-workflow on github.tools.sap](https://github.tools.sap/gardenlinux/release-workflow).

## Quick start

### Production CI

Run the [`glci.yml`](https://github.tools.sap/gardenlinux/release-workflow/actions/workflows/glci.yml) workflow. For a 2150 release, set the following inputs:

| Input | Value |
| --- | --- |
| `op` | `publish` |
| `config` | `glci_2150` |
| `version` | The release version, `2150.<minor>.0`. |
| `commitish` | The Garden Linux commit used to build that release (first 8 characters or full commit). |

Leave the remaining inputs at their defaults. See [The production workflow](#the-production-workflow) for the full input reference.

### Local development and testing

Before running your first test consider reading [Testing considerations](#testing-considerations) for important things you need to know.

If deploying to OpenStack (enabled by default) you need to be on an SAP network or VPN. To obtain valid credentials you need to have your account added to the [Vault repository configuration](https://github.tools.sap/vault-namespaces/vault-namespace-gardnlinux).

Clone and build GLCI:

```sh
git clone https://github.com/gardenlinux/glci.git
cd glci
go build -o glci ./cmd
```

Download [`glci_dev.yaml`](https://github.tools.sap/gardenlinux/release-workflow/blob/main/glci_dev.yaml) into the GLCI checkout.

Obtain a personal Vault token from the Vault UI at `https://vault.tools.sap`. Then use that to obtain a role ID and generate a secret ID, valid for 30 days:

```sh
GLCI_PUBLISHING_CREDENTIALS_ROLE_ID="$(VAULT_ADDR='https://vault.tools.sap' VAULT_TOKEN='<personal-vault-token>' vault read -format=json -namespace=gardnlinux auth/approle/role/dev-local/role-id | jq -er '.data.role_id // empty')" && export GLCI_PUBLISHING_CREDENTIALS_ROLE_ID
GLCI_PUBLISHING_CREDENTIALS_SECRET_ID="$(VAULT_ADDR='https://vault.tools.sap' VAULT_TOKEN='<personal-vault-token>' vault write -format=json -namespace=gardnlinux -f auth/approle/role/dev-local/secret-id | jq -er '.data.secret_id // empty')" && export GLCI_PUBLISHING_CREDENTIALS_SECRET_ID
```

Choose an unpublished test build. You need the version and the commit (either the first 8 characters or the entire commit).

Publish:

```sh
./glci --config-file glci_dev.yaml publish --version '<version>' --commit '<commit>'
```

Unpublish:

```sh
./glci --config-file glci_dev.yaml unpublish --version '<version>' --commit '<commit>'
```

## Configurations

| Configuration | Purpose |
| --- | --- |
| `glci.yaml` | Production publishing for nightlies and future major releases. |
| `glci_2150.yaml` | Production for the 2150 release family. |
| `glci_1877.yaml` | Production for the 1877 release family. |
| `glci_dev.yaml` | Development and testing. |

The workflow selects a configuration by basename without `.yaml`. Keep the versioned configuration for its release family, since flavors and destinations differ between families.

Production publishes the full production flavor set to Aliyun, AWS, Azure, GCP, and OpenStack, plus container images to Artifactory (staging for HCCS, irreversible), and GDC to RBSC. AWS, Azure, and OpenStack also publish to China.

## The production workflow

Production GLCI runs through `glci.yml` in [https://github.tools.sap/gardenlinux/release-workflow](https://github.tools.sap/gardenlinux/release-workflow). The workflow executes the container `ghcr.io/gardenlinux/glci:<glcitag>`.

The workflow makes the deployment configurations available to the container through a bind mount.

| Input | Default | Notes |
| --- | --- | --- |
| `op` | `publish` | `publish`, `unpublish`, `replicate`, `unreplicate`. |
| `config` | `glci_dev` | Configuration basename. |
| `version`, `commitish` | none | Release identity, required. |
| `replicate` | `true` | Applied only when `op` is `publish`. |
| `unreplicate` | `true` | Applied only when `op` is `publish`. |
| `omit_irreversible` | `false` | Applied only when `op` is `publish`. |
| `params` | none | Extra GLCI parameters, passed through. |
| `glcitag` | `latest` | GLCI image tag. |
| `comment` | none | Free-text label for the dispatch. |

The default configuration is `glci_dev` and the default image tag is `latest`, so a careless dispatch runs the latest released binary against the development configuration. For a production run, set `config` to `glci` or the configuration for the relevant major release.

**The component descriptor is the release gate.** Downstream automation observes it as soon as it is published, and it must not be subsequently modified or removed.

## Data flow

- **Inputs.** The build system writes artifacts to S3 and OCI registries. GLCI reads build manifests and image artifacts only from S3.
- **Outputs.** GLCI publishes cloud images to cloud providers, container images to an OCI staging repository in Artifactory, RBSC artifacts to GHCR, and the OCM component descriptor to Google Artifact Registry.
- **Manifests.** Production runs record published image metadata in the source manifests. Development runs write updated manifests to a separate bucket, preserving the shared source manifests.
- **State.** GLCI stores recovery state in S3.

## Environments and accounts

Production and development runs generally use the `gardenlinux` and `gardenlinux-integration-test` credential sets, respectively. The `gardenlinux-cn` set supplies separate China credentials where configured.

Artifact sources, publishing targets, state storage, and descriptor output each select their credentials independently. Production and test destinations can share credentials, and a publishing target can use different credentials from its artifact source. The configuration files define these assignments.

In production, the manifest source bucket, AWS publishing target, and state bucket share the `gardenlinux` AWS account (`544319711298`).

**OpenStack development runs use the production account.** OpenStack has no separate integration-test environment. The development configuration sets `test: true`, which adds `-test` to the flavor portion of image names, before the version and commit. Keep those test images short-lived and remove them promptly.

**OpenStack is reachable only from the SAP network.** Both the self-hosted CI runners and a developer laptop need SAP network access or VPN before GLCI can reach it.

## Credentials

GLCI gets all credentials from Vault at `https://vault.tools.sap`, namespace `gardnlinux`. The credentials are a mix of dynamic engines (AWS, Aliyun, Azure, GCP) and static KV v2 records (OCI registries, OpenStack application credentials, Azure storage).

The accounts, credential sets, and rotation behind these are managed in the [`vault-namespaces/vault-namespace-gardnlinux`](https://github.tools.sap/vault-namespaces/vault-namespace-gardnlinux) Terraform repository, which is the authority for that setup. The detailed account and rotation model is out of scope here.

Authentication methods:

- **CI** uses Vault JWT (mount `jwt-ghtools`, role `prod-glci`), driven by GitHub OIDC.
- **Local one-off runs** use a personal Vault token, supplied through `GLCI_PUBLISHING_CREDENTIALS_TOKEN`. Tokens are issued for six hours and can be renewed up to the maximum lifetime set by Vault policy.
- **Persistent local setups** use AppRole. Supply the role ID through `GLCI_PUBLISHING_CREDENTIALS_ROLE_ID` and the secret ID through `GLCI_PUBLISHING_CREDENTIALS_SECRET_ID`. The secret ID is valid for 30 days.

## Versioning and the build pipeline

Garden Linux maintains `main` and release branches such as `rel-2150` in `gardenlinux/gardenlinux`. GLCI is not branched per release. Release-specific configuration files determine how it publishes each Garden Linux release family.

GLCI's repository has two workflows, both required to merge a pull request:

- **Validate** (`validate.yaml`) currently runs lint checks only. A test suite is planned.
- **Build and publish container image** (`publish-container.yaml`) builds the multi-architecture (`amd64` and `arm64`) image and pushes it to `ghcr.io/gardenlinux/glci` on pull requests and pushes to `main`. Publishing a GitHub release also triggers the workflow to build and push its image. Images are tagged `pr-<number>` for a pull request, `main` for a main-branch build, and the version number for a release.

Builds triggered by a GitHub release update the `latest` image tag, which the production workflow uses by default.

## Testing considerations

`glci_dev.yaml` sets `steamroll: true` and `omit-irreversible: true`. Explicit command-line flags override these configuration defaults.

Whatever you publish for a test, unpublish it as soon as the test is done. Published test resources should not outlive the test.

For a production test (publishing into a production account), always pass `--omit-irreversible`, so the run stays reversible and skips the containers and descriptor, and unpublish promptly afterward.

OpenStack development images are published into the production account with `test: true`, which adds `-test` to the flavor portion of image names, before the version and commit. Keep them short-lived.

China replication timing is unpredictable. A CI replicate can finish in under five minutes or take hours. For a production test, consider pre-replicating through the CI workflow (`op=replicate`).

## Contacts

If you have any issues contact Georgi Chulkov or Sascha Schmerling.
