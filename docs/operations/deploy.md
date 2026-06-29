# Deploying the pipeline on AWS (Prefect Cloud + ECS Fargate)

The corpus build runs as **Prefect** flows on **ECS Fargate** tasks (per-source
isolation, pay-per-run), versions outputs with **DVC** on **S3**, and reads API
keys from **Secrets Manager** at runtime. Architecture rationale is in the plan;
this is the runbook.

```
GitHub Actions ──build/push──> ECR ──image──> ECS Fargate task
       │                                           │ run by
   prefect deploy ──> Prefect Cloud ──schedule──> ECS push work pool
                                                   │ reads
                              Secrets Manager + S3 (DVC remote)
```

## 1. Provision infrastructure (Terraform)

```bash
cd infra
terraform init
terraform apply -var data_bucket_name=<globally-unique-bucket> -var region=us-east-1
```

Outputs you'll need: `ecr_repository_url`, `data_bucket`, `ecs_cluster_arn`,
`task_role_arn`, `execution_role_arn`, `secret_arns`.

Set the secret values (out of band — never in Terraform/Git):

```bash
aws secretsmanager put-secret-value --secret-id cybersec-slm/nvd-api-key --secret-string '...'
aws secretsmanager put-secret-value --secret-id cybersec-slm/kaggle-api-token --secret-string '...'
# ... google-search-api-key, google-search-engine-id
```

## 2. Build + push the image

CI does this on a `v*` tag (`.github/workflows/deploy.yml`). Manually:

```bash
aws ecr get-login-password | docker login --username AWS --password-stdin <ecr_url>
docker build -t <ecr_url>:latest .
docker push <ecr_url>:latest
```

## 3. Configure Prefect Cloud

```bash
prefect cloud login
# ECS push work pool targeting the Terraform-created cluster/roles:
prefect work-pool create ecs-pool --type ecs:push
#   then set, in the pool's base job template: cluster = <ecs_cluster_arn>,
#   task role = <task_role_arn>, execution role = <execution_role_arn>, image = <ecr_url>.
```

Wire the secrets into `prefect-aws` blocks (the flow's `load_secrets` reads these):

```bash
prefect block register -m prefect_aws
# create one AwsSecret block per key, named to match SECRET_KEYS in flows.py
#   (nvd-api-key, kaggle-api-token, google-search-api-key, google-search-engine-id)
```

## 4. Register + run the deployment

```bash
prefect deploy --all          # registers build-corpus from prefect.yaml (weekly cron)
prefect deployment run 'build-corpus/build-corpus'   # kick off once to smoke test
```

The DVC remote is set once (see `docs/operations/dvc.md`): `dvc remote add -d s3 s3://<data_bucket>/dvc`.
With `dvc_push: true` (default in `prefect.yaml`), each run snapshots + pushes the
versioned `dataset.jsonl` release to S3.

## Required GitHub secrets / vars (for CI deploy)

| Name | Kind | Purpose |
|---|---|---|
| `AWS_DEPLOY_ROLE_ARN` | secret | OIDC role CI assumes to push to ECR |
| `AWS_REGION` | var | region |
| `PREFECT_API_URL`, `PREFECT_API_KEY` | secret | register the deployment |

## Least privilege (threat model: Access Control)

The ECS **task role** can only RW the one data bucket and read the four named
secrets — nothing else. The image holds **no** credentials; everything sensitive
is injected at runtime.
