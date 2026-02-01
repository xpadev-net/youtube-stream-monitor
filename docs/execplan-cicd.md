# CI/CD build automation ExecPlan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with .agent/PLANS.md.

## Purpose / Big Picture

The goal is to make every change automatically testable and to publish Docker images without manual steps. After this work, pushing a change or opening a pull request will run tests, and a manual or main-branch build will publish the gateway, worker, and webhook-demo images to GHCR. A human can see it working by observing green GitHub Actions runs and by confirming new image tags are visible in GHCR for this repository.

## Progress

- [x] (2026-02-02 00:10Z) Draft and implement GitHub Actions workflows for CI tests and image builds.
- [x] (2026-02-02 00:10Z) Document verification steps and expected outputs in this ExecPlan.

## Surprises & Discoveries

- Observation: None yet.
  Evidence: Not applicable.

## Decision Log

- Decision: Use GitHub Actions as the CI platform and GHCR as the image registry, and automate image builds without deployment.
  Rationale: The repository is on GitHub and GHCR provides first-class integration for image publishing; the user requested image build automation only.
  Date/Author: 2026-02-02 / GitHub Copilot

- Decision: Do not include scheduled rebuilds for dependency refresh.
  Rationale: The user requested no schedule and manual-only rebuilds.
  Date/Author: 2026-02-02 / GitHub Copilot

## Outcomes & Retrospective

- Outcome (2026-02-02): Added GitHub Actions workflows for test runs and GHCR image builds. Remaining validation depends on GitHub Actions runs and GHCR visibility.

## Context and Orientation

This repository contains three Go services with corresponding Dockerfiles: a gateway service at [Dockerfile.gateway](Dockerfile.gateway), a worker service at [Dockerfile.worker](Dockerfile.worker), and a webhook-demo service at [Dockerfile.webhook-demo](Dockerfile.webhook-demo). A Docker image is a packaged filesystem and metadata that can be run as a container; here the Dockerfiles define how to build those images. The local development stack uses [docker-compose.yaml](docker-compose.yaml), and Kubernetes deployment settings are in the Helm chart under [helm/stream-monitor](helm/stream-monitor). There is currently no CI configuration, so tests and image builds are manual.

The plan will add GitHub Actions workflows. CI (continuous integration) means automatic checks run when code changes are pushed or proposed; here it will run `go test ./...`. CD (continuous delivery) usually means deploying automatically; in this plan CD is limited to building and publishing images only, with no automated deployment. GHCR (GitHub Container Registry) is the image registry where built images will be pushed.

## Plan of Work

First, add a CI workflow file at .github/workflows/ci.yml that runs on pull requests and pushes to the default branch. It will check out the code, set up the Go toolchain, and run `go test ./...` in the repository root. The workflow will use a stable Go version aligned with go.mod and will include the minimal permissions needed to read the repository.

Second, add an image build workflow at .github/workflows/build-images.yml. It will run on pushes to the default branch and on manual dispatch. It will authenticate to GHCR using the GitHub Actions token, build images for the gateway, worker, and webhook-demo targets using their Dockerfiles, and push tags to GHCR. The image tags will include the commit SHA for traceability and `latest` for the default branch. The workflow will use Docker Buildx with cache to speed up rebuilds.

Third, update this ExecPlan as the work proceeds: record progress timestamps, note any surprises or deviations, and append a brief outcomes summary once the workflows are in place.

## Concrete Steps

All commands below are run from the repository root.

1) Create .github/workflows/ci.yml with a job named `test` that uses actions/checkout and actions/setup-go, then runs:

    go test ./...

2) Create .github/workflows/build-images.yml with a matrix over three images. For each matrix entry, build and push using the corresponding Dockerfile and image name. The image naming convention is:

    ghcr.io/<owner>/<repo>-gateway
    ghcr.io/<owner>/<repo>-worker
    ghcr.io/<owner>/<repo>-webhook-demo

3) Ensure both workflows are committed and visible in GitHub Actions.

4) Update Progress and Outcomes sections in this ExecPlan when each step is completed.

## Validation and Acceptance

Validation should be done in two ways.

First, run tests locally to confirm the CI command works:

    go test ./...

Expected result: tests complete without failures.

Second, verify CI and image publication:

- Open or update a pull request and confirm the CI workflow runs and passes.
- Trigger the build workflow on the default branch (push or manual dispatch) and confirm all three images are pushed to GHCR with new tags.

Acceptance is met when a user can see green GitHub Actions runs for the test workflow and can see updated image tags for all three services in GHCR.

## Idempotence and Recovery

Re-running the workflows is safe because the steps are read-only checks (tests) and image pushes with deterministic tags. If a build fails halfway, re-run the workflow after fixing the cause; no manual cleanup is required. SHA-based tags are immutable, while the `latest` tag is intentionally updated on each push to the default branch.

## Artifacts and Notes

Expected CI log excerpt for tests:

    go test ./...
    ok   github.com/<owner>/<repo>/internal/ids 0.012s
    ok   github.com/<owner>/<repo>/internal/api 0.123s

Expected log excerpt for image push:

    pushing layers
    pushed ghcr.io/<owner>/<repo>-gateway:sha-<commit>

## Interfaces and Dependencies

The workflows will depend on the following GitHub Actions:

- actions/checkout: checks out the repository source code.
- actions/setup-go: installs the Go toolchain used to run tests.
- docker/setup-qemu-action and docker/setup-buildx-action: enable Buildx for multi-stage builds.
- docker/login-action: authenticates to GHCR using the GitHub Actions token.
- docker/build-push-action: builds and pushes images defined by the Dockerfiles.

No application code interfaces are changed by this plan; only CI configuration files will be added.

Change Log: Created initial ExecPlan and implemented workflows for CI tests and GHCR image builds without scheduled rebuilds.
