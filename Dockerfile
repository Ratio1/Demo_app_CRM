# Demo_App_CRM — one image, one process (PLAN.md §1 Deliverable).
#
# Base image, resolved on this machine 2026-09-21 by `docker pull python:3.12-slim`:
#
#   index digest (multi-arch — what a repo digest names)  sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
#   linux/amd64 manifest digest                           sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b
#   org.opencontainers.image.version                      3.12.14-slim-trixie
#   CPython 3.12.14, Debian GNU/Linux 13.7 (trixie), pip 25.0.1
#
# The index digest is what is pinned below: it is the digest `docker pull
# python:3.12-slim@sha256:...` accepts, it is immutable, and it keeps this file
# architecture-neutral instead of hard-coding the amd64 leaf. The amd64 leaf is
# recorded above so a reader can check exactly which manifest this machine ran.
#
# Inherited VOLUME: none. `docker image inspect` reports `Config.Volumes = null`
# and `docker history --no-trunc` contains zero VOLUME entries, which is the
# local confirmation PLAN.md §5 requires before the digest is pinned at all.
# This file declares no VOLUME of its own either (spec §8).
#
# Three named stages on ONE linear chain. Nothing is copied between stages, so
# `runtime` is byte-for-byte what a single-stage build would produce. `deps`
# exists so the dependency install can be built and timed on its own —
# PLAN.md §6: "Build resources are measured separately by timing the dependency
# install from requirements.lock.txt inside the same capped container":
#
#   docker build --target deps -t demo-crm-app:p0 .
#
# No RUN imports the application (PLAN.md §5 "DB-free build proof"), no DB_*
# variable is read at build time, and there is no HEALTHCHECK: `/health/live`
# and `/health/ready` are the deployer's probes and are documented in DEPLOY.md,
# and spec §8 is explicit that Dockerfile health settings are not evidence of
# anything. Runtime configuration is only the five variables of CONTRACTS.md §2,
# supplied by the deployer; none of them has a default here.

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS base

# PYTHONDONTWRITEBYTECODE covers anything the entrypoints re-exec; `python -B`
# in scripts/start and scripts/manage covers the entrypoints themselves. It does
# NOT suppress pip's own explicit compileall pass (verified: a package installed
# with the variable set still ships its .pyc), so the interpreter never needs to
# write bytecode on the read-only root filesystem at runtime.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# A fixed, high, non-reserved uid/gid so the numeric USER below is stable and
# does not collide with a host account. -M: no home directory — the rootfs is
# read-only at runtime and the process has nothing to write anywhere.
RUN groupadd --system --gid 10001 crm \
 && useradd --system --uid 10001 --gid 10001 -M --home-dir /nonexistent \
            --shell /usr/sbin/nologin crm


FROM base AS deps

# The hash-pinned install input, exported from the committed uv.lock by
#   uv export --frozen --no-dev --hashes -o requirements.lock.txt
# --require-hashes puts pip in hash-checking mode, which additionally refuses
# any requirement that is not pinned with `==` and hashed — including one pulled
# in transitively. So this line fails the build if the exported closure is
# incomplete, rather than shipping an unverified wheel. Deliberately no
# `pip install --upgrade pip`: that would be an unpinned network fetch inside a
# build whose whole point is that every byte installed is hash-checked.
COPY requirements.lock.txt ./
RUN python -B -m pip install --require-hashes --no-cache-dir -r requirements.lock.txt


FROM deps AS runtime

COPY app/ ./app/
COPY migrations/ ./migrations/
COPY scripts/ ./scripts/

# Non-root from here on, by number so it holds even if /etc/passwd were absent.
# Everything above is owned by root and mode 0755/0644: the application user can
# read and execute the code and can write nothing, which is what a read-only
# root filesystem is meant to make redundant rather than rely on.
USER 10001:10001

# Documentation only; the port is bound by scripts/start and published by the
# deployer. The container listens on 0.0.0.0:3000 (spec §8).
EXPOSE 3000

# scripts/start is the single start command. Relative to WORKDIR, exec form, so
# uvicorn is PID 1 and SIGTERM reaches it directly with no shell in between.
CMD ["scripts/start"]
