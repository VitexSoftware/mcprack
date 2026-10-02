# Build context is the repository root so Dockerfile.full can COPY
# mcprack/ over the apt-installed package.

all:
	cd ../.. && docker buildx build --pull -f deploy/docker/Dockerfile . --push --tag vitexsoftware/mcprack

# Prefer cached apt layers when repo/backports are flaky; force a fresh
# apt solve with: make full-nocache
full:
	cd ../.. && docker buildx build --pull -f deploy/docker/Dockerfile.full . --push --tag vitexsoftware/mcprack:full

full-nocache:
	cd ../.. && docker buildx build --pull --no-cache -f deploy/docker/Dockerfile.full . --push --tag vitexsoftware/mcprack:full
