# Build context is the repository root so Dockerfile.full can COPY
# mcprack/static, templates, and app.py over the apt-installed package.

all:
	cd ../.. && docker buildx build -f deploy/docker/Dockerfile . --push --tag vitexsoftware/mcprack

full:
	cd ../.. && docker buildx build -f deploy/docker/Dockerfile.full . --push --tag vitexsoftware/mcprack:full
