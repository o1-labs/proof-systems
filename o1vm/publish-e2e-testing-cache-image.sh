#!/usr/bin/env bash
set -euo pipefail

# ARCH="amd64"
DOCKER_FILE_NAME="Dockerfile-e2e-testing-cache"
DOCKER_HUB_USER_NAME="o1labs"
DOCKER_HUB_REPO_NAME="proof-systems"
DOCKER_HUB_IMAGE_TAG="o1vm-e2e-testing-cache"
DOCKER_IMAGE_FULL_NAME="${DOCKER_HUB_USER_NAME}/${DOCKER_HUB_REPO_NAME}:${DOCKER_HUB_IMAGE_TAG}"

echo ""
echo "Building the '${DOCKER_IMAGE_FULL_NAME}' Docker image..."
echo ""
docker rmi -f ${DOCKER_IMAGE_FULL_NAME} || true
docker rmi -f ${DOCKER_HUB_IMAGE_TAG} || true
# docker build --platform linux/${ARCH} -t ${DOCKER_HUB_IMAGE_TAG} -f ${DOCKER_FILE_NAME} .
docker build -t ${DOCKER_HUB_IMAGE_TAG} -f ${DOCKER_FILE_NAME} .

echo ""
echo "Publishing the '${DOCKER_IMAGE_FULL_NAME}' Docker image..."
echo ""
docker tag ${DOCKER_HUB_IMAGE_TAG} ${DOCKER_IMAGE_FULL_NAME}
docker push ${DOCKER_IMAGE_FULL_NAME}
echo ""
