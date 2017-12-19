#!/usr/bin/env bash
# Deploy to Docker Hub
mkdir -p /root/.docker
cat > /root/.docker/config.json <<- "EOF"
{
        "auths": {
                "https://index.docker.io/v1/": {
                        "auth": "docker_hub_credentials"
                }
        }
}
EOF
sed -i 's/docker_hub_credentials/'"$docker_hub_credentials"'/g' /root/.docker/config.json
docker pull $CONTAINER_TEST_IMAGE_UBU1604
docker tag $CONTAINER_TEST_IMAGE_UBU1604 psono/security-scans:ce-$CI_BUILD_REF_NAME
docker push psono/security-scans:ce-$CI_BUILD_REF_NAME