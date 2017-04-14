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
docker pull registry.gitlab.com/psono/psono-server:latest
docker tag registry.gitlab.com/psono/psono-server:latest psono/psono-server:latest
docker push psono/psono-server:latest

# Inform production stage about new image
curl -X POST https://hooks.microbadger.com/images/psono/psono-server/8BDLpDMSMHR-Ias4JAPRhy0f-cg=
curl -X POST $psono_image_updater_url

# Deploy to GitHub
mkdir -p /root/.ssh
echo $github_deploy_key > /root/.ssh/id_rsa
git clone https://gitlab.com/psono/psono-server.git
cd psono-server
git remote set-url origin git@github.com:psono/psono-server.git
git push -u origin master
