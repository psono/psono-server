#!/usr/bin/env bash
apk upgrade --no-cache
apk add --update curl

# Deploy to Docker Hub
docker pull psono-docker.jfrog.io/psono/psono-server:latest
docker tag psono-docker.jfrog.io/psono/psono-server:latest psono/psono-server:latest
docker push psono/psono-server:latest

# Inform production stage about new image
curl -X POST https://hooks.microbadger.com/images/psono/psono-server/8BDLpDMSMHR-Ias4JAPRhy0f-cg=

# Deploy to GitHub
echo "Cloning gitlab.com/psono/psono-server.git"
git clone https://gitlab.com/psono/psono-server.git
cd psono-server
git branch --track develop origin/develop
git fetch --all
git pull --all

echo "Empty .ssh folder"
if [ -d "/root/.ssh" ]; then
    rm -Rf /root/.ssh;
fi
mkdir -p /root/.ssh

echo "Fill .ssh folder"
echo "$github_deploy_key" > /root/.ssh/id_rsa
cat > /root/.ssh/known_hosts <<- "EOF"
|1|QihaxuxIU4rUFjd+Zi5Mr3V0oyI=|m1minLYaqd2pSUN52YJk1ROukfY= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
|1|dhFyBNrE6k3jSyFFOoEbeJKgbcs=|W0ag0VmyD+G4NSRpMOGkApaY594= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
EOF
chmod 600 /root/.ssh/id_rsa
chmod 600 /root/.ssh/known_hosts

echo "Push to github.com/psono/psono-server.git"
git remote set-url origin git@github.com:psono/psono-server.git
git push --all origin

echo "Trigger psono combo rebuild"
curl -X POST -F token=$PSONO_COMBO_TRIGGER_TOKEN -F ref=master https://gitlab.com/api/v4/projects/16086547/trigger/pipeline