#!/usr/bin/env bash
apt-get update && \
apt-get install -y lsb-release curl gnupg && \
export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)" && \
echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
apt-get update && apt-get -y install google-cloud-sdk && \
echo "$GOOGLE_APPLICATION_CREDENTIALS" > "/root/key.json" && \
gcloud auth activate-service-account --key-file=/root/key.json && \
curl -H "PRIVATE-TOKEN: $GITLAB_PERSONAL_ACCESS_TOKEN" "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/repository/tags" --output changelog.json && \
gsutil cp changelog.json gs://static.psono.com/gitlab.com/$CI_PROJECT_PATH/changelog.json