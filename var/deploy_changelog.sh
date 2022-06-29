#!/usr/bin/env bash
apt-get update && \
apt-get install -y curl python3 && \
curl -fSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-392.0.0-linux-x86_64.tar.gz" -o google-cloud-cli.tar.gz && echo "a7e88856a07ed75cf310ebe5415c922c9b516021a6c7e66b3eb8f2859b9351bc google-cloud-cli.tar.gz" | sha256sum -c - && tar -xzvf google-cloud-cli.tar.gz  && \
./google-cloud-sdk/install.sh -q && \
echo "$GOOGLE_APPLICATION_CREDENTIALS" > "/root/key.json" && \
./google-cloud-sdk/bin/gcloud auth activate-service-account --key-file=/root/key.json && \
curl -H "PRIVATE-TOKEN: $GITLAB_PERSONAL_ACCESS_TOKEN" "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/repository/tags" --output changelog.json && \
./google-cloud-sdk/bin/gsutil cp changelog.json gs://static.psono.com/gitlab.com/$CI_PROJECT_PATH/changelog.json