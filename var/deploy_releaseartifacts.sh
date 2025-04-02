#!/usr/bin/env bash
apt-get update && \
apt-get install -y lsb-release curl gnupg && \
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && \
apt-get update -y && apt-get install google-cloud-cli -y && \
echo "$GOOGLE_APPLICATION_CREDENTIALS" > "/root/key.json" && \
gcloud auth activate-service-account --key-file=/root/key.json && \
gsutil cp sbom.json gs://get.psono.com/$CI_PROJECT_PATH/latest/sbom.json && \
gsutil cp sbom.json gs://get.psono.com/$CI_PROJECT_PATH/$CI_COMMIT_REF_NAME/sbom.json
