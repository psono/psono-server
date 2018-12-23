#!/usr/bin/env bash

if [ -z "$CI_COMMIT_TAG" ]; then
	exit 0
fi

if [ -z "$CI_COMMIT_SHA" ]; then
	exit 0
fi

if ! echo "$CI_COMMIT_TAG" | egrep -q ^v[0-9]+\.[0-9]+\.[0-9]+$; then
	exit 0
fi

version="$(echo $CI_COMMIT_TAG | awk  '{ string=substr($0, 2, 100); print string; }' ) (Build $(echo $CI_COMMIT_SHA | awk  '{ string=substr($0, 1, 8); print string; }' ))"

echo $version > ./psono/VERSION.txt
echo $CI_COMMIT_SHA > ./psono/SHA.txt
