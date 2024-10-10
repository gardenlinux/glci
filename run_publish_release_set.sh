#!/usr/bin/env bash

pip install networkx
pip install ocm-lib

"$MAIN_REPO_DIR/publish-release-set" "$@"
