#!/usr/bin/env bash

set -eu

GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)

export BIN_PATH=_output/bin
export PLUGIN_PATH=_output/plugins

mkdir -p ${BIN_PATH}
mkdir -p ${PLUGIN_PATH}

echo "Building microshift and ovn-kubernetes plugins ..."
CGO_ENABLED=1 GOOS=${GOOS} GOARCH=${GOARCH} go build -buildmode=plugin -ldflags "-s -w" -o ${PLUGIN_PATH}/ovn_kubernetes_plugin.so pkg/plugins/ovn-kubernetes-plugin.go
CGO_ENABLED=1 GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags "-s -w" -o ${BIN_PATH}/microshift cmd/microshift/main.go
