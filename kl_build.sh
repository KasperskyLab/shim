#!/bin/bash
set -e

OUT_DIR="${PWD}/out"
mkdir -p "${OUT_DIR}"

exec &> >(tee "${OUT_DIR}/build.log")

docker build -t kl-shim-build .
docker run --rm -t -v "${OUT_DIR}:/out" kl-shim-build
