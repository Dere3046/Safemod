#!/usr/bin/env bash
set -e

TARGETS="android12-5.10 android13-5.15 android14-5.15 android16-6.12"
IMG_BASE=docker.cnb.cool/ylarod/ddk/ddk-min
DIR="$(cd "$(dirname "$0")" && pwd)/kernel"

for target in $TARGETS; do
	echo "== building $target"
	docker run --rm -v "${DIR}":/src -w /src "${IMG_BASE}:${target}" make
	mkdir -p "${DIR}/../out/${target}"
	cp "${DIR}/safemod.ko" "${DIR}/../out/${target}/"
	echo "== done $target -> out/${target}/safemod.ko"
done
