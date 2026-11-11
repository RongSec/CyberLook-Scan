#!/usr/bin/env bash
# build-cli.sh —— 多平台出包 cyberlook-scan CLI
#
# 产物：<repo>/dist/v<版本>/cyberlook-scan-<os>-<arch>[.exe]
#   linux:   amd64 / arm64 / 386 / mipsle(GOMIPS=softfloat)
#   windows: amd64
# 全部 CGO_ENABLED=0 + -trimpath + -ldflags "-s -w"（纯 Go，无 gcc 依赖，
# 麒麟/老旧发行版直接可用）。版本号取 cmd/cyberlook-scan/main.go 的 const version。
#
# 用法：
#   bash scripts/build-cli.sh     # 本机有 go 用本机；否则自动用 docker golang:1.26-alpine
set -euo pipefail
# Git Bash 下 docker.exe 参数 "/src" 会被 MSYS 路径换算破坏；关闭换算。
export MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."
REPO="$(pwd)"

VERSION="${VERSION:-$(sed -n 's/^const version = "\(.*\)"/\1/p' cmd/cyberlook-scan/main.go)}"
[ -n "$VERSION" ] || { echo "无法确定版本号"; exit 1; }
OUT="$REPO/dist/v$VERSION"
mkdir -p "$OUT"

LDF="-s -w"
TARGETS=(
  "linux amd64"
  "linux arm64"
  "linux 386"
  "linux mipsle GOMIPS=softfloat"
  "windows amd64"
)

build_one() { # os arch [GOMIPS=softfloat]
  local os=$1 arch=$2 extra=${3:-}
  local name="cyberlook-scan-$os-$arch"
  [ "$os" = windows ] && name="$name.exe"
  echo "==> $os/$arch ${extra:-}"
  # shellcheck disable=SC2086
  env GOOS=$os GOARCH=$arch $extra CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags="$LDF" -o "$OUT/$name" ./cmd/cyberlook-scan
}

if command -v go >/dev/null 2>&1; then
  for t in "${TARGETS[@]}"; do
    # shellcheck disable=SC2086
    build_one $t
  done
elif command -v docker >/dev/null 2>&1; then
  src="$REPO"
  case "$src" in
    /?/*) src="$(printf '%s' "${src:1:1}" | tr 'a-z' 'A-Z'):${src:2}" ;;
  esac
  docker run --rm --platform linux/amd64 \
    -v "$src:/src" \
    -v gocache-clsbuild:/root/.cache/go-build \
    -v gomod-clsbuild:/go/pkg/mod \
    -e GOFLAGS=-buildvcs=false -e CGO_ENABLED=0 \
    -e GOPROXY="${GOPROXY:-https://goproxy.cn,direct}" \
    -w /src golang:1.26-alpine sh -c '
      set -e; cd /src
      for t in "linux amd64" "linux arm64" "linux 386" "linux mipsle GOMIPS=softfloat" "windows amd64"; do
        set -- $t
        os=$1; arch=$2; extra=${3:-}
        name="cyberlook-scan-$os-$arch"
        [ "$os" = windows ] && name="$name.exe"
        echo "==> $os/$arch ${extra:-}"
        if [ -n "$extra" ]; then
          GOOS=$os GOARCH=$arch GOMIPS=softfloat go build -trimpath -ldflags="-s -w" -o "dist/v'"$VERSION"'/$name" ./cmd/cyberlook-scan
        else
          GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "dist/v'"$VERSION"'/$name" ./cmd/cyberlook-scan
        fi
      done
    '
else
  echo "需要 go 或 docker"; exit 1
fi

echo
echo "产物（v$VERSION）："
ls -la "$OUT"
