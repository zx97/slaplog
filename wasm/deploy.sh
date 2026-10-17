#!/usr/bin/env bash
#
# deploy.sh - Build the slaplog WebAssembly page and publish it to Cloudflare
#             Pages, so that refreshing it is a single command.
#
#   ./wasm/deploy.sh                     # build + deploy to the production branch
#   SKIP_BUILD=1 ./wasm/deploy.sh        # deploy the current artefacts as-is
#   PROJECT=other ./wasm/deploy.sh       # target another Pages project
#   BRANCH=preview ./wasm/deploy.sh      # deploy to a preview branch
#
# PREREQUISITES
#   - Emscripten SDK activated (em++ on PATH) unless SKIP_BUILD=1
#   - a logged-in wrangler with access to the Pages project:
#         npx wrangler login
#
# NOTE ON THE FIRST DEPLOYMENT
#   Creating the Pages project must be done once with the legacy flow:
#       npx wrangler pages project create <name> --production-branch main --force
#   without --force the command is delegated to Cloudflare Workers and fails.
#   Subsequent deploys (this script) run directly against Pages.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PROJECT:-slaplog}"
BRANCH="${BRANCH:-main}"
WEB_DIR="$ROOT_DIR/wasm/web"
WRANGLER="${WRANGLER:-npx -y wrangler@latest}"

log() { printf '\033[36m[deploy]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[deploy] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    command -v em++ >/dev/null 2>&1 \
        || die "em++ not found — activate the Emscripten SDK first (or set SKIP_BUILD=1)"
    log "building the WebAssembly artefacts"
    make -C "$ROOT_DIR" wasm
else
    log "SKIP_BUILD=1 — using the artefacts already in wasm/web"
fi

for f in index.html slaplog.js slaplog.wasm; do
    [[ -f "$WEB_DIR/$f" ]] || die "$WEB_DIR/$f is missing — run 'make wasm' first"
done

log "deploying $(du -sh "$WEB_DIR" | cut -f1) to Pages project '$PROJECT' (branch '$BRANCH')"
# shellcheck disable=SC2086
$WRANGLER pages deploy "$WEB_DIR" --project-name "$PROJECT" --branch "$BRANCH"

log "done — https://${PROJECT}.pages.dev/"
