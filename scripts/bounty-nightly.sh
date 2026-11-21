#!/usr/bin/env bash
# Nightly pipeline run: `bounty run`, refresh this week's digest, post a one-line summary to Slack.
#
# Installed in cron (01:30, when llm-server is usually idle):
#   30 1 * * * /home/maqo/projects/bounty-agent/scripts/bounty-nightly.sh >> /home/maqo/projects/bounty-agent/data/nightly.log 2>&1
#
# Slack: same pattern as the other cron jobs on this machine. SLACK_WEBHOOK_URL is loaded
# from ~/.bashrc_env at runtime (cron doesn't inherit the shell env). It is never printed
# or stored in the repo. A failed Slack post is a warning, never a failed run.
#
# Env:
#   BOUNTY_MAX_MINUTES     cap on draining the local queue (default 300)
#   BOUNTY_SLACK_DRY_RUN=1 print the Slack payload instead of posting it
set -uo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
cd "$(dirname "$0")/.."

if [[ -f "$HOME/.bashrc_env" ]]; then
    set +u
    # shellcheck disable=SC1091
    source "$HOME/.bashrc_env"
    set -u
fi

post_slack() {
    local text=$1 payload
    if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
        echo "SLACK_WEBHOOK_URL is not set; skipping the Slack post" >&2
        return 0
    fi
    payload=$(python3 -I -c 'import json, sys; print(json.dumps({"text": sys.argv[1]}))' "$text")
    if [[ "${BOUNTY_SLACK_DRY_RUN:-0}" == 1 ]]; then
        echo "[dry run] would post to Slack: $payload"
        return 0
    fi
    curl -fsS -m 20 -X POST -H 'Content-Type: application/json' --data "$payload" "$SLACK_WEBHOOK_URL" >/dev/null \
        || echo "Slack post failed; the run itself is unaffected" >&2
}

echo "=== $(date -Is) nightly run"
uv run --locked bounty run --max-minutes "${BOUNTY_MAX_MINUTES:-300}"
status=$?
# 3 = another run still holds the lock: not an error worth alerting on.
if [[ $status -eq 3 ]]; then status=0; fi

summary=$(uv run --locked bounty digest --short 2>&1) || summary="bounty-agent: digest failed ($summary)"
echo "$summary"
if [[ $status -eq 0 ]]; then
    post_slack ":white_check_mark: $summary"
else
    post_slack ":warning: $summary (bounty run exited $status; see data/nightly.log)"
fi
exit $status
