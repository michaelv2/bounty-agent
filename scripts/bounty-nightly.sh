#!/usr/bin/env bash
# Nightly pipeline run: `bounty run`, then refresh this week's digest.
#
# Schedule it from cron or a systemd user timer, e.g. at 01:30 when llm-server is idle:
#   30 1 * * *  notify-on-complete /home/maqo/projects/bounty-agent/scripts/bounty-nightly.sh
# (drop `notify-on-complete` if you don't want the Slack alert). The last line printed is
# the one-line digest summary, which is what a completion alert should show.
#
# Env: BOUNTY_MAX_MINUTES (default 300) caps how long the local queue is drained.
set -uo pipefail
cd "$(dirname "$0")/.."

uv run --locked bounty run --max-minutes "${BOUNTY_MAX_MINUTES:-300}"
status=$?
# 3 = another run still holds the lock: not an error worth alerting on.
if [[ $status -eq 3 ]]; then status=0; fi

uv run --locked bounty digest --short
exit $status
