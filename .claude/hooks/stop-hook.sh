#!/bin/bash
# Ralph Loop - Same-Session Stop Hook
# This hook runs when Claude attempts to stop, checking if a loop is active.

set -euo pipefail

STATE_FILE=".claude/ralph-loop.local.md"

# Check if loop is active
if [ ! -f "$STATE_FILE" ]; then
  # No loop — allow stop
  echo '{"decision": "allow"}'
  exit 0
fi

# Read state
ACTIVE=$(grep "^active:" "$STATE_FILE" | cut -d: -f2 | tr -d ' ')
ITERATION=$(grep "^iteration:" "$STATE_FILE" | cut -d: -f2 | tr -d ' ')
MAX_ITER=$(grep "^max_iterations:" "$STATE_FILE" | cut -d: -f2 | tr -d ' ')
PROMISE=$(grep "^completion_promise:" "$STATE_FILE" | cut -d: -f2 | tr -d ' "')

if [ "$ACTIVE" != "true" ]; then
  echo '{"decision": "allow"}'
  exit 0
fi

# Check if max iterations reached
if [ "$ITERATION" -ge "$MAX_ITER" ]; then
  rm -f "$STATE_FILE"
  echo '{"decision": "allow"}'
  exit 0
fi

# Check transcript for completion promise
TRANSCRIPT="${CLAUDE_TRANSCRIPT:-}"
if echo "$TRANSCRIPT" | tail -10 | grep -q "<promise>${PROMISE}</promise>"; then
  rm -f "$STATE_FILE"
  echo '{"decision": "allow"}'
  exit 0
fi

# Run verification
VERIFY_OUTPUT=$(CGO_ENABLED=0 go build -o /dev/null ./cmd/certstrike && CGO_ENABLED=0 go test ./... 2>&1) || true
VERIFY_EXIT=$?

# Increment iteration
NEW_ITER=$((ITERATION + 1))
sed -i "s/^iteration: .*/iteration: $NEW_ITER/" "$STATE_FILE"

# Block stop and re-prompt
if [ $VERIFY_EXIT -eq 0 ]; then
  FEEDBACK="Verification PASSED. Continue with the next task from prd.json."
else
  FEEDBACK="Verification FAILED:\n$(echo "$VERIFY_OUTPUT" | tail -20)\n\nFix the issues and try again."
fi

echo "{\"decision\": \"block\", \"reason\": \"Ralph loop iteration $NEW_ITER/$MAX_ITER. $FEEDBACK\"}"
