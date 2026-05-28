#!/usr/bin/env bash
set -euo pipefail
export STRIPE_SECRET_KEY="sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"
export SLACK_BOT_TOKEN="xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx"
export DISCORD_BOT_TOKEN="MTAxK3p7QxR4mN9sBv2Ta5Yc.Gd7Wx2A.Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm"
aws s3 sync ./build/ s3://prod-deployments/
