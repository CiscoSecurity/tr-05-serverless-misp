#! /usr/bin/env sh
if [[ -z "${DEBUG}" ]]; then
	echo "[start.sh] DEBUG MODE OFF" >> /var/log/messages
else
	echo "[start.sh] DEBUG MODE ON" >> /var/log/messages
	echo "[start.sh] ............." >> /var/log/messages
	echo "[start.sh] Integration Module: " `jq -r .NAME /app/container_settings.json` >> /var/log/messages
	echo "[start.sh]            Version: " `jq -r .VERSION /app/container_settings.json` >> /var/log/messages
	echo "[start.sh] Starting supervisord ..." >> /var/log/messages
	echo "[start.sh] ............." >> /var/log/messages
fi
set -e
exec /usr/bin/supervisord -c /supervisord.ini
