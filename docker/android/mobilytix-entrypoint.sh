#!/bin/bash
# Run mobilytix init (frida, drozer, proxy) in background,
# then hand off to the base image's original startup script.
/start.sh &
exec sh -c "${APP_PATH}/mixins/scripts/run.sh"
