#!/bin/bash

INFOPLIST="$1/Info.plist"

if [ -f "${INFOPLIST}" ]; then
    defaults delete "${INFOPLIST}" UISupportedDevices >/dev/null 2>&1
fi

if [ -n "$2" ]; then
    defaults write "${INFOPLIST}" MinimumOSVersion $2 >/dev/null 2>&1
fi

echo "******* fix MinimumOSVersion and delete UISupportedDevices *******"

exit 0
