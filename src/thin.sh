#!/bin/bash

executablePath="$1"
ARCH='arm64'

fatHeader=`otool -f "${executablePath}"`
if [ -n "${fatHeader}" ]; then
    fat=true
else
    fat=false
fi

if [ "$fat" == true ]; then
    thinPath="${executablePath}"_"${ARCH}"
    lipo "${executablePath}" -thin "${ARCH}" -output "${thinPath}"
    mv "${thinPath}" "${executablePath}"
fi

