#! /usr/bin/env sh
echo " .:|:.:|:. "
echo " C I S C O "
echo "  SecureX "
echo
echo " Development Dockerfile build script."
echo

module_name="MISP"
image_name="tr-05-misp"

CONFIG_FILE=code/container_settings.json
if [ -f $CONFIG_FILE ]; then
   echo
   echo "The configuration file (container_settings.json) already exists."
   echo
   version=`jq -r .VERSION code/container_settings.json`
else
   read -p 'Version: ' version
   echo {\"VERSION\": \"$version\", \"NAME\": \"$module_name\"} > code/container_settings.json
fi

echo " Integration Module: $module_name"
echo "            Version: $version"
echo
echo "Starting build process ..."
echo
docker build -t "$image_name:$version" .

echo
echo "Please ensure you update module_type.json with correct url."
echo
