#!/usr/bin/env sh
set -e

# Grab the repository
if [ -n "$GITREPO" ]; then
  echo "rm -rf /app && git clone $GITREPO /app"
  rm -rf /app && git clone $GITREPO /app
fi


if [ -n "$ALPINEPYTHON" ] ; then
    export PYTHONPATH=$PYTHONPATH:/usr/local/lib/$ALPINEPYTHON/site-packages:/usr/lib/$ALPINEPYTHON/site-packages
fi

exec "$@"
