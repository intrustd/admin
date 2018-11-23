#!/bin/sh

npm run local-build
tar cjvf admin-local.tar.gz dist-local

echo "Built admin-local.tar.gz"
