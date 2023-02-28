#!/usr/bin/env bash

opa run -s \
  --tls-ca-cert-file=ca.pem \
  --tls-cert-file=svid__clusters_station1_opa_cert.pem \
  --tls-private-key-file=svid__clusters_station1_opa_key.pem \
  --authentication=tls \
  --authorization=basic \
  --config-file=demo/station1_config.yaml
