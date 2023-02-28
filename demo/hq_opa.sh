#!/usr/bin/env bash

opa run -s \
  --addr=:8182 \
  --tls-ca-cert-file=ca.pem \
  --tls-cert-file=svid__clusters_hq_opa_cert.pem \
  --tls-private-key-file=svid__clusters_hq_opa_key.pem \
  --authentication=tls \
  --authorization=basic \
  --config-file=demo/hq_config.yaml
