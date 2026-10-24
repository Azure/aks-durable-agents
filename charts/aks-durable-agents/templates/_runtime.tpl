{{- define "agents.validateRuntime" -}}
{{- if eq .Values.runtime.mode "substrate" -}}
{{- if not .Values.networkPolicy.enabled -}}{{ fail "Substrate runtime requires NetworkPolicy separation" }}{{- end -}}
{{- range $name := list "atespace" "templateAtespace" "template" -}}
{{- if not (get $.Values.runtime.substrate $name) -}}{{ fail (printf "runtime.substrate.%s is required" $name) }}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "agents.substrateFlags" -}}
- {{ printf "-substrate-harness=%s=%s/%s" .Values.harness.name .Values.runtime.substrate.templateAtespace .Values.runtime.substrate.template | quote }}
- {{ printf "-substrate-atespace=%s" .Values.runtime.substrate.atespace | quote }}
- -ateapi-addr=api.ate-system.svc.cluster.local:443
- -ateapi-server-name=api.ate-system.svc
- -ateapi-ca-file=/var/run/substrate-control/ca.crt
- -ateapi-token-file=/var/run/substrate-control/token
- -atenet-router=atenet-router.ate-system.svc.cluster.local:80
- -substrate-placement-file=/data/substrate-placement.json
{{- end -}}

{{- define "agents.substrateVolumes" -}}
- name: substrate-control
  projected:
    defaultMode: 0444
    sources:
      - serviceAccountToken:
          audience: api.ate-system.svc
          expirationSeconds: 3600
          path: token
      - clusterTrustBundle:
          signerName: servicedns.podcert.ate.dev/identity
          labelSelector:
            matchLabels:
              podcert.ate.dev/canarying: live
          path: ca.crt
{{- end -}}
