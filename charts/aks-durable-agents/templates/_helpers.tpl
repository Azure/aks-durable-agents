{{- define "agents.name" -}}
{{- $full := printf "%s-%s" .Release.Name .Chart.Name -}}
{{- if gt (len $full) 40 -}}
{{- printf "%s-%s" ($full | trunc 31 | trimSuffix "-") ($full | sha256sum | trunc 8) -}}
{{- else -}}
{{- $full -}}
{{- end -}}
{{- end -}}

{{- define "agents.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "agents.claim" -}}
{{- default (printf "%s-data" (include "agents.name" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{- define "agents.service" -}}
{{- printf "%s-harness.%s.svc.cluster.local:9000" (include "agents.name" .) .Release.Namespace -}}
{{- end -}}

{{- define "agents.security" -}}
runAsUser: 65532
runAsGroup: 65532
runAsNonRoot: true
allowPrivilegeEscalation: false
privileged: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "agents.resources" -}}
requests:
  cpu: 100m
  memory: 128Mi
  ephemeral-storage: 16Mi
limits:
  cpu: 1000m
  memory: 1Gi
  ephemeral-storage: 128Mi
{{- end -}}

{{- define "agents.mounts" -}}
- name: data
  mountPath: /data
  subPath: {{ .root.Values.persistence.subPath | quote }}
- name: data
  mountPath: /tmp
  subPath: {{ printf "%s/tmp-%s" .root.Values.persistence.subPath .container | quote }}
{{- end -}}
