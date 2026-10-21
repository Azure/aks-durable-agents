{{- define "agents.canvasClaim" -}}
{{- default (printf "%s-canvas-data" (include "agents.name" .)) .Values.canvas.persistence.existingClaim -}}
{{- end -}}

{{- define "agents.canvasConfig" -}}
{{- dict "version" 1 "authMode" "off" "trustedNetwork" true "instanceID" .Values.canvas.instanceID "listen" "127.0.0.1:8443" "origin" .Values.canvas.origin "readinessAddress" "127.0.0.1:8081" "stateDirectory" "/data/state" "definitionFile" "/data/definition/canvas.yaml" "sessionsEndpoint" (printf "%s-sessions.%s.svc.cluster.local:8080" (include "agents.name" .) .Release.Namespace) "sessionsCAFile" "/sessions-ca/ca.crt" "tlsCertFile" "/engine-tls/tls.crt" "tlsKeyFile" "/engine-tls/tls.key" | toJson -}}
{{- end -}}

{{- define "agents.canvasConfigName" -}}
{{- printf "%s-canvas-%s" (include "agents.name" .) (include "agents.canvasConfig" . | sha256sum | trunc 12) -}}
{{- end -}}

{{- define "agents.validateCanvas" -}}
{{- if (.Values.canvas | default dict).enabled -}}
{{- if gt (int (last (splitList ":" .Values.canvas.origin))) 65535 -}}
{{- fail "canvas.origin port must be between 1 and 65535" -}}
{{- end -}}
{{- if eq .Values.canvas.tlsSecretName .Values.canvas.sessionsTLSSecretName -}}
{{- fail "canvas.tlsSecretName must reference a separate Secret from canvas.sessionsTLSSecretName" -}}
{{- end -}}
{{- if eq (include "agents.canvasClaim" .) (include "agents.claim" .) -}}
{{- fail "canvas.persistence must use a separate claim from host/harness persistence" -}}
{{- end -}}
{{- end -}}
{{- end -}}
