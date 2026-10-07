{{/* Exact matchLabels only: no empty selectors, expression-only or IP grants. */}}
{{- define "hanko-operator.validateMetricsSelector" -}}
{{- $name := .name -}}
{{- $selector := .selector -}}
{{- if not (kindIs "map" $selector) -}}
{{- fail (printf "%s must be an object" $name) -}}
{{- end -}}
{{- if $selector -}}
{{- if or (ne (len $selector) 1) (not (hasKey $selector "matchLabels")) -}}
{{- fail (printf "%s accepts only nonempty exact matchLabels" $name) -}}
{{- end -}}
{{- $labels := $selector.matchLabels -}}
{{- if or (not (kindIs "map" $labels)) (not $labels) -}}
{{- fail (printf "%s requires nonempty matchLabels" $name) -}}
{{- end -}}
{{- include "hanko-operator.validateMetricsLabels" (dict "name" $name "labels" $labels) -}}
{{- if .namespace -}}
{{- $namespace := index $labels "kubernetes.io/metadata.name" -}}
{{- if or (not $namespace) (gt (len $namespace) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $namespace)) -}}
{{- fail (printf "%s must select one namespace by kubernetes.io/metadata.name" $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hanko-operator.validateMetricsLabels" -}}
{{- $name := .name -}}
{{- $labels := .labels -}}
{{- if not (kindIs "map" $labels) -}}{{- fail (printf "%s must be a label map" $name) -}}{{- end -}}
{{- range $key, $value := $labels -}}
{{- $parts := splitList "/" $key -}}
{{- $labelName := last $parts -}}
{{- if or (gt (len $parts) 2) (gt (len $labelName) 63) (not (regexMatch "^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$" $labelName)) -}}
{{- fail (printf "%s contains an invalid label key" $name) -}}
{{- end -}}
{{- if eq (len $parts) 2 -}}
{{- $prefix := first $parts -}}
{{- if gt (len $prefix) 253 -}}{{- fail (printf "%s label prefix is too long" $name) -}}{{- end -}}
{{- range splitList "." $prefix -}}
{{- if or (gt (len .) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .)) -}}
{{- fail (printf "%s contains an invalid label prefix" $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if or (not (kindIs "string" $value)) (gt (len $value) 63) (not (regexMatch "^([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?$" $value)) -}}
{{- fail (printf "%s label values must be valid Kubernetes label strings" $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "hanko-operator.validateMetrics" -}}
{{- $metrics := .Values.metrics -}}
{{- if not (kindIs "bool" .Values.networkPolicy.enabled) -}}{{- fail "networkPolicy.enabled must be a boolean" -}}{{- end -}}
{{- if not (kindIs "map" $metrics) -}}{{- fail "metrics must be an object" -}}{{- end -}}
{{- range $key, $value := $metrics -}}
{{- if not (has $key (list "enabled" "serviceMonitor" "networkPolicy")) -}}{{- fail (printf "unknown metrics option %s" $key) -}}{{- end -}}
{{- end -}}
{{- if not (kindIs "bool" $metrics.enabled) -}}{{- fail "metrics.enabled must be a boolean" -}}{{- end -}}
{{- if not (kindIs "map" $metrics.serviceMonitor) -}}{{- fail "metrics.serviceMonitor must be an object" -}}{{- end -}}
{{- if or (ne (len $metrics.serviceMonitor) 2) (not (hasKey $metrics.serviceMonitor "labels")) (not (kindIs "bool" $metrics.serviceMonitor.enabled)) -}}
{{- fail "metrics.serviceMonitor accepts only enabled and labels options" -}}
{{- end -}}
{{- include "hanko-operator.validateMetricsLabels" (dict "name" "metrics.serviceMonitor.labels" "labels" $metrics.serviceMonitor.labels) -}}
{{- $reserved := include "hanko-operator.labels" . | fromYaml -}}
{{- range $key, $value := $metrics.serviceMonitor.labels -}}
{{- if and (hasKey $reserved $key) (ne (index $reserved $key) $value) -}}{{- fail "metrics.serviceMonitor.labels must not override chart labels" -}}{{- end -}}
{{- end -}}
{{- if not (kindIs "map" $metrics.networkPolicy) -}}{{- fail "metrics.networkPolicy must be an object" -}}{{- end -}}
{{- if or (ne (len $metrics.networkPolicy) 2) (not (hasKey $metrics.networkPolicy "namespaceSelector")) (not (hasKey $metrics.networkPolicy "podSelector")) -}}
{{- fail "metrics.networkPolicy requires namespaceSelector and podSelector options" -}}
{{- end -}}
{{- include "hanko-operator.validateMetricsSelector" (dict "name" "metrics.networkPolicy.namespaceSelector" "selector" $metrics.networkPolicy.namespaceSelector "namespace" true) -}}
{{- include "hanko-operator.validateMetricsSelector" (dict "name" "metrics.networkPolicy.podSelector" "selector" $metrics.networkPolicy.podSelector "namespace" false) -}}
{{- if and $metrics.enabled .Values.networkPolicy.enabled (or (not $metrics.networkPolicy.namespaceSelector) (not $metrics.networkPolicy.podSelector)) -}}
{{- fail "metrics.enabled with networkPolicy.enabled requires explicit Prometheus namespaceSelector and podSelector" -}}
{{- end -}}
{{- if and $metrics.enabled $metrics.serviceMonitor.enabled (not (.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/ServiceMonitor")) -}}
{{- fail "metrics.serviceMonitor.enabled requires the installed monitoring.coreos.com/v1/ServiceMonitor API; offline rendering needs --api-versions monitoring.coreos.com/v1/ServiceMonitor" -}}
{{- end -}}
{{- end -}}
