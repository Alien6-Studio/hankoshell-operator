{{/* Keycloak credentials require explicit transport policy in every profile. */}}
{{- define "hanko-operator.validateKeycloakTransport" -}}
{{- range $key := list "HANKO_KEYCLOAK_URL" "HANKO_KEYCLOAK_ALLOW_INSECURE_HTTP" -}}
{{- if hasKey $.Values.env $key -}}{{- fail (printf "%s is managed by keycloak values; do not override it in env" $key) -}}{{- end -}}
{{- end -}}
{{- if not (kindIs "bool" .Values.keycloak.allowInsecureHTTP) -}}
{{- fail "keycloak.allowInsecureHTTP must be a boolean" -}}
{{- end -}}
{{- if .Values.keycloak.enabled -}}
{{- $endpoint := required "keycloak.url is required when Keycloak is enabled; configure verified HTTPS" .Values.keycloak.url -}}
{{- if not (kindIs "string" $endpoint) -}}{{- fail "keycloak.url must be a string" -}}{{- end -}}
{{- if not (regexMatch `^https?://([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?|\[(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|:(:[0-9A-Fa-f]{1,4}){1,7}|::)\])(:[0-9]+)?(/[A-Za-z0-9._~-]+)*/?$` $endpoint) -}}
{{- fail "keycloak.url must be an HTTP(S) origin with an optional plain context path, without userinfo, query or fragment" -}}
{{- end -}}
{{- $parsed := urlParse $endpoint -}}
{{- $authority := get $parsed "host" -}}
{{- if regexMatch ":[0-9]+$" $authority -}}
{{- $port := atoi (trimPrefix ":" (regexFind ":[0-9]+$" $authority)) -}}
{{- if or (lt $port 1) (gt $port 65535) -}}{{- fail "keycloak.url port must be between 1 and 65535" -}}{{- end -}}
{{- end -}}
{{- if regexMatch `(^|/)\.{1,2}(/|$)` (get $parsed "path") -}}{{- fail "keycloak.url context path must not contain dot segments" -}}{{- end -}}
{{- if eq (get $parsed "scheme") "http" -}}
{{- if eq (default "standard" .Values.profile) "enterprise" -}}{{- fail "enterprise keycloak.url must use HTTPS regardless of keycloak.allowInsecureHTTP" -}}{{- end -}}
{{- if not .Values.keycloak.allowInsecureHTTP -}}{{- fail "HTTP Keycloak administrative transport requires explicit keycloak.allowInsecureHTTP=true; use verified HTTPS" -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "hanko-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Enterprise constraints are evaluated before any resource is rendered. */}}
{{- define "hanko-operator.validateProfile" -}}
{{- include "hanko-operator.validateKeycloakTransport" . -}}
{{- $profile := default "standard" .Values.profile -}}
{{- if not (has $profile (list "standard" "enterprise")) -}}
{{- fail "profile must be standard or enterprise" -}}
{{- end -}}
{{- range $key := list "HANKO_SECURITY_PROFILE" "HANKO_ENTERPRISE_HUB_ENDPOINT" "HANKO_CONTINUUM_HUB_ADDRESS" "HANKO_ENTERPRISE_ENROLLMENT_ENDPOINT" -}}
{{- if hasKey $.Values.env $key -}}{{- fail (printf "%s is managed by profile; do not override it in env" $key) -}}{{- end -}}
{{- end -}}
{{- if eq $profile "enterprise" -}}
{{- if not (and .Values.hub.enabled .Values.continuum.enabled .Values.networkPolicy.enabled) -}}
{{- fail "enterprise requires hub.enabled, continuum.enabled and networkPolicy.enabled" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "enterprise requires a complete immutable image.digest" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" .Values.continuum.hubHostname) -}}
{{- fail "enterprise requires an exact lowercase continuum.hubHostname" -}}
{{- end -}}
{{- if or (not (regexMatch "^[0-9]+$" (toString .Values.continuum.hubPort))) (lt (int .Values.continuum.hubPort) 1) (gt (int .Values.continuum.hubPort) 65535) -}}
{{- fail "enterprise continuum.hubPort must be between 1 and 65535" -}}
{{- end -}}
{{- $endpoint := printf "https://%s:%v" .Values.continuum.hubHostname .Values.continuum.hubPort -}}
{{- if ne (trimSuffix "/" .Values.hub.endpoint) $endpoint -}}
{{- fail "enterprise hub.endpoint must match the exact HTTPS Continuum hostname and port, without a path" -}}
{{- end -}}
{{- if .Values.hub.externalCIDRs -}}{{- fail "enterprise forbids direct hub.externalCIDRs" -}}{{- end -}}
{{- if not (or .Values.hub.enrollToken .Values.hub.tenantID) -}}
{{- fail "enterprise requires an enrolled hub.tenantID or a single-use hub.enrollToken" -}}
{{- end -}}
{{- if and .Values.hub.enrollToken (not (hasPrefix "https://" .Values.hub.enrollmentEndpoint)) -}}
{{- fail "enterprise bootstrap requires an explicit HTTPS hub.enrollmentEndpoint" -}}
{{- end -}}
{{- if and (not .Values.hub.enrollToken) .Values.continuum.bootstrap.cidrs -}}
{{- fail "enterprise requires removal of continuum.bootstrap.cidrs after enrollment" -}}
{{- end -}}
{{- if and .Values.keycloak.enabled (not (hasPrefix "https://" .Values.keycloak.url)) -}}
{{- fail "enterprise keycloak.url must use HTTPS" -}}
{{- end -}}
{{- if and .Values.organizationProjection.enabled (not (hasPrefix "https://" .Values.organizationProjection.apiURL)) -}}
{{- fail "enterprise organizationProjection.apiURL must use HTTPS" -}}
{{- end -}}
{{- if and .Values.supervision.enabled (not (hasPrefix "https://" .Values.supervision.apiURL)) -}}
{{- fail "enterprise supervision.apiURL must use HTTPS" -}}
{{- end -}}
{{- range $key := list "HANKO_API_URL" "HANKO_SUPERVISION_API_URL" "HANKO_KEYCLOAK_URL" "HANKO_SPOKE_MODE" "HANKO_HUB_CA_FILE" -}}
{{- if hasKey $.Values.env $key -}}{{- fail (printf "enterprise forbids overriding %s in env" $key) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "hanko-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "hanko-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "hanko-operator.labels" -}}
helm.sh/chart: {{ include "hanko-operator.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{ include "hanko-operator.selectorLabels" . }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "hanko-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hanko-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
