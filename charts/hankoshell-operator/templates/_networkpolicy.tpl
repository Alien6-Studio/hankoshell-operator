{{/* Never render an empty destination or port list: Kubernetes treats it as all. */}}
{{- define "hanko-operator.validateNetworkPolicy" -}}
{{- $network := .Values.networkPolicy -}}
{{- if or (not $network.dnsNamespace) (not $network.dnsSelector) -}}
{{- fail "networkPolicy DNS requires an explicit namespace and pod selector" -}}
{{- end -}}
{{- if hasKey $network.dnsSelector "io.kubernetes.pod.namespace" -}}
{{- fail "networkPolicy.dnsSelector must not override the Cilium namespace identity" -}}
{{- end -}}
{{- range $name, $ports := dict "kubernetesAPIEndpointPorts" $network.kubernetesAPIEndpointPorts "keycloakPorts" $network.keycloakPorts "keycloakExternalPorts" $network.keycloakExternalPorts -}}
{{- if not $ports -}}{{- fail (printf "networkPolicy.%s must not be empty" $name) -}}{{- end -}}
{{- range $ports -}}
{{- if or (not (regexMatch "^[0-9]+$" (toString .))) (lt (int .) 1) (gt (int .) 65535) -}}
{{- fail (printf "networkPolicy.%s must contain ports between 1 and 65535" $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $name, $cidrs := dict "kubernetesAPIServiceCIDRs" $network.kubernetesAPIServiceCIDRs "kubernetesAPIEndpointCIDRs" $network.kubernetesAPIEndpointCIDRs "keycloakExternalCIDRs" $network.keycloakExternalCIDRs "dnsCIDRs" $network.dnsCIDRs -}}
{{- range $cidrs -}}
{{- if not (regexMatch "^([0-9.]+/32|[0-9a-fA-F:]+/128)$" .) -}}
{{- fail (printf "networkPolicy.%s requires exact /32 or /128 addresses" $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if or .Values.azureKeyVault.enabled $network.externalEmailEgress.enabled -}}
{{- fail "Messaging moved to the hankoShell API: disable azureKeyVault.enabled and networkPolicy.externalEmailEgress.enabled on the operator" -}}
{{- end -}}
{{- end -}}
