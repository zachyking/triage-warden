{{/*
Expand the name of the chart.
*/}}
{{- define "triage-warden.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "triage-warden.fullname" -}}
{{- if .Values.global.fullnameOverride }}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.global.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "triage-warden.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "triage-warden.labels" -}}
helm.sh/chart: {{ include "triage-warden.chart" . }}
{{ include "triage-warden.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "triage-warden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "triage-warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API component labels
*/}}
{{- define "triage-warden.api.labels" -}}
{{ include "triage-warden.labels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
API selector labels
*/}}
{{- define "triage-warden.api.selectorLabels" -}}
{{ include "triage-warden.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Orchestrator component labels
*/}}
{{- define "triage-warden.orchestrator.labels" -}}
{{ include "triage-warden.labels" . }}
app.kubernetes.io/component: orchestrator
{{- end }}

{{/*
Orchestrator selector labels
*/}}
{{- define "triage-warden.orchestrator.selectorLabels" -}}
{{ include "triage-warden.selectorLabels" . }}
app.kubernetes.io/component: orchestrator
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "triage-warden.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "triage-warden.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret to use
*/}}
{{- define "triage-warden.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "triage-warden.fullname" . }}-secrets
{{- end }}
{{- end }}

{{/*
Create the name of the configmap to use
*/}}
{{- define "triage-warden.configMapName" -}}
{{- include "triage-warden.fullname" . }}-config
{{- end }}

{{/*
Create the PostgreSQL connection URL
*/}}
{{- define "triage-warden.databaseUrl" -}}
{{- if .Values.postgresql.existingSecret }}
{{- printf "postgres://%s:$(DATABASE_PASSWORD)@%s:%d/%s?sslmode=%s" .Values.postgresql.username .Values.postgresql.host (int .Values.postgresql.port) .Values.postgresql.database .Values.postgresql.sslMode }}
{{- else if .Values.postgresql.password }}
{{- printf "postgres://%s:%s@%s:%d/%s?sslmode=%s" .Values.postgresql.username .Values.postgresql.password .Values.postgresql.host (int .Values.postgresql.port) .Values.postgresql.database .Values.postgresql.sslMode }}
{{- else }}
{{- printf "postgres://%s@%s:%d/%s?sslmode=%s" .Values.postgresql.username .Values.postgresql.host (int .Values.postgresql.port) .Values.postgresql.database .Values.postgresql.sslMode }}
{{- end }}
{{- end }}

{{/*
Create the Redis connection URL
*/}}
{{- define "triage-warden.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- if .Values.redis.password }}
{{- if .Values.redis.tls }}
{{- printf "rediss://:%s@%s:%d/%d" .Values.redis.password .Values.redis.host (int .Values.redis.port) (int .Values.redis.database) }}
{{- else }}
{{- printf "redis://:%s@%s:%d/%d" .Values.redis.password .Values.redis.host (int .Values.redis.port) (int .Values.redis.database) }}
{{- end }}
{{- else }}
{{- if .Values.redis.tls }}
{{- printf "rediss://%s:%d/%d" .Values.redis.host (int .Values.redis.port) (int .Values.redis.database) }}
{{- else }}
{{- printf "redis://%s:%d/%d" .Values.redis.host (int .Values.redis.port) (int .Values.redis.database) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return the proper image name
*/}}
{{- define "triage-warden.image" -}}
{{- $registryName := .Values.image.repository -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" $registryName $tag }}
{{- end }}

{{/*
Return the proper image pull secrets
*/}}
{{- define "triage-warden.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Render pod anti-affinity rules based on preset
*/}}
{{- define "triage-warden.podAntiAffinity" -}}
{{- if eq .preset "hard" }}
requiredDuringSchedulingIgnoredDuringExecution:
  - labelSelector:
      matchLabels:
        {{- include .selectorLabelsTemplate .context | nindent 8 }}
    topologyKey: kubernetes.io/hostname
{{- else if eq .preset "soft" }}
preferredDuringSchedulingIgnoredDuringExecution:
  - weight: 100
    podAffinityTerm:
      labelSelector:
        matchLabels:
          {{- include .selectorLabelsTemplate .context | nindent 10 }}
      topologyKey: kubernetes.io/hostname
{{- end }}
{{- end }}

{{/*
Validate required values
*/}}
{{- define "triage-warden.validateValues" -}}
{{- if not .Values.postgresql.host }}
{{- fail "postgresql.host is required" }}
{{- end }}
{{- if and (not .Values.secrets.existingSecret) (not .Values.secrets.encryptionKey) }}
{{- fail "Either secrets.existingSecret or secrets.encryptionKey is required" }}
{{- end }}
{{- if and (not .Values.secrets.existingSecret) (not .Values.secrets.jwtSecret) }}
{{- fail "Either secrets.existingSecret or secrets.jwtSecret is required" }}
{{- end }}
{{- if and (not .Values.secrets.existingSecret) (not .Values.secrets.sessionSecret) }}
{{- fail "Either secrets.existingSecret or secrets.sessionSecret is required" }}
{{- end }}
{{- end }}

{{/*
Create Nginx ingress annotations
*/}}
{{- define "triage-warden.nginx.annotations" -}}
{{- if and .Values.ingress.nginx.enabled (eq .Values.ingress.className "nginx") }}
nginx.ingress.kubernetes.io/ssl-redirect: {{ .Values.ingress.nginx.sslRedirect | quote }}
nginx.ingress.kubernetes.io/proxy-body-size: {{ .Values.ingress.nginx.proxyBodySize | quote }}
nginx.ingress.kubernetes.io/proxy-read-timeout: {{ .Values.ingress.nginx.proxyReadTimeout | quote }}
nginx.ingress.kubernetes.io/proxy-send-timeout: {{ .Values.ingress.nginx.proxySendTimeout | quote }}
nginx.ingress.kubernetes.io/limit-rps: {{ .Values.ingress.nginx.limitRps | quote }}
nginx.ingress.kubernetes.io/limit-connections: {{ .Values.ingress.nginx.limitConnections | quote }}
nginx.ingress.kubernetes.io/configuration-snippet: |
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
{{- end }}
{{- end }}

{{/*
Create Traefik ingress annotations
*/}}
{{- define "triage-warden.traefik.annotations" -}}
{{- if and .Values.ingress.traefik.enabled (eq .Values.ingress.className "traefik") }}
traefik.ingress.kubernetes.io/router.entrypoints: {{ .Values.ingress.traefik.entryPoints | quote }}
traefik.ingress.kubernetes.io/router.tls.certresolver: {{ .Values.ingress.traefik.tlsResolver | quote }}
traefik.ingress.kubernetes.io/router.middlewares: {{ printf "%s-%s-headers@kubernetescrd" .Release.Namespace (include "triage-warden.fullname" .) }}
{{- end }}
{{- end }}
