{{- define "iaga-sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "iaga-sentinel.fullname" -}}
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

{{- define "iaga-sentinel.labels" -}}
helm.sh/chart: {{ include "iaga-sentinel.name" . }}-{{ .Chart.Version }}
{{ include "iaga-sentinel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "iaga-sentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iaga-sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "iaga-sentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "iaga-sentinel.fullname" . }}
{{- end }}
{{- end }}

{{- define "iaga-sentinel.databaseUrl" -}}
{{- if .Values.postgres.enabled }}
{{- if .Values.postgres.url }}
{{- .Values.postgres.url }}
{{- else }}
{{- required "postgres.url or postgres.existingSecret must be set when postgres.enabled is true" nil }}
{{- end }}
{{- else }}
{{- if .Values.config.databaseUrl }}
{{- .Values.config.databaseUrl }}
{{- else }}
{{- printf "sqlite:///app/data/iaga_sentinel.db?mode=rwc" }}
{{- end }}
{{- end }}
{{- end }}
