{{/*
Expand the name of the chart.
*/}}
{{- define "cloudsentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "cloudsentinel.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "cloudsentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cloudsentinel.labels" -}}
helm.sh/chart: {{ include "cloudsentinel.chart" . }}
{{ include "cloudsentinel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cloudsentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cloudsentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "cloudsentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cloudsentinel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Auditor labels
*/}}
{{- define "cloudsentinel.auditor.labels" -}}
{{ include "cloudsentinel.labels" . }}
app.kubernetes.io/component: auditor
{{- end }}

{{/*
Reporter labels
*/}}
{{- define "cloudsentinel.reporter.labels" -}}
{{ include "cloudsentinel.labels" . }}
app.kubernetes.io/component: reporter
{{- end }}
