{{- define "certmate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "certmate.fullname" -}}
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

{{- define "certmate.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "certmate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "certmate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certmate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "certmate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "certmate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "certmate.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "certmate.fullname" . }}
{{- end }}
{{- end }}

{{- define "certmate.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "certmate.fullname" . }}
{{- end }}
{{- end }}

{{/*
Refuse to render a configuration the application cannot survive.

CertMate runs APScheduler inside the web process and gunicorn with a single
worker. A second replica is a second scheduler issuing and renewing against the
same store, and a second writer to a ReadWriteOnce volume. Failing at template
time is the only place this can be caught before it is someone's incident.
*/}}
{{- define "certmate.validate" -}}
{{- if ne (int .Values.replicaCount) 1 }}
{{- fail "certmate: replicaCount must be 1. CertMate is single-instance by design — its scheduler runs in-process, so a second replica duplicates every renewal job against the same certificate store. Scale up the resources, not the replicas." }}
{{- end }}
{{- if and (not .Values.persistence.enabled) (not .Values.persistence.existingClaim) }}
{{- fail "certmate: persistence is disabled, which means issued certificates, the audit chain and the settings store live in the pod and are lost on restart. Set persistence.enabled=true, or persistence.existingClaim to a volume you manage." }}
{{- end }}
{{- end }}
