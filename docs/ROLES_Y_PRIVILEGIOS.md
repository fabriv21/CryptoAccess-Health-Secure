# Roles y privilegios

## Administrador
Gestiona usuarios, MFA, recuperación de cuentas, claves, certificados, respaldos y configuración. No puede consultar la bitácora detallada del auditor.

## Médico
Consulta pacientes autorizados, crea expedientes, diagnósticos y documentos, y firma versiones clínicas.

## Recepción
Gestiona datos administrativos, citas y recordatorios. No visualiza diagnósticos ni tratamientos.

## Técnico TI
Consulta únicamente estado técnico agregado. No puede ver pacientes, expedientes ni la bitácora del auditor.

## Auditor
Existe una sola cuenta, `auditor_crypto`. Consulta, verifica y exporta la bitácora criptográfica. No administra datos clínicos ni configuración del sistema. Puede modificar únicamente sus propias credenciales desde Configuración.
