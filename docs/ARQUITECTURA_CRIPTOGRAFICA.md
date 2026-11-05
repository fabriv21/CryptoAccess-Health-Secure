# Arquitectura criptográfica

## Expedientes clínicos

1. Se construye una representación canónica de la versión.
2. Se calcula SHA-384.
3. Los campos se cifran mediante AES-256-GCM.
4. Al firmar se utiliza RSA-3072-PSS con SHA-384.
5. Se asocia el certificado X.509 y el Key ID.
6. La versión firmada queda bloqueada.
7. Si la clave es comprometida, se genera una atestación de recuperación con la nueva clave.

## Documentos

1. Se genera una clave AES-256 aleatoria por documento.
2. AES-256-GCM cifra el contenido.
3. RSA-3072-OAEP protege la clave AES.
4. SHA-384 resume el documento y el paquete.
5. RSA-3072-PSS firma el contenido.
6. El certificado X.509 se incorpora al paquete `.cahs`.
7. Antes del descifrado se verifican certificado, hash, firma y etiqueta GCM.

## Autenticación

- Usuario institucional.
- Contraseña protegida con Argon2id.
- MFA TOTP compatible con Authy.
- TOTP de un solo uso con contador persistente.
- SHA-256 y HKDF para clave efímera de sesión.
- Bloqueo tras cinco intentos fallidos.
- Recuperación MFA con token administrativo temporal.
- Expiración de sesión por inactividad.

## PKI y claves

- CA raíz interna RSA-3072.
- Certificados de firma y TLS.
- Claves privadas cifradas.
- DPAPI en Windows para proteger los secretos locales.
- Rotación de 180 días.
- Revocación, incidentes y reprotección.

## Transporte

- HTTPS local con certificado X.509.
- TLS 1.2 mínimo y TLS 1.3 cuando está disponible.
- HMAC-SHA384.
- Timestamp.
- Nonce único.
- Registro de intentos de repetición.

## Auditoría

Cada evento registra usuario, rol, acción, resultado, severidad, estación, metadatos, hash anterior y hash SHA-384 propio.
