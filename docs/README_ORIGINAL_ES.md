# CryptoAccess Health Secure 3.5

**Sistema Empresarial de Autenticación Criptográfica, Protección de Expedientes y Gestión Clínica Segura**

Desarrollado por **CryptoSecure Solutions S.A.**

## Cambio principal de esta versión

La cuenta se crea primero con:

1. Nombre.
2. Usuario.
3. Contraseña.

**Authy ya no se configura durante la creación de la cuenta.**

Después del primer ingreso, la aplicación dirige al usuario a:

**Configuración > Seguridad > Activar Authy**

Allí se genera el QR, se escanea con Authy y se confirma el código temporal.

## Inicio de sesión

- Si Authy todavía no fue activado, el usuario puede ingresar con usuario y contraseña para completar la configuración.
- Una vez activado, el código MFA es obligatorio.
- Los códigos TOTP aceptados no pueden reutilizarse.
- Cinco intentos fallidos generan un bloqueo temporal.
- Si el administrador inició una recuperación MFA, el usuario debe registrar el nuevo teléfono antes de ingresar normalmente.

## Recuperación MFA

Si un empleado pierde o cambia el teléfono:

1. El administrador abre Usuarios y roles.
2. Selecciona la cuenta.
3. Presiona Restablecer MFA.
4. El secreto Authy anterior se revoca.
5. Se genera un código temporal de recuperación válido por 20 minutos.
6. El usuario selecciona Perdí el acceso a Authy en la pantalla de inicio.
7. Introduce usuario, contraseña y código de recuperación.
8. Escanea un nuevo QR.
9. Confirma el nuevo código Authy.
10. Todo queda registrado en auditoría.

## Auditor único

Se mantiene `auditor_crypto` como cuenta separada porque el profesor solicitó un auditor único que solo pueda consultar logs.

- El administrador administra usuarios, roles, MFA, claves, certificados y configuración desde el módulo Configuración.
- El administrador no consulta la bitácora detallada.
- El auditor consulta, verifica y exporta logs.
- El auditor solo puede modificar sus propias credenciales desde Configuración.

## Organización del menú

- La opción independiente **Usuarios y roles** fue eliminada del menú principal.
- La administración de usuarios se encuentra dentro de **Configuración > Administración de accesos**.
- El evaluador de 15 criterios fue eliminado porque pertenece al proceso de evaluación del profesor y no al producto.

## Centro legal

El visor legal utiliza la mayor parte posible de la pantalla:

- Menú lateral compacto.
- Área de lectura amplia.
- Fuente de mayor tamaño.
- Botón de aceptación en el encabezado.
- Altura de lectura ampliada.

## Criptografía

- AES-256-GCM.
- RSA-3072-OAEP.
- RSA-3072-PSS.
- SHA-384.
- Argon2id.
- TOTP Authy.
- SHA-256 + HKDF.
- PBKDF2-HMAC-SHA256.
- HMAC-SHA384.
- Certificados X.509.
- TLS.
- Rotación y revocación de claves.
- Auditoría encadenada.

## Instalación

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe main.py
```

También puede utilizar `instalar_y_ejecutar.bat`.

## Mejoras de interfaz 3.4

### Configuración

El módulo Configuración fue reconstruido para evitar el problema de pestañas vacías. Ahora dispone de:

- Mi cuenta.
- Cambio de contraseña.
- Seguridad y estado de Authy.
- Controles de sesión.
- Administración de accesos para el administrador.
- Tabla de usuarios, recuperación MFA, desbloqueo y activación de cuentas.

### Citas y calendario

La agenda aprovecha una mayor proporción de la pantalla.

- Barra superior compacta.
- Vista Día con resumen de citas y agenda de 30 minutos.
- Vista Mes personalizada en siete columnas.
- Celdas mensuales interactivas con citas visibles.
- Panel lateral con el detalle del día seleccionado.
- Navegación anterior, hoy y siguiente adaptada a Día o Mes.

## Corrección MFA 3.5

Se corrigió el ciclo completo de Authy.

La versión anterior registraba correctamente el secreto TOTP durante la activación, pero el inicio de sesión calculaba de forma incorrecta el código esperado porque trataba el contador TOTP como si fuera una marca de tiempo Unix.

La versión 3.5:

- Utiliza un único verificador TOTP para activación, login y recuperación.
- Calcula correctamente el contador de 30 segundos.
- Acepta una ventana temporal de ±1 intervalo.
- Normaliza el código a seis dígitos.
- Verifica el secreto después de cifrarlo y descifrarlo antes de guardarlo.
- Actualiza Configuración inmediatamente después de activar Authy.
- Mantiene la protección contra reutilización del mismo código.
- Incluye una prueba automática específica de MFA.

Si un código válido continúa fallando, debe verificarse que la fecha y hora de Windows y del teléfono estén configuradas automáticamente.
