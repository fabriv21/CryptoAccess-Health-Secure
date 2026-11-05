
from __future__ import annotations

import base64
import calendar as pycalendar
import csv
import ctypes
import hashlib
import hmac
import http.server
import ipaddress
import io
import json
import os
import platform
import secrets
import shutil
import socket
import sqlite3
import ssl
import threading
import time
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import customtkinter as ctk
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
from tkcalendar import Calendar
from tkinter import END, BOTH, LEFT, RIGHT, X, Y, filedialog, messagebox, ttk


APP_NAME = "CryptoAccess Health Secure"
COMPANY = "CryptoSecure Solutions S.A."
VERSION = "3.5.0 Final Presentation Edition"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESOURCE_DIR = BASE_DIR / "resources"
EXPORT_DIR = BASE_DIR / "exports"
DB_PATH = DATA_DIR / "cryptoaccess_health.db"
KEY_PATH = DATA_DIR / "master.key"
KEYS_DIR = DATA_DIR / "keys"
SECURE_DOCUMENTS_DIR = BASE_DIR / "secure_documents"
CERTS_DIR = DATA_DIR / "certs"
SECURE_STORE_DIR = DATA_DIR / "secure_store"
REPORTS_DIR = BASE_DIR / "reports"
LOGO_PATH = RESOURCE_DIR / "cryptosecure_logo.png"

COLORS = {
    "navy": "#071E3D",
    "navy_2": "#0B2A52",
    "blue": "#1677FF",
    "cyan": "#19C2FF",
    "bg": "#F5F8FC",
    "card": "#FFFFFF",
    "text": "#14213D",
    "muted": "#667085",
    "line": "#E5EAF2",
    "green": "#18A86B",
    "orange": "#FF9F43",
    "red": "#E74856",
    "purple": "#7B61FF",
}

ph = PasswordHasher()


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    RESOURCE_DIR.mkdir(exist_ok=True)
    EXPORT_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    SECURE_STORE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SECURE_DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn



class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob_from_bytes(data: bytes):
    buffer = ctypes.create_string_buffer(data)
    blob = _DATA_BLOB(
        len(data),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _protect_local(data: bytes) -> bytes:
    """Protege secretos con DPAPI en Windows y con una clave ligada al equipo en otros sistemas."""
    if os.name == "nt":
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        input_blob, _buffer = _blob_from_bytes(data)
        output_blob = _DATA_BLOB()
        if not crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            ctypes.c_wchar_p("CryptoAccess"),
            None,
            None,
            None,
            0,
            ctypes.byref(output_blob),
        ):
            raise OSError("DPAPI no pudo proteger el secreto.")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)

    machine_material = (
        platform.node() + "|" + str(os.getuid() if hasattr(os, "getuid") else 0)
    ).encode("utf-8")
    key = hashlib.sha384(machine_material).digest()[:32]
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, b"LOCAL-SECURE-STORE")


def _unprotect_local(data: bytes) -> bytes:
    if os.name == "nt":
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        input_blob, _buffer = _blob_from_bytes(data)
        output_blob = _DATA_BLOB()
        if not crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(output_blob),
        ):
            raise OSError("DPAPI no pudo recuperar el secreto.")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)

    machine_material = (
        platform.node() + "|" + str(os.getuid() if hasattr(os, "getuid") else 0)
    ).encode("utf-8")
    key = hashlib.sha384(machine_material).digest()[:32]
    return AESGCM(key).decrypt(data[:12], data[12:], b"LOCAL-SECURE-STORE")


def load_or_create_secret(name: str, length: int) -> bytes:
    ensure_dirs()
    path = SECURE_STORE_DIR / f"{name}.bin"
    if path.exists():
        return _unprotect_local(path.read_bytes())
    secret = secrets.token_bytes(length)
    path.write_bytes(_protect_local(secret))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return secret


MASTER_KEY = load_or_create_secret("field_master_key", 32)
PRIVATE_KEY_PASSWORD_RAW = load_or_create_secret("private_key_password", 32)
PRIVATE_KEY_PASSWORD = base64.urlsafe_b64encode(PRIVATE_KEY_PASSWORD_RAW)
API_SHARED_SECRET = load_or_create_secret("tls_api_hmac", 48)
AES = AESGCM(MASTER_KEY)


def encrypt_bytes(value: bytes, aad: bytes = b"CRYPTOACCESS-HEALTH-V3") -> str:
    nonce = os.urandom(12)
    ciphertext = AES.encrypt(nonce, value, aad)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_bytes(token: str, aad: bytes = b"CRYPTOACCESS-HEALTH-V3") -> bytes:
    if not token:
        return b""
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    return AES.decrypt(raw[:12], raw[12:], aad)


def encrypt_text(value: str) -> str:
    return encrypt_bytes((value or "").encode("utf-8"))


def decrypt_text(token: str) -> str:
    return decrypt_bytes(token).decode("utf-8") if token else ""




def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")



def initialize_database() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('ADMIN','DOCTOR','RECEPTION','IT','AUDITOR')),
                password_hash TEXT NOT NULL,
                totp_secret_enc TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 1,
                setup_complete INTEGER NOT NULL DEFAULT 0,
                last_totp_counter INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                mfa_recovery_token_hash TEXT,
                mfa_recovery_expires TEXT,
                mfa_reset_pending INTEGER NOT NULL DEFAULT 0,
                password_changed_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_auditor_only
            ON users(role) WHERE role='AUDITOR';

            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                internal_code TEXT UNIQUE NOT NULL,
                full_name_enc TEXT NOT NULL,
                birth_date_enc TEXT NOT NULL,
                id_number_enc TEXT,
                phone_enc TEXT,
                email_enc TEXT,
                address_enc TEXT,
                emergency_contact_enc TEXT,
                preferred_contact TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS clinical_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                doctor_username TEXT NOT NULL,
                visit_date TEXT NOT NULL,
                reason_enc TEXT,
                diagnosis_enc TEXT,
                treatment_enc TEXT,
                medications_enc TEXT,
                allergies_enc TEXT,
                notes_enc TEXT,
                status TEXT NOT NULL DEFAULT 'DRAFT',
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                content_hash TEXT,
                digital_signature TEXT,
                signer_key_id TEXT,
                signed_at TEXT,
                recovery_signature TEXT,
                recovery_key_id TEXT,
                recovery_at TEXT,
                FOREIGN KEY(patient_id) REFERENCES patients(id)
            );

            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                professional TEXT NOT NULL,
                specialty TEXT NOT NULL,
                appointment_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                duration_min INTEGER NOT NULL,
                room TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING',
                reason_admin TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(patient_id) REFERENCES patients(id)
            );

            CREATE TABLE IF NOT EXISTS reminders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                recipient_masked TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                sent_by TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                FOREIGN KEY(appointment_id) REFERENCES appointments(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id TEXT,
                result TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                workstation TEXT,
                metadata_json TEXT,
                previous_hash TEXT,
                event_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS legal_acceptance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                document_name TEXT NOT NULL,
                document_version TEXT NOT NULL,
                accepted_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_registry (
                key_id TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL,
                key_size INTEGER NOT NULL,
                public_path TEXT NOT NULL,
                private_path TEXT NOT NULL,
                fingerprint_sha384 TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                retired_at TEXT,
                expires_at TEXT,
                compromise_reason TEXT,
                created_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificates (
                certificate_id TEXT PRIMARY KEY,
                key_id TEXT,
                certificate_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                pem_path TEXT NOT NULL,
                fingerprint_sha384 TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_to TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secure_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_uuid TEXT UNIQUE NOT NULL,
                patient_id INTEGER,
                original_name TEXT NOT NULL,
                package_path TEXT NOT NULL,
                category TEXT NOT NULL,
                owner_username TEXT NOT NULL,
                plaintext_sha384 TEXT NOT NULL,
                package_sha384 TEXT NOT NULL,
                signature_b64 TEXT NOT NULL,
                key_id TEXT NOT NULL,
                algorithm_summary TEXT NOT NULL,
                original_size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_verified_at TEXT,
                verification_status TEXT NOT NULL DEFAULT 'PENDING',
                FOREIGN KEY(patient_id) REFERENCES patients(id)
            );

            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                purpose TEXT NOT NULL,
                used_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_uuid TEXT UNIQUE NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                key_id TEXT,
                description TEXT NOT NULL,
                affected_documents INTEGER NOT NULL DEFAULT 0,
                affected_records INTEGER NOT NULL DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                closed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        # Migraciones desde versiones anteriores.
        migrations = {
            "users": [
                ("totp_secret_enc", "TEXT"),
                ("setup_complete", "INTEGER NOT NULL DEFAULT 0"),
                ("last_totp_counter", "INTEGER"),
                ("failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("locked_until", "TEXT"),
                ("mfa_recovery_token_hash", "TEXT"),
                ("mfa_recovery_expires", "TEXT"),
                ("mfa_reset_pending", "INTEGER NOT NULL DEFAULT 0"),
                ("password_changed_at", "TEXT"),
            ],
            "clinical_records": [
                ("recovery_signature", "TEXT"),
                ("recovery_key_id", "TEXT"),
                ("recovery_at", "TEXT"),
            ],
            "key_registry": [
                ("expires_at", "TEXT"),
                ("compromise_reason", "TEXT"),
            ],
        }
        for table, columns in migrations.items():
            for column, definition in columns:
                _add_column_if_missing(conn, table, column, definition)

        # Migra secretos TOTP antiguos si existen.
        user_columns = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "totp_secret" in user_columns:
            rows = conn.execute(
                "SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL AND (totp_secret_enc IS NULL OR totp_secret_enc='')"
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE users SET totp_secret_enc=?, setup_complete=0 WHERE id=?",
                    (encrypt_text(row["totp_secret"]), row["id"]),
                )

        conn.execute(
            "INSERT OR IGNORE INTO settings(name,value,updated_at) VALUES('rotation_days','180',?)",
            (now_iso(),),
        )
        conn.execute(
            "INSERT OR IGNORE INTO settings(name,value,updated_at) VALUES('session_timeout_minutes','15',?)",
            (now_iso(),),
        )

def sha384_bytes(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA384())
    digest.update(data)
    return digest.finalize()


def sha384_hex(data: bytes) -> str:
    return sha384_bytes(data).hex()


def canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def audit(
    username: str,
    role: str,
    action: str,
    entity: str,
    entity_id: str = "",
    result: str = "OK",
    details: str = "",
    severity: str = "INFO",
    metadata: Optional[dict] = None,
) -> None:
    timestamp = now_iso()
    workstation = socket.gethostname()
    metadata_json = json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)

    with db() as conn:
        previous = conn.execute(
            "SELECT event_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous and previous["event_hash"] else "GENESIS"

        event_payload = {
            "previous_hash": previous_hash,
            "timestamp": timestamp,
            "username": username,
            "role": role,
            "action": action,
            "entity": entity,
            "entity_id": entity_id,
            "result": result,
            "details": details,
            "severity": severity,
            "workstation": workstation,
            "metadata": metadata or {},
        }
        event_hash = sha384_hex(canonical_json(event_payload))

        conn.execute(
            """
            INSERT INTO audit_logs
            (timestamp, username, role, action, entity, entity_id, result, details,
             severity, workstation, metadata_json, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                username,
                role,
                action,
                entity,
                entity_id,
                result,
                details,
                severity,
                workstation,
                metadata_json,
                previous_hash,
                event_hash,
            ),
        )


def verify_audit_chain() -> tuple[bool, str, int]:
    expected_previous = "GENESIS"
    verified = 0

    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()

    for row in rows:
        previous_hash = row["previous_hash"] or "GENESIS"
        if previous_hash != expected_previous:
            return False, f"Ruptura de encadenamiento en el evento {row['id']}.", verified

        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except json.JSONDecodeError:
            metadata = {}

        payload = {
            "previous_hash": previous_hash,
            "timestamp": row["timestamp"],
            "username": row["username"],
            "role": row["role"],
            "action": row["action"],
            "entity": row["entity"],
            "entity_id": row["entity_id"] or "",
            "result": row["result"],
            "details": row["details"],
            "severity": row["severity"] or "INFO",
            "workstation": row["workstation"] or "",
            "metadata": metadata,
        }
        calculated = sha384_hex(canonical_json(payload))
        if not row["event_hash"] or calculated != row["event_hash"]:
            return False, f"El hash SHA-384 del evento {row['id']} no es válido.", verified

        expected_previous = row["event_hash"]
        verified += 1

    return True, "La cadena de auditoría SHA-384 es íntegra.", verified




def normalize_totp_code(code: str) -> str:
    return "".join(character for character in (code or "") if character.isdigit())


def verify_totp_secret(
    secret: str,
    code: str,
    last_counter: Optional[int] = None,
    valid_window: int = 1,
) -> tuple[bool, Optional[int], str]:
    """
    Verifica TOTP utilizando el contador temporal correcto.

    PyOTP TOTP.at() trabaja con una fecha/hora Unix. La implementación anterior
    le estaba pasando directamente el contador TOTP, lo que provocaba que un
    código aceptado durante la activación fallara después en el login.
    """
    clean_code = normalize_totp_code(code)

    if len(clean_code) != 6:
        return False, None, "El código Authy debe contener exactamente seis dígitos."

    try:
        totp = pyotp.TOTP(secret)
        current_counter = int(time.time()) // totp.interval
    except Exception:
        return False, None, "No fue posible inicializar la validación TOTP."

    matched_counter = None

    for counter in range(
        current_counter - valid_window,
        current_counter + valid_window + 1,
    ):
        expected = totp.generate_otp(counter)
        if hmac.compare_digest(expected, clean_code):
            matched_counter = counter
            break

    if matched_counter is None:
        return (
            False,
            None,
            "Código Authy incorrecto o vencido. Verifique también que la hora del teléfono y del equipo estén sincronizadas.",
        )

    if (
        last_counter is not None
        and matched_counter <= int(last_counter)
    ):
        return (
            False,
            None,
            "El código Authy ya fue utilizado. Espere el siguiente código para evitar un ataque de repetición.",
        )

    return True, matched_counter, "Código TOTP válido."


def verify_totp_once(
    user_row,
    code: str,
) -> tuple[bool, Optional[int], str]:
    if not user_row["totp_secret_enc"]:
        return False, None, "La cuenta no tiene Authy configurado."

    try:
        secret = decrypt_text(
            user_row["totp_secret_enc"]
        ).strip()
    except Exception:
        return (
            False,
            None,
            "No fue posible recuperar el secreto TOTP almacenado.",
        )

    return verify_totp_secret(
        secret,
        code,
        user_row["last_totp_counter"],
        valid_window=1,
    )


def register_nonce(nonce: str, purpose: str, ttl_seconds: int = 120) -> bool:
    now = datetime.now()
    expires = now + timedelta(seconds=ttl_seconds)
    with db() as conn:
        conn.execute(
            "DELETE FROM used_nonces WHERE expires_at < ?",
            (now.isoformat(timespec="seconds"),),
        )
        try:
            conn.execute(
                "INSERT INTO used_nonces(nonce,purpose,used_at,expires_at) VALUES(?,?,?,?)",
                (
                    nonce,
                    purpose,
                    now.isoformat(timespec="seconds"),
                    expires.isoformat(timespec="seconds"),
                ),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def public_key_fingerprint(public_key) -> str:
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha384_hex(public_der)



def _certificate_fingerprint(cert: x509.Certificate) -> str:
    return sha384_hex(cert.public_bytes(serialization.Encoding.DER))


def _ca_paths():
    return (
        CERTS_DIR / "internal_ca_private.pem",
        CERTS_DIR / "internal_ca_certificate.pem",
    )


def ensure_internal_ca():
    private_path, cert_path = _ca_paths()
    if private_path.exists() and cert_path.exists():
        key = serialization.load_pem_private_key(
            private_path.read_bytes(),
            password=PRIVATE_KEY_PASSWORD,
        )
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return key, cert

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, COMPANY),
            x509.NameAttribute(NameOID.COMMON_NAME, "CryptoSecure Internal Root CA"),
        ]
    )
    now = datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )
    private_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PRIVATE_KEY_PASSWORD),
        )
    )
    cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO certificates
            (certificate_id,key_id,certificate_type,subject,issuer,serial_number,
             pem_path,fingerprint_sha384,valid_from,valid_to,status,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "CERT-ROOT-CA",
                None,
                "ROOT_CA",
                ca_cert.subject.rfc4514_string(),
                ca_cert.issuer.rfc4514_string(),
                str(ca_cert.serial_number),
                str(cert_path),
                _certificate_fingerprint(ca_cert),
                ca_cert.not_valid_before.isoformat(),
                ca_cert.not_valid_after.isoformat(),
                "VALID",
                now_iso(),
            ),
        )
    return ca_key, ca_cert


def issue_certificate_for_key(key_id: str, public_key, certificate_type: str = "SIGNING") -> str:
    ca_key, ca_cert = ensure_internal_ca()
    cert_id = f"CERT-{certificate_type}-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.utcnow()
    common_name = (
        f"{APP_NAME} TLS Service"
        if certificate_type == "TLS_SERVER"
        else f"CryptoAccess Signing {key_id[-16:]}"
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "CR"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, COMPANY),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    if certificate_type == "TLS_SERVER":
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    cert = builder.sign(ca_key, hashes.SHA384())
    path = CERTS_DIR / f"{cert_id}.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO certificates
            (certificate_id,key_id,certificate_type,subject,issuer,serial_number,
             pem_path,fingerprint_sha384,valid_from,valid_to,status,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                cert_id,
                key_id,
                certificate_type,
                cert.subject.rfc4514_string(),
                cert.issuer.rfc4514_string(),
                str(cert.serial_number),
                str(path),
                _certificate_fingerprint(cert),
                cert.not_valid_before.isoformat(),
                cert.not_valid_after.isoformat(),
                "VALID",
                now_iso(),
            ),
        )
    return cert_id


def create_rsa_key_pair(created_by: str, activate: bool = True) -> str:
    key_id = f"RSA-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    private_path = KEYS_DIR / f"{key_id}_private.pem"
    public_path = KEYS_DIR / f"{key_id}_public.pem"

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASSWORD),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    fingerprint = public_key_fingerprint(public_key)
    created_at = now_iso()
    expires_at = (datetime.now() + timedelta(days=365)).isoformat(timespec="seconds")

    with db() as conn:
        if activate:
            conn.execute(
                """
                UPDATE key_registry SET status='RETIRED', retired_at=?
                WHERE status='ACTIVE'
                """,
                (created_at,),
            )
        conn.execute(
            """
            INSERT INTO key_registry
            (key_id, algorithm, key_size, public_path, private_path,
             fingerprint_sha384, status, created_at, activated_at, expires_at, created_by)
            VALUES (?, 'RSA', 3072, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_id,
                str(public_path),
                str(private_path),
                fingerprint,
                "ACTIVE" if activate else "STANDBY",
                created_at,
                created_at if activate else None,
                expires_at,
                created_by,
            ),
        )

    issue_certificate_for_key(key_id, public_key, "SIGNING")
    return key_id


def ensure_active_rsa_key() -> str:
    ensure_internal_ca()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM key_registry WHERE status='ACTIVE' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        rotation_days_row = conn.execute(
            "SELECT value FROM settings WHERE name='rotation_days'"
        ).fetchone()
    rotation_days = int(rotation_days_row["value"]) if rotation_days_row else 180

    if row:
        created = datetime.fromisoformat(row["created_at"])
        with db() as conn:
            cert = conn.execute(
                """
                SELECT certificate_id FROM certificates
                WHERE key_id=? AND certificate_type='SIGNING'
                ORDER BY created_at DESC LIMIT 1
                """,
                (row["key_id"],),
            ).fetchone()
        if not cert:
            public_key, _record = load_public_key(row["key_id"])
            issue_certificate_for_key(row["key_id"], public_key, "SIGNING")
        if datetime.now() - created < timedelta(days=rotation_days):
            return row["key_id"]
    return create_rsa_key_pair("SYSTEM-AUTO-ROTATION", activate=True)


def get_key_record(key_id: Optional[str] = None):
    with db() as conn:
        if key_id:
            return conn.execute(
                "SELECT * FROM key_registry WHERE key_id=?",
                (key_id,),
            ).fetchone()
        return conn.execute(
            "SELECT * FROM key_registry WHERE status='ACTIVE' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()


def load_private_key(key_id: Optional[str] = None):
    record = get_key_record(key_id)
    if not record:
        raise RuntimeError("No existe una clave privada RSA disponible.")
    private_key = serialization.load_pem_private_key(
        Path(record["private_path"]).read_bytes(),
        password=PRIVATE_KEY_PASSWORD,
    )
    return private_key, record


def load_public_key(key_id: Optional[str] = None):
    record = get_key_record(key_id)
    if not record:
        raise RuntimeError("No existe una clave pública RSA disponible.")
    public_key = serialization.load_pem_public_key(
        Path(record["public_path"]).read_bytes()
    )
    return public_key, record


def verify_certificate_for_key(key_id: str) -> tuple[bool, str]:
    with db() as conn:
        row = conn.execute(
            """
            SELECT * FROM certificates
            WHERE key_id=? AND certificate_type='SIGNING'
            ORDER BY created_at DESC LIMIT 1
            """,
            (key_id,),
        ).fetchone()
    if not row:
        return False, "No existe certificado digital asociado a la clave."
    if row["status"] != "VALID":
        return False, f"El certificado está en estado {row['status']}."

    cert = x509.load_pem_x509_certificate(Path(row["pem_path"]).read_bytes())
    ca_key, ca_cert = ensure_internal_ca()
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False, "La firma del certificado no es válida."

    now = datetime.utcnow()
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        return False, "El certificado está vencido o todavía no es válido."
    return True, "Certificado X.509 válido y emitido por la CA interna."


class SecureTLSService:
    def __init__(self):
        self.server = None
        self.thread = None
        self.port = None
        self.last_test_ok = False
        self.last_test_detail = "No ejecutada"

    def _ensure_tls_certificate(self):
        key_path = CERTS_DIR / "tls_server_private.pem"
        cert_path = CERTS_DIR / "tls_server_certificate.pem"
        if key_path.exists() and cert_path.exists():
            return key_path, cert_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(PRIVATE_KEY_PASSWORD),
            )
        )
        cert_id = issue_certificate_for_key("TLS-SERVER", key.public_key(), "TLS_SERVER")
        with db() as conn:
            cert = conn.execute(
                "SELECT * FROM certificates WHERE certificate_id=?",
                (cert_id,),
            ).fetchone()
        shutil.copy2(cert["pem_path"], cert_path)
        return key_path, cert_path

    def start(self):
        if self.server:
            return
        key_path, cert_path = self._ensure_tls_certificate()
        service = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def do_GET(self):
                timestamp = self.headers.get("X-Timestamp", "")
                nonce = self.headers.get("X-Nonce", "")
                signature = self.headers.get("X-Signature", "")
                payload = f"GET|{self.path}|{timestamp}|{nonce}".encode("utf-8")
                expected = hmac.new(API_SHARED_SECRET, payload, hashlib.sha384).hexdigest()

                try:
                    age = abs(time.time() - float(timestamp))
                except ValueError:
                    age = 9999

                if (
                    age > 60
                    or not nonce
                    or not hmac.compare_digest(signature, expected)
                    or not register_nonce(nonce, "TLS_API_REQUEST", 120)
                ):
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"status":"rejected","reason":"replay_or_auth"}')
                    return

                body = json.dumps(
                    {
                        "status": "ok",
                        "product": APP_NAME,
                        "tls": "TLS 1.3 preferred",
                        "timestamp": now_iso(),
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
            password=PRIVATE_KEY_PASSWORD.decode("ascii"),
        )
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="CryptoAccessTLS",
            daemon=True,
        )
        self.thread.start()

    def self_test(self) -> tuple[bool, str]:
        if not self.server:
            self.last_test_ok = False
            self.last_test_detail = "Servicio TLS no iniciado."
            return False, self.last_test_detail

        timestamp = str(time.time())
        nonce = secrets.token_urlsafe(24)
        path = "/health"
        payload = f"GET|{path}|{timestamp}|{nonce}".encode("utf-8")
        signature = hmac.new(API_SHARED_SECRET, payload, hashlib.sha384).hexdigest()

        request = urllib.request.Request(
            f"https://127.0.0.1:{self.port}{path}",
            headers={
                "X-Timestamp": timestamp,
                "X-Nonce": nonce,
                "X-Signature": signature,
            },
        )
        _ca_key, ca_cert = ensure_internal_ca()
        ca_path = CERTS_DIR / "internal_ca_certificate.pem"
        context = ssl.create_default_context(cafile=str(ca_path))
        context.check_hostname = False

        try:
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
            self.last_test_ok = data.get("status") == "ok"
            self.last_test_detail = (
                f"Canal HTTPS operativo en 127.0.0.1:{self.port}; "
                f"protocolo negociado y petición HMAC-SHA384 validada."
            )
        except Exception as error:
            self.last_test_ok = False
            self.last_test_detail = str(error)
        return self.last_test_ok, self.last_test_detail

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def rsa_sign_sha384(data: bytes, key_id: Optional[str] = None) -> tuple[str, str]:
    private_key, record = load_private_key(key_id)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA384()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA384(),
    )
    return base64.b64encode(signature).decode("ascii"), record["key_id"]


def rsa_verify_sha384(data: bytes, signature_b64: str, key_id: str) -> bool:
    public_key, _record = load_public_key(key_id)
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA384(),
        )
        return True
    except InvalidSignature:
        return False


def clinical_record_payload(
    patient_id: int,
    doctor_username: str,
    visit_date: str,
    version: int,
    fields: dict,
) -> bytes:
    return canonical_json(
        {
            "patient_id": patient_id,
            "doctor_username": doctor_username,
            "visit_date": visit_date,
            "version": version,
            "reason": fields.get("reason", ""),
            "diagnosis": fields.get("diagnosis", ""),
            "treatment": fields.get("treatment", ""),
            "medications": fields.get("medications", ""),
            "allergies": fields.get("allergies", ""),
            "notes": fields.get("notes", ""),
        }
    )


def verify_clinical_record_row(row) -> tuple[bool, str]:
    fields = {
        "reason": decrypt_text(row["reason_enc"]),
        "diagnosis": decrypt_text(row["diagnosis_enc"]),
        "treatment": decrypt_text(row["treatment_enc"]),
        "medications": decrypt_text(row["medications_enc"]),
        "allergies": decrypt_text(row["allergies_enc"]),
        "notes": decrypt_text(row["notes_enc"]),
    }
    payload = clinical_record_payload(
        row["patient_id"],
        row["doctor_username"],
        row["visit_date"],
        row["version"],
        fields,
    )
    calculated_hash = sha384_hex(payload)

    if not row["content_hash"]:
        return False, "El expediente no tiene hash SHA-384 registrado."
    if calculated_hash != row["content_hash"]:
        return False, "El contenido no coincide con el hash SHA-384 almacenado."
    if row["status"] == "SIGNED":
        if not row["digital_signature"] or not row["signer_key_id"]:
            return False, "El expediente figura firmado, pero no contiene firma digital."
        if not rsa_verify_sha384(payload, row["digital_signature"], row["signer_key_id"]):
            return False, "La firma digital RSA-PSS no es válida."

        certificate_ok, certificate_detail = verify_certificate_for_key(row["signer_key_id"])
        if certificate_ok:
            return True, "Hash SHA-384, firma RSA-PSS y certificado X.509 verificados."

        if row["recovery_signature"] and row["recovery_key_id"] and row["recovery_at"]:
            attestation = canonical_json(
                {
                    "record_id": row["id"],
                    "content_hash": row["content_hash"],
                    "original_key_id": row["signer_key_id"],
                    "recovery_key_id": row["recovery_key_id"],
                    "verified_at": row["recovery_at"],
                }
            )
            if rsa_verify_sha384(
                attestation,
                row["recovery_signature"],
                row["recovery_key_id"],
            ):
                recovery_cert_ok, _ = verify_certificate_for_key(row["recovery_key_id"])
                if recovery_cert_ok:
                    return True, (
                        "Firma original válida y atestación de recuperación verificada "
                        "después de la revocación de la clave."
                    )
        return False, certificate_detail

    return True, "Hash SHA-384 verificado correctamente."


def create_secure_document_package(
    source: Path,
    patient_id: Optional[int],
    category: str,
    owner_username: str,
) -> dict:
    plaintext = source.read_bytes()
    document_uuid = str(uuid.uuid4())
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aad = f"{APP_NAME}|{document_uuid}|{source.name}".encode("utf-8")
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

    public_key, key_record = load_public_key()
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None,
        ),
    )

    plaintext_hash = sha384_hex(plaintext)
    signature_b64, key_id = rsa_sign_sha384(plaintext, key_record["key_id"])
    with db() as conn:
        certificate_row = conn.execute(
            """
            SELECT * FROM certificates
            WHERE key_id=? AND certificate_type='SIGNING'
            ORDER BY created_at DESC LIMIT 1
            """,
            (key_id,),
        ).fetchone()
    certificate_id = certificate_row["certificate_id"] if certificate_row else None
    certificate_pem = (
        Path(certificate_row["pem_path"]).read_bytes()
        if certificate_row else b""
    )

    manifest = {
        "product": APP_NAME,
        "company": COMPANY,
        "version": VERSION,
        "document_uuid": document_uuid,
        "original_name": source.name,
        "category": category,
        "patient_id": patient_id,
        "owner_username": owner_username,
        "created_at": now_iso(),
        "original_size": len(plaintext),
        "plaintext_sha384": plaintext_hash,
        "key_id": key_id,
        "certificate_id": certificate_id,
        "algorithms": {
            "content_encryption": "AES-256-GCM",
            "key_encapsulation": "RSA-3072-OAEP-SHA-384",
            "integrity": "SHA-384",
            "digital_signature": "RSA-3072-PSS-SHA-384",
        },
        "aad_b64": base64.b64encode(aad).decode("ascii"),
    }

    package_path = SECURE_DOCUMENTS_DIR / f"{document_uuid}.cahs"
    with zipfile.ZipFile(package_path, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2),
        )
        package.writestr("nonce.bin", nonce)
        package.writestr("wrapped_key.bin", wrapped_key)
        package.writestr("ciphertext.bin", ciphertext)
        package.writestr("signature.b64", signature_b64)
        if certificate_pem:
            package.writestr("signing_certificate.pem", certificate_pem)

    package_hash = sha384_hex(package_path.read_bytes())
    return {
        "document_uuid": document_uuid,
        "package_path": str(package_path),
        "original_name": source.name,
        "category": category,
        "patient_id": patient_id,
        "owner_username": owner_username,
        "plaintext_sha384": plaintext_hash,
        "package_sha384": package_hash,
        "signature_b64": signature_b64,
        "key_id": key_id,
        "algorithm_summary": "AES-256-GCM + RSA-3072-OAEP + SHA-384 + RSA-PSS",
        "original_size": len(plaintext),
        "created_at": manifest["created_at"],
    }


def verify_and_open_secure_document(package_path: Path, output_path: Path) -> dict:
    package_hash = sha384_hex(package_path.read_bytes())

    with zipfile.ZipFile(package_path, "r") as package:
        manifest = json.loads(package.read("manifest.json").decode("utf-8"))
        nonce = package.read("nonce.bin")
        wrapped_key = package.read("wrapped_key.bin")
        ciphertext = package.read("ciphertext.bin")
        signature_b64 = package.read("signature.b64").decode("ascii")

    private_key, _record = load_private_key(manifest["key_id"])
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None,
        ),
    )
    aad = base64.b64decode(manifest["aad_b64"])
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)

    calculated_hash = sha384_hex(plaintext)
    if calculated_hash != manifest["plaintext_sha384"]:
        raise ValueError("El hash SHA-384 del documento no coincide.")
    certificate_ok, certificate_detail = verify_certificate_for_key(manifest["key_id"])
    if not certificate_ok:
        raise ValueError(certificate_detail)
    if not rsa_verify_sha384(plaintext, signature_b64, manifest["key_id"]):
        raise ValueError("La firma digital RSA-PSS del documento no es válida.")

    output_path.write_bytes(plaintext)
    manifest["calculated_package_sha384"] = package_hash
    return manifest



def derive_ephemeral_session_key(
    username: str,
    password: str,
    totp_code: str,
) -> tuple[bytes, str]:
    """
    Genera una clave efímera de sesión con SHA-256 + HKDF-SHA256.
    La clave no se almacena y se deriva de los elementos de acceso validados.
    """
    material = hashlib.sha256(
        username.encode("utf-8")
        + b"|"
        + password.encode("utf-8")
        + b"|"
        + totp_code.encode("utf-8")
    ).digest()
    salt = hashlib.sha256((APP_NAME + username).encode("utf-8")).digest()
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"CRYPTOACCESS-SECURE-SESSION",
    ).derive(material)
    proof = hmac.new(
        session_key,
        f"{username}|{now_iso()}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return session_key, proof


def derive_backup_key(password: str, salt: bytes, iterations: int = 600_000) -> bytes:
    if len(password) < 12:
        raise ValueError("La contraseña de respaldo debe tener al menos 12 caracteres.")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))


def create_encrypted_backup(destination: Path, password: str) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_backup_key(password, salt)

    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as archive:
        if DB_PATH.exists():
            archive.write(DB_PATH, "database/cryptoaccess_health.db")
        for folder, prefix in [
            (KEYS_DIR, "keys"),
            (CERTS_DIR, "certs"),
            (SECURE_STORE_DIR, "secure_store"),
            (SECURE_DOCUMENTS_DIR, "secure_documents"),
        ]:
            for path in folder.rglob("*"):
                if path.is_file():
                    archive.write(path, f"{prefix}/{path.relative_to(folder)}")
        manifest = {
            "product": APP_NAME,
            "version": VERSION,
            "created_at": now_iso(),
            "scope": "database, encrypted keys, certificates, secure store and protected documents",
            "recovery_note": "Designed for restoration on the same protected workstation.",
        }
        archive.writestr(
            "backup_manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2),
        )

    plaintext = memory.getvalue()
    aad = b"CRYPTOACCESS-ENCRYPTED-BACKUP-V1"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    package = {
        "version": "CAH-BACKUP-1",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 600_000,
        "encryption": "AES-256-GCM",
        "integrity": "SHA-384",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "plaintext_sha384": sha384_hex(plaintext),
        "created_at": now_iso(),
    }
    destination.write_text(json.dumps(package, ensure_ascii=False), encoding="utf-8")
    return {
        "path": str(destination),
        "sha384": package["plaintext_sha384"],
        "size": len(plaintext),
        "iterations": package["iterations"],
    }


def open_encrypted_backup(source: Path, password: str, output_dir: Optional[Path] = None) -> dict:
    package = json.loads(source.read_text(encoding="utf-8"))
    salt = base64.b64decode(package["salt_b64"])
    nonce = base64.b64decode(package["nonce_b64"])
    ciphertext = base64.b64decode(package["ciphertext_b64"])
    key = derive_backup_key(password, salt, int(package["iterations"]))
    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        b"CRYPTOACCESS-ENCRYPTED-BACKUP-V1",
    )
    if sha384_hex(plaintext) != package["plaintext_sha384"]:
        raise ValueError("El respaldo no supera la verificación SHA-384.")
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(plaintext), "r") as archive:
            archive.extractall(output_dir)
    return {
        "sha384": package["plaintext_sha384"],
        "size": len(plaintext),
        "created_at": package["created_at"],
    }


def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 10:
        return False, "La contraseña debe tener al menos 10 caracteres."
    if not any(c.isupper() for c in password):
        return False, "Debe incluir una letra mayúscula."
    if not any(c.islower() for c in password):
        return False, "Debe incluir una letra minúscula."
    if not any(c.isdigit() for c in password):
        return False, "Debe incluir un número."
    if not any(not c.isalnum() for c in password):
        return False, "Debe incluir un símbolo."
    return True, ""


LEGAL_DOCUMENTS = {
    "Aviso de privacidad": {
        "version": "1.0",
        "text": """
1. IDENTIDAD Y RESPONSABILIDAD

CryptoAccess Health Secure es una plataforma tecnológica desarrollada por CryptoSecure Solutions S.A. para apoyar la gestión segura de información administrativa y clínica. La institución de salud que instale y opere el producto será, según la legislación aplicable, la responsable o controladora del tratamiento de los datos de sus pacientes. CryptoSecure Solutions S.A. actuará como proveedor tecnológico y, cuando exista un contrato de soporte o alojamiento, podrá asumir funciones de encargado o procesador conforme al acuerdo correspondiente.

2. INFORMACIÓN TRATADA

La plataforma puede tratar datos de identificación, contacto, agenda, antecedentes, diagnósticos, tratamientos, medicamentos, alergias, notas clínicas, archivos adjuntos, registros de acceso, consentimientos y datos técnicos necesarios para la operación y seguridad del sistema.

3. FINALIDADES

Los datos se utilizarán para brindar atención y continuidad asistencial, administrar expedientes, programar citas, enviar recordatorios autorizados, controlar accesos, mantener trazabilidad, generar respaldos, investigar incidentes, cumplir obligaciones legales y mejorar la calidad del servicio.

4. PRINCIPIOS

El tratamiento se realizará conforme a los principios de licitud, finalidad, proporcionalidad, minimización, exactitud, confidencialidad, integridad, disponibilidad, responsabilidad demostrada y conservación limitada.

5. BASE JURÍDICA

La institución deberá definir la base jurídica aplicable en cada jurisdicción. Esta puede incluir consentimiento, prestación de servicios de salud, cumplimiento de obligaciones legales, protección de intereses vitales, interés público en salud y otras bases expresamente autorizadas.

6. ACCESO Y DESTINATARIOS

Solo accederá el personal que lo requiera para sus funciones. Los médicos podrán consultar y actualizar información clínica; recepción accederá a datos administrativos y de citas; TI accederá a información técnica seudonimizada; administración gestionará usuarios y políticas sin obtener acceso clínico automático. Los proveedores externos deberán estar sujetos a acuerdos de confidencialidad y tratamiento de datos.

7. TRANSFERENCIAS

Las transferencias internacionales deberán evaluarse antes de habilitar servicios externos. La institución deberá comprobar la existencia de garantías contractuales, técnicas y legales adecuadas.

8. DERECHOS

Las personas podrán ejercer los derechos reconocidos por la legislación aplicable, como acceso, rectificación, actualización, oposición, restricción, portabilidad o supresión cuando proceda. Las solicitudes deberán tramitarse por el canal oficial de la institución.

9. SEGURIDAD

La plataforma incorpora cifrado AES-256-GCM, contraseñas protegidas mediante Argon2id, autenticación multifactor TOTP, control por roles, auditoría y separación de privilegios. Estas medidas deben complementarse con TLS, respaldos, gestión segura de claves, capacitación, políticas internas y protección física.

10. CONSERVACIÓN

Los datos se conservarán durante los plazos clínicos, contractuales y legales definidos por la institución y la jurisdicción aplicable. Finalizado el plazo, deberán eliminarse, anonimizarse o bloquearse de forma segura.

11. INCIDENTES

Los incidentes se gestionarán mediante detección, contención, evaluación, preservación de evidencia, notificación cuando corresponda, recuperación y acciones correctivas.

12. ACTUALIZACIONES

Este aviso podrá actualizarse cuando cambien las funciones, la normativa o los procesos institucionales. La versión vigente deberá permanecer disponible para pacientes, usuarios y autoridades competentes.
""",
    },
    "Consentimiento informado": {
        "version": "1.0",
        "text": """
CONSENTIMIENTO PARA EL TRATAMIENTO DE INFORMACIÓN DE SALUD

La institución deberá obtener y documentar el consentimiento cuando este constituya la base jurídica aplicable. El registro deberá identificar al paciente, la versión del documento, la fecha, las finalidades autorizadas, el medio de aceptación y el funcionario que gestionó el proceso.

El paciente deberá recibir información clara sobre:

• Datos que serán recopilados.
• Finalidades asistenciales y administrativas.
• Uso de recordatorios y canales de comunicación.
• Posibles destinatarios y proveedores.
• Plazos de conservación.
• Riesgos razonables y medidas de seguridad.
• Derechos y canales para ejercerlos.
• Posibilidad de retirar el consentimiento cuando proceda.

El consentimiento no deberá presentarse como autorización ilimitada. Las finalidades opcionales, como comunicaciones promocionales o investigación, deberán separarse de la atención médica. La negativa a aceptar una finalidad opcional no deberá impedir la prestación de servicios esenciales.

La revocación no afectará la licitud del tratamiento realizado antes de su retiro y no obligará a eliminar información que deba conservarse por razones clínicas o legales.
""",
    },
    "Política de acceso y confidencialidad": {
        "version": "1.0",
        "text": """
POLÍTICA DE ACCESO Y CONFIDENCIALIDAD

1. Todo acceso deberá asociarse con una cuenta individual.
2. Se prohíbe compartir contraseñas, códigos MFA o sesiones.
3. Los permisos se asignarán según funciones y mínimo privilegio.
4. Recepción no accederá a diagnósticos, tratamientos, notas médicas o adjuntos clínicos.
5. TI no visualizará nombres, diagnósticos ni contenidos clínicos. Los logs usarán identificadores técnicos.
6. El administrador gestionará cuentas y configuración sin acceso clínico automático.
7. Los médicos solo consultarán expedientes vinculados a una necesidad asistencial.
8. Todo acceso, modificación, firma, exportación o intento fallido deberá registrarse.
9. Las sesiones se cerrarán al finalizar la jornada o al abandonar el puesto.
10. Los permisos se revisarán periódicamente y al producirse cambios laborales.
11. Las cuentas inactivas deberán suspenderse sin demora.
12. El acceso de emergencia deberá justificarse y auditarse.
13. La información no podrá copiarse a medios personales o servicios no autorizados.
14. Las infracciones estarán sujetas a medidas disciplinarias, contractuales y legales.
""",
    },
    "Política de conservación y eliminación": {
        "version": "1.0",
        "text": """
POLÍTICA DE CONSERVACIÓN Y ELIMINACIÓN

La organización deberá crear una tabla de retención por país, tipo de documento y obligación aplicable. Esta política no fija plazos universales porque los requisitos varían entre jurisdicciones.

Categorías mínimas:

• Expedientes clínicos activos.
• Expedientes clínicos inactivos.
• Consentimientos.
• Citas y recordatorios.
• Documentos firmados.
• Registros de auditoría.
• Incidentes de seguridad.
• Respaldos.
• Información de usuarios.
• Datos técnicos y métricas.

Reglas operativas:

1. Una nota clínica firmada no se eliminará ni sobrescribirá. Las correcciones crearán una nueva versión.
2. Las eliminaciones deberán quedar autorizadas y auditadas.
3. Los medios de respaldo deberán someterse a los mismos plazos que el sistema principal.
4. Los respaldos vencidos deberán destruirse de forma verificable.
5. La información sujeta a investigación o litigio quedará suspendida de eliminación.
6. La anonimización deberá impedir razonablemente la reidentificación.
7. Los documentos físicos derivados del sistema deberán destruirse de manera segura.
8. La institución deberá revisar la tabla de retención al menos una vez al año.
""",
    },
    "Seguridad de la información": {
        "version": "1.0",
        "text": """
POLÍTICA DE SEGURIDAD DE LA INFORMACIÓN

Objetivo: preservar la confidencialidad, integridad, disponibilidad, autenticidad y trazabilidad de la información de salud.

Controles principales:

• Gestión de riesgos y revisión periódica.
• Autenticación multifactor para cuentas privilegiadas y personal clínico.
• Contraseñas robustas almacenadas mediante Argon2id.
• Cifrado AES-256-GCM para información sensible almacenada.
• TLS para comunicaciones en un despliegue cliente-servidor.
• Separación entre datos administrativos, clínicos y técnicos.
• Gestión del ciclo de vida de claves.
• Registro y revisión de eventos.
• Copias de seguridad cifradas, separadas y probadas.
• Actualizaciones y correcciones de seguridad.
• Protección contra malware.
• Capacitación y acuerdos de confidencialidad.
• Evaluación de proveedores.
• Gestión formal de cambios.
• Pruebas de seguridad antes de producción.
• Continuidad operativa y recuperación ante desastres.

Las claves maestras no deberán almacenarse junto con la base de datos en un despliegue comercial. Se recomienda utilizar un KMS o HSM, rotación controlada y separación de funciones.
""",
    },
    "Respuesta a incidentes": {
        "version": "1.0",
        "text": """
PROCEDIMIENTO DE RESPUESTA A INCIDENTES

1. DETECCIÓN
Registrar la alerta, fecha, origen, sistema afectado y responsable inicial.

2. CLASIFICACIÓN
Evaluar confidencialidad, integridad, disponibilidad, alcance, datos afectados y riesgo para pacientes.

3. CONTENCIÓN
Aislar cuentas, dispositivos o servicios comprometidos sin destruir evidencia.

4. PRESERVACIÓN DE EVIDENCIA
Conservar logs, copias forenses, hashes, tiempos y cadena de custodia.

5. ERRADICACIÓN
Eliminar la causa, corregir vulnerabilidades, rotar credenciales y validar controles.

6. RECUPERACIÓN
Restaurar servicios desde fuentes confiables, verificar integridad y monitorear recurrencia.

7. NOTIFICACIÓN
Determinar obligaciones de notificación a pacientes, autoridades, aseguradoras, socios y dirección. Los plazos dependen de la jurisdicción.

8. INVESTIGACIÓN
Identificar causa raíz, fallas de control, impacto real y decisiones adoptadas.

9. ACCIONES CORRECTIVAS
Actualizar controles, políticas, formación, contratos y arquitectura.

10. CIERRE
Documentar resultados, responsables, lecciones aprendidas y aprobación del cierre.

Nunca se deberá ocultar, alterar o eliminar evidencia de un incidente.
""",
    },
    "Continuidad y respaldos": {
        "version": "1.0",
        "text": """
POLÍTICA DE CONTINUIDAD Y RESPALDOS

• Realizar respaldos cifrados según la criticidad y el volumen de cambios.
• Mantener al menos una copia separada del entorno principal.
• Restringir el acceso a respaldos mediante cuentas específicas.
• Probar periódicamente la restauración.
• Documentar RPO y RTO de cada servicio.
• Monitorear fallos de respaldo y almacenamiento.
• Proteger las claves de recuperación.
• Mantener inventario de copias, ubicaciones y responsables.
• Incluir escenarios de ransomware, pérdida de sede, corrupción y fallo de proveedor.
• Revisar el plan después de pruebas, incidentes y cambios relevantes.

La existencia de un archivo de respaldo no demuestra recuperación. Toda estrategia deberá validarse mediante restauraciones documentadas.
""",
    },
    "Normas y marcos aplicables": {
        "version": "1.0",
        "text": """
REFERENCIAS INTERNACIONALES

ISO/IEC 27001:2022
Requisitos para establecer, implementar, mantener y mejorar un sistema de gestión de seguridad de la información.

ISO/IEC 27002:2022
Guía de controles sobre acceso, criptografía, operaciones, personas, proveedores, incidentes y continuidad.

ISO 27799:2025
Controles de seguridad de la información para organizaciones de salud, basados en ISO/IEC 27002:2022.

ISO/IEC 27701
Marco de gestión de privacidad para responsables y encargados del tratamiento.

ISO 9001:2015
Gestión de calidad, enfoque por procesos, control documental, auditoría, mejora continua y tratamiento de no conformidades.

HL7 FHIR
Referencia de interoperabilidad para representar e intercambiar información sanitaria.

IEC 81001-5-1
Actividades de seguridad durante el ciclo de vida de productos de salud y sistemas de TI médica.

ISO/IEC 30107-3
Solo aplicaría si se integra biometría con detección de ataques de presentación.

ICAO Doc 9303
No es una norma clínica. Podría utilizarse únicamente en futuras funciones de validación de documentos de viaje.

MARCOS JURÍDICOS DE REFERENCIA

Costa Rica:
Ley N.° 8968 y su normativa relacionada con protección de datos personales. La institución deberá validar requisitos sectoriales y de expediente clínico con asesoría local.

Unión Europea:
Reglamento General de Protección de Datos. Los datos de salud requieren protección reforzada, base jurídica adecuada, privacidad desde el diseño y evaluación de impacto cuando exista alto riesgo.

Estados Unidos:
HIPAA Privacy Rule y HIPAA Security Rule para entidades y asociados de negocio cubiertos. Exigen salvaguardas administrativas, físicas y técnicas para la información médica electrónica.

IMPORTANTE:
La presencia de estas referencias en el producto no implica certificación ni cumplimiento automático. Cada organización deberá realizar un análisis legal y de riesgos antes del despliegue.
""",
    },
    "Términos de uso y descargo": {
        "version": "1.0",
        "text": """
TÉRMINOS DE USO Y DESCARGO RESPONSABLE

CryptoAccess Health Secure es una herramienta de apoyo administrativo y clínico. No reemplaza el criterio profesional, la responsabilidad médica, los protocolos institucionales ni la asesoría jurídica.

La institución usuaria es responsable de:

• Configurar usuarios y permisos.
• Comprobar la identidad de los usuarios.
• Definir políticas de conservación.
• Gestionar consentimientos.
• Capacitar al personal.
• Proteger infraestructura y dispositivos.
• Mantener respaldos.
• Revisar logs.
• Gestionar incidentes.
• Cumplir la legislación local.
• Validar integraciones y comunicaciones externas.

CryptoSecure Solutions S.A. deberá proporcionar documentación, actualizaciones y medidas razonables según el contrato. Ninguna cláusula pretende excluir responsabilidades que no puedan limitarse legalmente.

Este prototipo académico no está certificado para utilizarse con pacientes reales. Un despliegue comercial requiere pruebas de seguridad, revisión jurídica, gestión profesional de claves, TLS, arquitectura cliente-servidor, base de datos empresarial, validación clínica, controles de continuidad y acuerdos contractuales.
""",
    },
}



def reprotect_document_row(row, new_key_id: str) -> None:
    package_path = Path(row["package_path"])
    with zipfile.ZipFile(package_path, "r") as package:
        manifest = json.loads(package.read("manifest.json").decode("utf-8"))
        nonce = package.read("nonce.bin")
        wrapped_key = package.read("wrapped_key.bin")
        ciphertext = package.read("ciphertext.bin")

    old_private, _ = load_private_key(manifest["key_id"])
    aes_key = old_private.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        base64.b64decode(manifest["aad_b64"]),
    )
    if sha384_hex(plaintext) != manifest["plaintext_sha384"]:
        raise ValueError("El documento afectado no superó la verificación SHA-384.")

    new_public, _ = load_public_key(new_key_id)
    new_wrapped_key = new_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None,
        ),
    )
    new_signature, _ = rsa_sign_sha384(plaintext, new_key_id)
    with db() as conn:
        new_cert = conn.execute(
            """
            SELECT * FROM certificates WHERE key_id=? AND certificate_type='SIGNING'
            ORDER BY created_at DESC LIMIT 1
            """,
            (new_key_id,),
        ).fetchone()
    history = manifest.setdefault("key_history", [])
    history.append(
        {
            "previous_key_id": manifest["key_id"],
            "reprotected_at": now_iso(),
            "reason": "key_compromise_response",
        }
    )
    manifest["key_id"] = new_key_id
    manifest["certificate_id"] = new_cert["certificate_id"] if new_cert else None
    manifest["reprotected_at"] = now_iso()

    temp_path = package_path.with_suffix(".tmp")
    with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        package.writestr("nonce.bin", nonce)
        package.writestr("wrapped_key.bin", new_wrapped_key)
        package.writestr("ciphertext.bin", ciphertext)
        package.writestr("signature.b64", new_signature)
        if new_cert:
            package.writestr(
                "signing_certificate.pem",
                Path(new_cert["pem_path"]).read_bytes(),
            )
    temp_path.replace(package_path)

    with db() as conn:
        conn.execute(
            """
            UPDATE secure_documents SET key_id=?, signature_b64=?,
            package_sha384=?, verification_status='REPROTECTED',
            last_verified_at=? WHERE id=?
            """,
            (
                new_key_id,
                new_signature,
                sha384_hex(package_path.read_bytes()),
                now_iso(),
                row["id"],
            ),
        )


def revoke_compromised_key(key_id: str, reason: str, actor: str) -> dict:
    key = get_key_record(key_id)
    if not key:
        raise ValueError("La clave seleccionada no existe.")
    if key["status"] in ("REVOKED", "COMPROMISED"):
        raise ValueError("La clave ya fue revocada.")

    new_key_id = ensure_active_rsa_key()
    if key["status"] == "ACTIVE" or new_key_id == key_id:
        new_key_id = create_rsa_key_pair(actor, activate=True)

    with db() as conn:
        documents = conn.execute(
            "SELECT * FROM secure_documents WHERE key_id=?",
            (key_id,),
        ).fetchall()
        records = conn.execute(
            "SELECT * FROM clinical_records WHERE signer_key_id=? AND status='SIGNED'",
            (key_id,),
        ).fetchall()

    reprotected = 0
    for document in documents:
        reprotect_document_row(document, new_key_id)
        reprotected += 1

    recovered_records = 0
    for record in records:
        valid, detail = verify_clinical_record_row(record)
        if not valid:
            continue
        recovery_time = now_iso()
        attestation = canonical_json(
            {
                "record_id": record["id"],
                "content_hash": record["content_hash"],
                "original_key_id": key_id,
                "recovery_key_id": new_key_id,
                "verified_at": recovery_time,
            }
        )
        recovery_signature, _ = rsa_sign_sha384(attestation, new_key_id)
        with db() as conn:
            conn.execute(
                """
                UPDATE clinical_records SET recovery_signature=?,
                recovery_key_id=?, recovery_at=? WHERE id=?
                """,
                (recovery_signature, new_key_id, recovery_time, record["id"]),
            )
        recovered_records += 1

    incident_uuid = str(uuid.uuid4())
    with db() as conn:
        conn.execute(
            """
            UPDATE key_registry SET status='COMPROMISED',
            compromise_reason=?, retired_at=? WHERE key_id=?
            """,
            (reason, now_iso(), key_id),
        )
        conn.execute(
            "UPDATE certificates SET status='REVOKED' WHERE key_id=?",
            (key_id,),
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_uuid,incident_type,severity,status,key_id,description,
             affected_documents,affected_records,created_by,created_at)
            VALUES(?, 'KEY_COMPROMISE', 'CRITICAL', 'CONTAINED', ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_uuid,
                key_id,
                reason,
                len(documents),
                len(records),
                actor,
                now_iso(),
            ),
        )

    return {
        "incident_uuid": incident_uuid,
        "new_key_id": new_key_id,
        "documents_reprotected": reprotected,
        "records_attested": recovered_records,
    }



@dataclass
class Session:
    id: int
    username: str
    full_name: str
    role: str


class RoundedCard(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        defaults = {
            "fg_color": COLORS["card"],
            "corner_radius": 18,
            "border_width": 1,
            "border_color": COLORS["line"],
        }
        defaults.update(kwargs)
        super().__init__(master, **defaults)


class HealthApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ensure_dirs()
        initialize_database()
        ensure_internal_ca()
        ensure_active_rsa_key()

        self.tls_service = SecureTLSService()
        self.tls_service.start()
        self.tls_service.self_test()
        self.last_activity = time.time()

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self.title(f"{APP_NAME} | {VERSION}")
        self.geometry("1440x880")
        self.minsize(1200, 720)
        self.configure(fg_color=COLORS["bg"])

        self.session: Optional[Session] = None
        self.logo_large = ctk.CTkImage(Image.open(LOGO_PATH), size=(420, 270))
        self.logo_sidebar = ctk.CTkImage(Image.open(LOGO_PATH), size=(205, 132))

        self._configure_tree_style()
        self.protocol("WM_DELETE_WINDOW", self._close_application)
        self.bind_all("<Any-KeyPress>", lambda _event: self._touch_activity())
        self.bind_all("<Any-Button>", lambda _event: self._touch_activity())
        self.after(30000, self._check_session_timeout)

        with db() as conn:
            count = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        if count == 0:
            self.after(100, self.show_first_run)
        else:
            self.show_login()

    def _configure_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Health.Treeview",
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground=COLORS["text"],
            rowheight=32,
            font=("Segoe UI", 10),
            borderwidth=0,
        )
        style.configure(
            "Health.Treeview.Heading",
            background="#EFF4FB",
            foreground=COLORS["text"],
            font=("Segoe UI", 10, "bold"),
            relief="flat",
        )
        style.map(
            "Health.Treeview",
            background=[("selected", "#DCEBFF")],
            foreground=[("selected", COLORS["text"])],
        )


    def _touch_activity(self):
        self.last_activity = time.time()

    def _check_session_timeout(self):
        if self.session:
            with db() as conn:
                row = conn.execute(
                    "SELECT value FROM settings WHERE name='session_timeout_minutes'"
                ).fetchone()
            timeout_minutes = int(row["value"]) if row else 15
            if time.time() - self.last_activity > timeout_minutes * 60:
                audit(
                    self.session.username,
                    self.session.role,
                    "SESSION_TIMEOUT",
                    "SESSION",
                    details=f"Cierre por inactividad de {timeout_minutes} minutos.",
                    severity="MEDIUM",
                )
                messagebox.showinfo(
                    "Sesión finalizada",
                    "La sesión se cerró automáticamente por inactividad.",
                )
                self.show_login()
        self.after(30000, self._check_session_timeout)

    def _close_application(self):
        try:
            self.tls_service.stop()
        finally:
            self.destroy()

    def clear_root(self):
        for widget in self.winfo_children():
            widget.destroy()




    def provision_user_dialog(
        self,
        role: str,
        fixed_username: Optional[str] = None,
        on_success=None,
        title: Optional[str] = None,
        mandatory: bool = False,
    ):
        dialog = ctk.CTkToplevel(self)
        dialog.title(title or "Crear cuenta")
        dialog.geometry("700x590")
        dialog.minsize(650, 550)
        dialog.resizable(True, True)
        dialog.grab_set()

        outer = ctk.CTkFrame(dialog, fg_color=COLORS["bg"])
        outer.pack(fill=BOTH, expand=True)

        header = ctk.CTkFrame(
            outer,
            fg_color=COLORS["navy"],
            corner_radius=0,
            height=92,
        )
        header.pack(fill=X)
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text=title or f"Crear {self.role_label(role)}",
            font=("Segoe UI", 24, "bold"),
            text_color="white",
        ).pack(anchor="w", padx=28, pady=(18, 2))

        ctk.CTkLabel(
            header,
            text="La cuenta se crea primero. Authy se activa después desde Configuración.",
            text_color="#C8D6EA",
        ).pack(anchor="w", padx=28)

        card = RoundedCard(outer)
        card.pack(fill=BOTH, expand=True, padx=26, pady=22)

        full_name = ctk.StringVar()
        username = ctk.StringVar(value=fixed_username or "")
        password = ctk.StringVar()
        confirm = ctk.StringVar()

        ctk.CTkLabel(
            card,
            text="Datos de la cuenta",
            font=("Segoe UI", 20, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=28, pady=(24, 16))

        for label, variable, hidden, disabled in [
            ("Nombre completo", full_name, False, False),
            ("Nombre de usuario", username, False, fixed_username is not None),
            ("Contraseña", password, True, False),
            ("Confirmar contraseña", confirm, True, False),
        ]:
            ctk.CTkLabel(
                card,
                text=label,
                text_color=COLORS["text"],
            ).pack(anchor="w", padx=28)

            entry = ctk.CTkEntry(
                card,
                textvariable=variable,
                show="•" if hidden else "",
                height=43,
                corner_radius=12,
            )
            entry.pack(fill=X, padx=28, pady=(5, 13))

            if disabled:
                entry.configure(state="disabled")

        info = ctk.CTkFrame(
            card,
            fg_color="#F7FAFE",
            corner_radius=12,
            border_width=1,
            border_color=COLORS["line"],
        )
        info.pack(fill=X, padx=28, pady=(2, 16))

        ctk.CTkLabel(
            info,
            text=(
                "Después del primer ingreso, el usuario podrá activar Authy desde "
                "Configuración > Seguridad. Mientras MFA no esté configurado, "
                "el sistema mostrará el estado como pendiente."
            ),
            wraplength=580,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=16, pady=13)

        def save_user():
            clean_username = username.get().strip().lower()
            ok, detail = validate_password(password.get())

            if not full_name.get().strip() or not clean_username:
                messagebox.showwarning(
                    "Datos",
                    "Complete el nombre y el usuario.",
                )
                return

            if " " in clean_username:
                messagebox.showwarning(
                    "Usuario",
                    "El nombre de usuario no debe contener espacios.",
                )
                return

            if not ok:
                messagebox.showwarning(
                    "Contraseña",
                    detail,
                )
                return

            if password.get() != confirm.get():
                messagebox.showwarning(
                    "Contraseña",
                    "Las contraseñas no coinciden.",
                )
                return

            try:
                with db() as conn:
                    conn.execute(
                        """
                        INSERT INTO users
                        (username,full_name,role,password_hash,totp_secret_enc,
                         mfa_enabled,setup_complete,last_totp_counter,active,
                         failed_attempts,mfa_reset_pending,password_changed_at,
                         created_at)
                        VALUES(?,?,?,?,NULL,0,1,NULL,1,0,0,?,?)
                        """,
                        (
                            clean_username,
                            full_name.get().strip(),
                            role,
                            ph.hash(password.get()),
                            now_iso(),
                            now_iso(),
                        ),
                    )

                audit(
                    clean_username,
                    role,
                    "PROVISION",
                    "USER",
                    clean_username,
                    details=(
                        "Cuenta creada. MFA pendiente de activación dentro de Configuración."
                    ),
                    metadata={
                        "authentication": [
                            "username",
                            "Argon2id password",
                            "TOTP Authy pending activation",
                        ]
                    },
                )

            except sqlite3.IntegrityError:
                messagebox.showerror(
                    "Cuenta",
                    "El usuario ya existe o ya existe el auditor único.",
                )
                return

            dialog.destroy()

            if on_success:
                self.after(150, on_success)

        ctk.CTkButton(
            card,
            text="Crear cuenta",
            height=48,
            corner_radius=14,
            fg_color=COLORS["green"],
            hover_color="#128455",
            font=("Segoe UI", 14, "bold"),
            command=save_user,
        ).pack(fill=X, padx=28, pady=(0, 24))

        def close_dialog():
            if mandatory:
                self.destroy()
            else:
                dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", close_dialog)

    def show_first_run(self):
        self.withdraw()

        def create_auditor():
            self.provision_user_dialog(
                "AUDITOR",
                fixed_username="auditor_crypto",
                title="Crear auditor criptográfico único",
                on_success=finish,
                mandatory=True,
            )

        def finish():
            self.deiconify()
            self.show_login()
            messagebox.showinfo(
                "Configuración completada",
                "Se crearon el administrador y el auditor único. Ambos utilizan usuario, contraseña y MFA.",
            )

        self.provision_user_dialog(
            "ADMIN",
            title="Crear administrador inicial",
            on_success=create_auditor,
            mandatory=True,
        )



    def show_login(self):
        self.clear_root()
        self.session = None
        self.last_activity = time.time()

        left = ctk.CTkFrame(
            self,
            width=500,
            corner_radius=0,
            fg_color=COLORS["navy"],
        )
        left.pack(side=LEFT, fill=Y)
        left.pack_propagate(False)

        right = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=COLORS["bg"],
        )
        right.pack(side=RIGHT, fill=BOTH, expand=True)

        ctk.CTkLabel(
            left,
            image=self.logo_large,
            text="",
        ).pack(pady=(60, 6))

        ctk.CTkLabel(
            left,
            text="CryptoAccess\nHealth Secure",
            font=("Segoe UI", 30, "bold"),
            text_color="white",
            justify="left",
        ).pack(anchor="w", padx=62)

        ctk.CTkLabel(
            left,
            text=(
                "Protección criptográfica y gestión clínica\n"
                "para clínicas, centros médicos y odontológicos."
            ),
            font=("Segoe UI", 13),
            text_color="#C8D6EA",
            justify="left",
        ).pack(anchor="w", padx=62, pady=(12, 22))

        for text in [
            "Usuario institucional",
            "Contraseña protegida con Argon2id",
            "MFA temporal mediante Authy",
            "Bloqueo ante intentos repetidos",
            "Canal TLS y auditoría criptográfica",
        ]:
            ctk.CTkLabel(
                left,
                text=f"✓  {text}",
                text_color="#DCEBFA",
                anchor="w",
            ).pack(fill=X, padx=62, pady=4)

        login_card = RoundedCard(
            right,
            width=585,
            height=610,
        )
        login_card.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
        )
        login_card.pack_propagate(False)

        ctk.CTkLabel(
            login_card,
            text="Acceso seguro",
            font=("Segoe UI", 29, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=48, pady=(42, 4))

        ctk.CTkLabel(
            login_card,
            text=f"{COMPANY} | {VERSION}",
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=48, pady=(0, 26))

        user_var = ctk.StringVar()
        password_var = ctk.StringVar()
        code_var = ctk.StringVar()

        for label, variable, hidden, placeholder in [
            ("Usuario", user_var, False, "Ingrese su usuario"),
            ("Contraseña", password_var, True, "Ingrese su contraseña"),
            (
                "Código MFA de Authy",
                code_var,
                False,
                "Solo si ya activó Authy",
            ),
        ]:
            ctk.CTkLabel(
                login_card,
                text=label,
                text_color=COLORS["text"],
            ).pack(anchor="w", padx=48)

            ctk.CTkEntry(
                login_card,
                textvariable=variable,
                show="•" if hidden else "",
                placeholder_text=placeholder,
                height=45,
                corner_radius=13,
            ).pack(fill=X, padx=48, pady=(6, 15))

        ctk.CTkLabel(
            login_card,
            text=(
                "Si la cuenta todavía no tiene MFA activado, puede ingresar con usuario "
                "y contraseña y configurarlo dentro de Configuración > Seguridad."
            ),
            wraplength=470,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=48, pady=(2, 14))

        def failed(row, reason, factor):
            attempts = int(row["failed_attempts"] or 0) + 1
            locked_until = None

            if attempts >= 5:
                locked_until = (
                    datetime.now() + timedelta(minutes=5)
                ).isoformat(timespec="seconds")
                attempts = 0

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts=?,locked_until=?
                    WHERE id=?
                    """,
                    (attempts, locked_until, row["id"]),
                )

            audit(
                row["username"],
                row["role"],
                "LOGIN",
                "SESSION",
                result="DENIED",
                details=reason,
                severity="HIGH",
                metadata={
                    "failed_factor": factor,
                    "lock_applied": locked_until is not None,
                },
            )

            messagebox.showerror(
                "Acceso denegado",
                reason,
            )

        def authenticate():
            username = user_var.get().strip().lower()

            with db() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM users
                    WHERE username=? AND active=1 AND setup_complete=1
                    """,
                    (username,),
                ).fetchone()

            if not row:
                audit(
                    username or "unknown",
                    "UNKNOWN",
                    "LOGIN",
                    "SESSION",
                    result="DENIED",
                    details="Usuario inexistente, inactivo o no provisionado.",
                    severity="HIGH",
                )
                messagebox.showerror(
                    "Acceso denegado",
                    "Credenciales incorrectas.",
                )
                return

            if row["locked_until"]:
                try:
                    lock_time = datetime.fromisoformat(row["locked_until"])
                    if datetime.now() < lock_time:
                        seconds = max(
                            1,
                            int(
                                (
                                    lock_time - datetime.now()
                                ).total_seconds()
                            ),
                        )
                        messagebox.showerror(
                            "Cuenta bloqueada",
                            f"Intente nuevamente en aproximadamente {seconds} segundos.",
                        )
                        return
                except ValueError:
                    pass

            try:
                ph.verify(
                    row["password_hash"],
                    password_var.get(),
                )
            except VerifyMismatchError:
                failed(
                    row,
                    "Contraseña incorrecta.",
                    "PASSWORD",
                )
                return

            # Si el administrador inició una recuperación MFA, la cuenta debe
            # completar el nuevo registro antes de ingresar normalmente.
            if row["mfa_reset_pending"]:
                messagebox.showwarning(
                    "MFA pendiente de recuperación",
                    "Utilice 'Perdí el acceso a Authy' para registrar el nuevo dispositivo.",
                )
                return

            counter = None
            mfa_state = "not_configured"

            if (
                row["mfa_enabled"]
                and row["totp_secret_enc"]
            ):
                totp_ok, counter, totp_detail = verify_totp_once(
                    row,
                    normalize_totp_code(code_var.get()),
                )
                if not totp_ok:
                    failed(
                        row,
                        totp_detail,
                        "TOTP_REPLAY_OR_INVALID",
                    )
                    return
                mfa_state = "verified"

            tls_ok, tls_detail = self.tls_service.self_test()

            if not tls_ok:
                audit(
                    username,
                    row["role"],
                    "TLS_SELF_TEST",
                    "SECURE_CHANNEL",
                    result="FAILED",
                    details=tls_detail,
                    severity="HIGH",
                )
                messagebox.showerror(
                    "Canal seguro",
                    "No fue posible validar el canal TLS interno.",
                )
                return

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET last_totp_counter=?,failed_attempts=0,
                        locked_until=NULL
                    WHERE id=?
                    """,
                    (
                        counter if mfa_state == "verified" else row["last_totp_counter"],
                        row["id"],
                    ),
                )

            self.session = Session(
                row["id"],
                row["username"],
                row["full_name"],
                row["role"],
            )

            self.session_crypto_key, self.session_proof = (
                derive_ephemeral_session_key(
                    username,
                    password_var.get(),
                    code_var.get().strip() if mfa_state == "verified" else "MFA-PENDING",
                )
            )

            audit(
                self.session.username,
                self.session.role,
                "LOGIN",
                "SESSION",
                details=(
                    "Acceso concedido. "
                    + (
                        "MFA Authy verificado."
                        if mfa_state == "verified"
                        else "MFA todavía no configurado."
                    )
                ),
                metadata={
                    "username": "verified",
                    "password": "verified",
                    "mfa": mfa_state,
                    "totp_counter": counter,
                    "tls": tls_detail,
                    "session_derivation": "SHA-256 + HKDF-SHA256",
                    "session_proof_hmac_sha256": (
                        self.session_proof[:24] + "..."
                    ),
                },
            )

            self.last_activity = time.time()
            self.show_dashboard()

            # Primer ingreso o MFA pendiente: dirigir al usuario al lugar correcto.
            if mfa_state == "not_configured":
                self.after(
                    250,
                    lambda: (
                        self.page_settings(),
                        messagebox.showinfo(
                            "Active Authy",
                            "La cuenta fue creada correctamente. Configure Authy en la pestaña Seguridad para completar la protección del acceso.",
                        ),
                    ),
                )

        ctk.CTkButton(
            login_card,
            text="Iniciar sesión",
            height=49,
            corner_radius=15,
            fg_color=COLORS["blue"],
            hover_color="#0E63D8",
            font=("Segoe UI", 14, "bold"),
            command=authenticate,
        ).pack(fill=X, padx=48, pady=(2, 9))

        ctk.CTkButton(
            login_card,
            text="Perdí el acceso a Authy",
            height=38,
            corner_radius=12,
            fg_color="transparent",
            hover_color="#EAF2FE",
            text_color=COLORS["blue"],
            command=self.mfa_recovery_dialog,
        ).pack(fill=X, padx=48, pady=(0, 8))

    def mfa_recovery_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Recuperar acceso MFA")
        dialog.geometry("650x680")
        dialog.grab_set()

        frame = ctk.CTkScrollableFrame(
            dialog,
            fg_color=COLORS["bg"],
        )
        frame.pack(fill=BOTH, expand=True)

        ctk.CTkLabel(
            frame,
            text="Recuperar Authy",
            font=("Segoe UI", 25, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=30, pady=(28, 5))

        ctk.CTkLabel(
            frame,
            text=(
                "Este proceso requiere usuario, contraseña y el código de recuperación "
                "temporal entregado por el administrador."
            ),
            wraplength=560,
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=30, pady=(0, 20))

        username = ctk.StringVar()
        password = ctk.StringVar()
        recovery = ctk.StringVar()

        for label, variable, hidden in [
            ("Usuario", username, False),
            ("Contraseña", password, True),
            ("Código de recuperación", recovery, False),
        ]:
            ctk.CTkLabel(
                frame,
                text=label,
                text_color=COLORS["text"],
            ).pack(anchor="w", padx=30)
            ctk.CTkEntry(
                frame,
                textvariable=variable,
                show="•" if hidden else "",
                height=42,
                corner_radius=12,
            ).pack(fill=X, padx=30, pady=(5, 13))

        qr_holder = ctk.CTkFrame(
            frame,
            fg_color="transparent",
        )
        qr_holder.pack(fill=X, padx=30, pady=(5, 8))

        confirm_code = ctk.StringVar()
        state = {
            "user_id": None,
            "secret": None,
            "qr_path": None,
            "qr_image": None,
        }

        def validate_recovery():
            clean_user = username.get().strip().lower()

            with db() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM users
                    WHERE username=? AND active=1
                    """,
                    (clean_user,),
                ).fetchone()

            if not row:
                messagebox.showerror(
                    "Recuperación",
                    "No se encontró una cuenta válida.",
                )
                return

            try:
                ph.verify(
                    row["password_hash"],
                    password.get(),
                )
            except VerifyMismatchError:
                messagebox.showerror(
                    "Recuperación",
                    "La contraseña no es correcta.",
                )
                audit(
                    clean_user,
                    row["role"],
                    "MFA_RECOVERY",
                    "USER",
                    result="DENIED",
                    details="Contraseña incorrecta durante recuperación MFA.",
                    severity="HIGH",
                )
                return

            if (
                not row["mfa_reset_pending"]
                or not row["mfa_recovery_token_hash"]
                or not row["mfa_recovery_expires"]
            ):
                messagebox.showerror(
                    "Recuperación",
                    "No existe una recuperación MFA activa para esta cuenta.",
                )
                return

            try:
                expires = datetime.fromisoformat(
                    row["mfa_recovery_expires"]
                )
            except ValueError:
                expires = datetime.min

            if datetime.now() > expires:
                messagebox.showerror(
                    "Recuperación",
                    "El código de recuperación venció. Solicite uno nuevo al administrador.",
                )
                return

            try:
                ph.verify(
                    row["mfa_recovery_token_hash"],
                    recovery.get().strip(),
                )
            except VerifyMismatchError:
                messagebox.showerror(
                    "Recuperación",
                    "El código de recuperación es incorrecto.",
                )
                audit(
                    clean_user,
                    row["role"],
                    "MFA_RECOVERY",
                    "USER",
                    result="DENIED",
                    details="Código de recuperación MFA incorrecto.",
                    severity="HIGH",
                )
                return

            for widget in qr_holder.winfo_children():
                widget.destroy()

            secret = pyotp.random_base32()
            qr_path = DATA_DIR / f"recovery_{uuid.uuid4().hex}.png"
            uri = pyotp.TOTP(secret).provisioning_uri(
                name=row["username"],
                issuer_name=APP_NAME,
            )
            qrcode.make(uri).save(qr_path)
            image = ctk.CTkImage(
                Image.open(qr_path),
                size=(210, 210),
            )

            state.update(
                {
                    "user_id": row["id"],
                    "secret": secret,
                    "qr_path": qr_path,
                    "qr_image": image,
                    "username": row["username"],
                    "role": row["role"],
                }
            )

            ctk.CTkLabel(
                qr_holder,
                image=image,
                text="",
            ).pack()

            ctk.CTkLabel(
                qr_holder,
                text=(
                    "Escanee este QR con el nuevo teléfono y confirme "
                    "el código que aparezca en Authy."
                ),
                wraplength=540,
                text_color=COLORS["muted"],
            ).pack(pady=(5, 8))

            ctk.CTkEntry(
                qr_holder,
                textvariable=confirm_code,
                placeholder_text="Nuevo código Authy",
                height=42,
                corner_radius=12,
            ).pack(fill=X)

            confirm_button.pack(fill=X, padx=30, pady=(10, 24))

        def finish_recovery():
            if not state["secret"] or not state["user_id"]:
                return

            recovery_ok, recovery_counter, recovery_detail = (
                verify_totp_secret(
                    state["secret"],
                    confirm_code.get(),
                    last_counter=None,
                    valid_window=1,
                )
            )

            if not recovery_ok:
                messagebox.showerror(
                    "Authy",
                    recovery_detail,
                )
                return

            encrypted_secret = encrypt_text(
                state["secret"].strip()
            )

            recovered_secret = decrypt_text(
                encrypted_secret
            ).strip()

            roundtrip_ok, _, roundtrip_detail = verify_totp_secret(
                recovered_secret,
                confirm_code.get(),
                last_counter=None,
                valid_window=1,
            )

            if not roundtrip_ok:
                messagebox.showerror(
                    "Authy",
                    "No fue posible validar el nuevo secreto MFA después de cifrarlo. "
                    + roundtrip_detail,
                )
                return

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET totp_secret_enc=?,mfa_enabled=1,
                        last_totp_counter=NULL,
                        mfa_recovery_token_hash=NULL,
                        mfa_recovery_expires=NULL,
                        mfa_reset_pending=0,
                        failed_attempts=0,
                        locked_until=NULL
                    WHERE id=?
                    """,
                    (
                        encrypted_secret,
                        state["user_id"],
                    ),
                )

            audit(
                state["username"],
                state["role"],
                "MFA_RECOVERY",
                "USER",
                str(state["user_id"]),
                details="MFA Authy registrado nuevamente mediante recuperación administrativa.",
                severity="HIGH",
            )

            if state["qr_path"]:
                Path(state["qr_path"]).unlink(missing_ok=True)

            messagebox.showinfo(
                "MFA recuperado",
                "El nuevo Authy quedó registrado. Ya puede iniciar sesión normalmente.",
            )
            dialog.destroy()

        self.action_button(
            frame,
            "Validar recuperación",
            validate_recovery,
            COLORS["blue"],
        ).pack(fill=X, padx=30, pady=(4, 10))

        confirm_button = self.action_button(
            frame,
            "Confirmar nuevo Authy",
            finish_recovery,
            COLORS["green"],
        )

    def show_dashboard(self):
        self.clear_root()

        sidebar = ctk.CTkFrame(self, width=265, corner_radius=0, fg_color=COLORS["navy"])
        sidebar.pack(side=LEFT, fill=Y)
        sidebar.pack_propagate(False)

        self.content = ctk.CTkScrollableFrame(
            self,
            corner_radius=0,
            fg_color=COLORS["bg"],
            scrollbar_button_color="#C6D4E6",
            scrollbar_button_hover_color="#AFC2D9",
        )
        self.content.pack(side=RIGHT, fill=BOTH, expand=True)

        ctk.CTkLabel(sidebar, image=self.logo_sidebar, text="").pack(pady=(16, 2))
        ctk.CTkLabel(
            sidebar,
            text="CryptoAccess\nHealth Secure",
            font=("Segoe UI", 21, "bold"),
            text_color="white",
            justify="left",
        ).pack(anchor="w", padx=22, pady=(0, 20))

        role = self.session.role
        if role == "AUDITOR":
            items = [
                ("Auditoría y logs", self.page_logs),
                ("Configuración", self.page_settings),
            ]
        else:
            items = [("Inicio", self.page_home)]
            if role in ("ADMIN", "DOCTOR", "RECEPTION"):
                items.append(("Pacientes", self.page_patients))
            if role in ("ADMIN", "DOCTOR"):
                items.append(("Expedientes clínicos", self.page_records))
                items.append(("Documentos protegidos", self.page_secure_documents))
            if role in ("ADMIN", "DOCTOR", "RECEPTION"):
                items.append(("Citas y calendario", self.page_appointments))
            if role in ("ADMIN", "RECEPTION"):
                items.append(("Recordatorios", self.page_reminders))
            if role == "IT":
                items.append(("Estado técnico", self.page_it_status))
            if role == "ADMIN":
                items.append(("Centro criptográfico", self.page_crypto_center))
                items.append(("Respaldo y recuperación", self.page_backup))
            items.extend(
                [
                    ("Centro legal", self.page_legal),
                    ("Configuración", self.page_settings),
                    ("Acerca del producto", self.page_about),
                ]
            )

        for label, command in items:
            ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                height=42,
                corner_radius=12,
                fg_color="transparent",
                hover_color=COLORS["navy_2"],
                text_color="#E8F1FC",
                font=("Segoe UI", 12),
                command=command,
            ).pack(fill=X, padx=14, pady=3)

        ctk.CTkButton(
            sidebar,
            text="Cerrar sesión",
            height=44,
            corner_radius=13,
            fg_color=COLORS["blue"],
            hover_color="#0E63D8",
            command=self.show_login,
        ).pack(side="bottom", fill=X, padx=16, pady=16)

        ctk.CTkLabel(
            sidebar,
            text=f"{self.session.full_name}\n{self.role_label(self.session.role)}",
            text_color="#C8D6EA",
            justify="left",
        ).pack(side="bottom", anchor="w", padx=22, pady=(0, 4))

        if role == "AUDITOR":
            self.page_logs()
        elif role == "IT":
            self.page_it_status()
        else:
            self.page_home()

    @staticmethod
    def role_label(role: str) -> str:
        return {
            "ADMIN": "Administrador",
            "DOCTOR": "Médico",
            "RECEPTION": "Recepción",
            "IT": "Soporte TI",
            "AUDITOR": "Auditor criptográfico",
        }.get(role, role)

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def page_header(self, title: str, subtitle: str = ""):
        ctk.CTkLabel(
            self.content,
            text=title,
            font=("Segoe UI", 28, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=12, pady=(14, 2))
        if subtitle:
            ctk.CTkLabel(
                self.content,
                text=subtitle,
                text_color=COLORS["muted"],
                font=("Segoe UI", 12),
            ).pack(anchor="w", padx=12, pady=(0, 18))

    def action_button(self, master, text, command, color=None):
        return ctk.CTkButton(
            master,
            text=text,
            command=command,
            height=40,
            corner_radius=13,
            fg_color=color or COLORS["blue"],
            hover_color="#0E63D8",
        )

    def page_home(self):
        self.clear_content()
        self.page_header(
            f"¡Bienvenido, {self.session.full_name}!",
            "Aquí tiene un resumen operativo del centro de salud.",
        )

        with db() as conn:
            patients = conn.execute("SELECT COUNT(*) AS n FROM patients").fetchone()["n"]
            appointments = conn.execute(
                "SELECT COUNT(*) AS n FROM appointments WHERE appointment_date=date('now','localtime')"
            ).fetchone()["n"]
            records = conn.execute("SELECT COUNT(*) AS n FROM clinical_records").fetchone()["n"]
            logs = conn.execute("SELECT COUNT(*) AS n FROM audit_logs").fetchone()["n"]

        cards = ctk.CTkFrame(self.content, fg_color="transparent")
        cards.pack(fill=X, padx=12)

        values = [
            ("Citas de hoy", appointments, COLORS["blue"]),
            ("Pacientes registrados", patients, COLORS["green"]),
            ("Expedientes", records, COLORS["purple"]),
            ("Eventos auditados", logs, COLORS["orange"]),
        ]

        for title, value, color in values:
            card = RoundedCard(cards)
            card.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 12), pady=6)
            ctk.CTkFrame(card, width=10, height=56, corner_radius=5, fg_color=color).pack(side=LEFT, padx=(16, 10), pady=20)
            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side=LEFT, fill=BOTH, expand=True, pady=17)
            ctk.CTkLabel(info, text=title, text_color=COLORS["muted"], anchor="w").pack(fill=X)
            ctk.CTkLabel(info, text=str(value), font=("Segoe UI", 23, "bold"), text_color=COLORS["text"], anchor="w").pack(fill=X)

        lower = ctk.CTkFrame(self.content, fg_color="transparent")
        lower.pack(fill=BOTH, expand=True, padx=12, pady=14)

        security = RoundedCard(lower)
        security.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 8))
        ctk.CTkLabel(security, text="Controles de seguridad activos", font=("Segoe UI", 17, "bold"), text_color=COLORS["text"]).pack(anchor="w", padx=22, pady=(22, 12))
        for text in [
            "Cifrado simétrico AES-256-GCM para datos clínicos y documentos.",
            "Contraseñas almacenadas mediante Argon2id.",
            "Usuario y contraseña con MFA Authy configurable desde la cuenta.",
            "Roles separados y mínimo privilegio.",
            "Auditoría sin contenido clínico para soporte TI.",
            "Criptografía híbrida RSA-3072 + AES-256-GCM + SHA-384.",
            "Firmas digitales RSA-PSS y auditoría encadenada.",
            "Centro legal y normativo integrado.",
        ]:
            ctk.CTkLabel(security, text=f"✓  {text}", text_color=COLORS["text"], anchor="w").pack(fill=X, padx=22, pady=5)

        quick = RoundedCard(lower)
        quick.pack(side=RIGHT, fill=BOTH, expand=True, padx=(8, 0))
        ctk.CTkLabel(quick, text="Acciones rápidas", font=("Segoe UI", 17, "bold"), text_color=COLORS["text"]).pack(anchor="w", padx=22, pady=(22, 12))

        if self.session.role in ("ADMIN", "DOCTOR", "RECEPTION"):
            self.action_button(quick, "Registrar paciente", self.patient_form, COLORS["cyan"]).pack(fill=X, padx=22, pady=5)
            self.action_button(quick, "Programar cita", self.appointment_form, COLORS["purple"]).pack(fill=X, padx=22, pady=5)
        if self.session.role in ("ADMIN", "DOCTOR"):
            self.action_button(quick, "Crear nota clínica", self.record_form, COLORS["green"]).pack(fill=X, padx=22, pady=5)
        self.action_button(quick, "Abrir centro legal", self.page_legal, COLORS["orange"]).pack(fill=X, padx=22, pady=5)

    def tree_card(self, columns, headings, widths, height=18):
        card = RoundedCard(self.content)
        card.pack(fill=BOTH, expand=True, padx=12, pady=8)
        tree = ttk.Treeview(card, columns=columns, show="headings", style="Health.Treeview", height=height)
        for column, title, width in zip(columns, headings, widths):
            tree.heading(column, text=title)
            tree.column(column, width=width, anchor="w")
        tree.pack(fill=BOTH, expand=True, padx=18, pady=18)
        return tree

    def page_patients(self):
        self.clear_content()
        self.page_header("Pacientes", "Datos administrativos protegidos. Recepción no puede consultar información clínica.")
        toolbar = ctk.CTkFrame(self.content, fg_color="transparent")
        toolbar.pack(fill=X, padx=12)
        self.action_button(toolbar, "Nuevo paciente", self.patient_form).pack(side=LEFT)

        tree = self.tree_card(
            ("code", "name", "birth", "phone", "email"),
            ("Código", "Nombre completo", "Nacimiento", "Teléfono", "Correo"),
            (120, 290, 130, 150, 260),
        )
        with db() as conn:
            rows = conn.execute("SELECT * FROM patients ORDER BY id DESC").fetchall()
        for row in rows:
            tree.insert(
                "",
                END,
                iid=str(row["id"]),
                values=(
                    row["internal_code"],
                    decrypt_text(row["full_name_enc"]),
                    decrypt_text(row["birth_date_enc"]),
                    decrypt_text(row["phone_enc"]),
                    decrypt_text(row["email_enc"]),
                ),
            )
        tree.bind("<Double-1>", lambda _e: self.patient_form(int(tree.selection()[0])) if tree.selection() else None)

    def patient_form(self, patient_id=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Paciente")
        dialog.geometry("690x780")
        dialog.grab_set()

        data = None
        if patient_id:
            with db() as conn:
                data = conn.execute("SELECT * FROM patients WHERE id=?", (patient_id,)).fetchone()

        frame = ctk.CTkScrollableFrame(dialog, fg_color=COLORS["bg"])
        frame.pack(fill=BOTH, expand=True)

        variables = {
            "code": ctk.StringVar(value=data["internal_code"] if data else f"PAC-{datetime.now().strftime('%Y%m%d%H%M%S')}"),
            "name": ctk.StringVar(value=decrypt_text(data["full_name_enc"]) if data else ""),
            "birth": ctk.StringVar(value=decrypt_text(data["birth_date_enc"]) if data else ""),
            "id_number": ctk.StringVar(value=decrypt_text(data["id_number_enc"]) if data else ""),
            "phone": ctk.StringVar(value=decrypt_text(data["phone_enc"]) if data else ""),
            "email": ctk.StringVar(value=decrypt_text(data["email_enc"]) if data else ""),
            "address": ctk.StringVar(value=decrypt_text(data["address_enc"]) if data else ""),
            "emergency": ctk.StringVar(value=decrypt_text(data["emergency_contact_enc"]) if data else ""),
            "preferred": ctk.StringVar(value=data["preferred_contact"] if data else "Teléfono"),
        }

        ctk.CTkLabel(frame, text="Información del paciente", font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]).pack(anchor="w", padx=25, pady=(20, 18))
        for key, label in [
            ("code", "Código interno"),
            ("name", "Nombre completo"),
            ("birth", "Fecha de nacimiento (AAAA-MM-DD)"),
            ("id_number", "Identificación"),
            ("phone", "Teléfono"),
            ("email", "Correo"),
            ("address", "Dirección"),
            ("emergency", "Contacto de emergencia"),
        ]:
            ctk.CTkLabel(frame, text=label, text_color=COLORS["text"]).pack(anchor="w", padx=25)
            ctk.CTkEntry(frame, textvariable=variables[key], height=41, corner_radius=12).pack(fill=X, padx=25, pady=(5, 12))

        ctk.CTkLabel(frame, text="Medio preferido de contacto", text_color=COLORS["text"]).pack(anchor="w", padx=25)
        ctk.CTkComboBox(frame, variable=variables["preferred"], values=["Teléfono", "Correo", "WhatsApp"], height=41, corner_radius=12).pack(fill=X, padx=25, pady=(5, 18))

        def save():
            if not variables["name"].get().strip():
                messagebox.showwarning("Paciente", "Ingrese el nombre completo.")
                return
            with db() as conn:
                if patient_id:
                    conn.execute(
                        """
                        UPDATE patients SET internal_code=?, full_name_enc=?, birth_date_enc=?,
                        id_number_enc=?, phone_enc=?, email_enc=?, address_enc=?,
                        emergency_contact_enc=?, preferred_contact=?, updated_at=? WHERE id=?
                        """,
                        (
                            variables["code"].get(),
                            encrypt_text(variables["name"].get()),
                            encrypt_text(variables["birth"].get()),
                            encrypt_text(variables["id_number"].get()),
                            encrypt_text(variables["phone"].get()),
                            encrypt_text(variables["email"].get()),
                            encrypt_text(variables["address"].get()),
                            encrypt_text(variables["emergency"].get()),
                            variables["preferred"].get(),
                            now_iso(),
                            patient_id,
                        ),
                    )
                    entity_id = str(patient_id)
                else:
                    cursor = conn.execute(
                        """
                        INSERT INTO patients
                        (internal_code, full_name_enc, birth_date_enc, id_number_enc,
                         phone_enc, email_enc, address_enc, emergency_contact_enc,
                         preferred_contact, created_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            variables["code"].get(),
                            encrypt_text(variables["name"].get()),
                            encrypt_text(variables["birth"].get()),
                            encrypt_text(variables["id_number"].get()),
                            encrypt_text(variables["phone"].get()),
                            encrypt_text(variables["email"].get()),
                            encrypt_text(variables["address"].get()),
                            encrypt_text(variables["emergency"].get()),
                            variables["preferred"].get(),
                            self.session.username,
                            now_iso(),
                            now_iso(),
                        ),
                    )
                    entity_id = str(cursor.lastrowid)
            audit(self.session.username, self.session.role, "SAVE", "PATIENT", entity_id)
            dialog.destroy()
            self.page_patients()

        self.action_button(frame, "Guardar paciente", save).pack(fill=X, padx=25, pady=(0, 25))


    def page_records(self):
        self.clear_content()
        self.page_header(
            "Expedientes clínicos",
            "Expedientes cifrados con AES-256-GCM, huella SHA-384 y firma digital RSA-3072.",
        )

        toolbar = ctk.CTkFrame(self.content, fg_color="transparent")
        toolbar.pack(fill=X, padx=12)
        self.action_button(
            toolbar,
            "Nueva nota clínica",
            self.record_form,
            COLORS["green"],
        ).pack(side=LEFT)

        verify_button = self.action_button(
            toolbar,
            "Verificar expediente",
            lambda: verify_selected(),
            COLORS["cyan"],
        )
        verify_button.pack(side=LEFT, padx=8)

        tree = self.tree_card(
            ("patient", "doctor", "date", "status", "version", "hash", "signature"),
            ("Paciente", "Médico", "Fecha", "Estado", "Versión", "SHA-384", "Firma"),
            (250, 140, 165, 90, 75, 225, 105),
        )

        with db() as conn:
            rows = conn.execute(
                """
                SELECT cr.*, p.full_name_enc FROM clinical_records cr
                JOIN patients p ON p.id=cr.patient_id
                ORDER BY cr.id DESC
                """
            ).fetchall()

        for row in rows:
            hash_preview = (
                row["content_hash"][:24] + "..."
                if row["content_hash"]
                else "Sin hash"
            )
            signature_state = (
                "RSA válida"
                if row["status"] == "SIGNED" and row["digital_signature"]
                else "Borrador"
            )
            tree.insert(
                "",
                END,
                iid=str(row["id"]),
                values=(
                    decrypt_text(row["full_name_enc"]),
                    row["doctor_username"],
                    row["visit_date"],
                    row["status"],
                    row["version"],
                    hash_preview,
                    signature_state,
                ),
            )

        def verify_selected():
            if not tree.selection():
                messagebox.showwarning("Verificación", "Seleccione un expediente.")
                return
            record_id = int(tree.selection()[0])
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM clinical_records WHERE id=?",
                    (record_id,),
                ).fetchone()
            valid, detail = verify_clinical_record_row(row)
            audit(
                self.session.username,
                self.session.role,
                "VERIFY",
                "CLINICAL_RECORD",
                str(record_id),
                result="OK" if valid else "FAILED",
                details=detail,
                severity="INFO" if valid else "HIGH",
                metadata={
                    "content_hash": row["content_hash"],
                    "signer_key_id": row["signer_key_id"],
                    "version": row["version"],
                },
            )
            if valid:
                messagebox.showinfo(
                    "Expediente íntegro",
                    f"{detail}\n\nSHA-384:\n{row['content_hash']}\n\n"
                    f"Clave firmante:\n{row['signer_key_id'] or 'No aplica'}",
                )
            else:
                messagebox.showerror("Verificación fallida", detail)

        tree.bind(
            "<Double-1>",
            lambda _e: self.record_form(int(tree.selection()[0]))
            if tree.selection()
            else None,
        )

    def record_form(self, record_id=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Expediente clínico criptográfico")
        dialog.geometry("930x900")
        dialog.grab_set()

        with db() as conn:
            patients = conn.execute(
                "SELECT id, full_name_enc FROM patients ORDER BY id"
            ).fetchall()
        patient_map = {
            f"{p['id']} - {decrypt_text(p['full_name_enc'])}": p["id"]
            for p in patients
        }

        data = None
        if record_id:
            with db() as conn:
                data = conn.execute(
                    "SELECT * FROM clinical_records WHERE id=?",
                    (record_id,),
                ).fetchone()

        if data and data["status"] == "SIGNED":
            read_only = True
        else:
            read_only = False

        frame = ctk.CTkScrollableFrame(dialog, fg_color=COLORS["bg"])
        frame.pack(fill=BOTH, expand=True)

        ctk.CTkLabel(
            frame,
            text="Expediente clínico criptográfico",
            font=("Segoe UI", 24, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=25, pady=(20, 4))

        ctk.CTkLabel(
            frame,
            text=(
                "AES-256-GCM protege el contenido. SHA-384 identifica cada versión. "
                "Al firmar se aplica RSA-3072-PSS y la versión queda bloqueada."
            ),
            wraplength=820,
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=25, pady=(0, 18))

        patient_var = ctk.StringVar()
        if data:
            for label, pid in patient_map.items():
                if pid == data["patient_id"]:
                    patient_var.set(label)
                    break

        ctk.CTkLabel(frame, text="Paciente", text_color=COLORS["text"]).pack(
            anchor="w", padx=25
        )
        patient_combo = ctk.CTkComboBox(
            frame,
            variable=patient_var,
            values=list(patient_map.keys()),
            height=41,
            corner_radius=12,
            state="disabled" if read_only else "normal",
        )
        patient_combo.pack(fill=X, padx=25, pady=(5, 12))

        text_fields = {}
        field_mapping = [
            ("reason_enc", "reason", "Motivo de consulta"),
            ("diagnosis_enc", "diagnosis", "Diagnóstico"),
            ("treatment_enc", "treatment", "Tratamiento"),
            ("medications_enc", "medications", "Medicamentos"),
            ("allergies_enc", "allergies", "Alergias"),
            ("notes_enc", "notes", "Notas clínicas"),
        ]

        for db_key, payload_key, label in field_mapping:
            ctk.CTkLabel(frame, text=label, text_color=COLORS["text"]).pack(
                anchor="w", padx=25
            )
            textbox = ctk.CTkTextbox(frame, height=92, corner_radius=12)
            textbox.pack(fill=X, padx=25, pady=(5, 12))
            if data:
                textbox.insert("1.0", decrypt_text(data[db_key]))
            if read_only:
                textbox.configure(state="disabled")
            text_fields[payload_key] = textbox

        crypto_card = RoundedCard(frame)
        crypto_card.pack(fill=X, padx=25, pady=(4, 16))

        ctk.CTkLabel(
            crypto_card,
            text="Estado criptográfico",
            font=("Segoe UI", 17, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=18, pady=(16, 6))

        hash_text = data["content_hash"] if data and data["content_hash"] else "Se calculará al guardar."
        ctk.CTkLabel(
            crypto_card,
            text=f"SHA-384: {hash_text}",
            wraplength=810,
            justify="left",
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=18, pady=3)

        ctk.CTkLabel(
            crypto_card,
            text=f"Firma: {'RSA-3072-PSS verificada al abrir' if data and data['digital_signature'] else 'No firmada'}",
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=18, pady=3)

        ctk.CTkLabel(
            crypto_card,
            text=f"Key ID: {data['signer_key_id'] if data and data['signer_key_id'] else 'Se asignará al firmar'}",
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=18, pady=(3, 16))

        if read_only:
            valid, detail = verify_clinical_record_row(data)
            color = COLORS["green"] if valid else COLORS["red"]
            ctk.CTkLabel(
                frame,
                text=("✓ " if valid else "⚠ ") + detail,
                text_color=color,
                font=("Segoe UI", 14, "bold"),
                wraplength=820,
            ).pack(anchor="w", padx=25, pady=(0, 18))

        def collect_fields():
            return {
                key: widget.get("1.0", END).strip()
                for key, widget in text_fields.items()
            }

        def persist(sign_record: bool):
            if read_only:
                messagebox.showwarning(
                    "Expediente firmado",
                    "Esta versión está firmada y no puede modificarse. Cree una nueva versión.",
                )
                return

            if patient_var.get() not in patient_map:
                messagebox.showwarning("Registro", "Seleccione un paciente.")
                return

            fields = collect_fields()
            patient_id = patient_map[patient_var.get()]
            visit_date = data["visit_date"] if data else now_iso()
            version = int(data["version"]) + 1 if data else 1
            doctor_username = data["doctor_username"] if data else self.session.username
            payload = clinical_record_payload(
                patient_id,
                doctor_username,
                visit_date,
                version,
                fields,
            )
            content_hash = sha384_hex(payload)
            signature_b64 = None
            signer_key_id = None
            signed_at = None
            status = "DRAFT"

            if sign_record:
                signature_b64, signer_key_id = rsa_sign_sha384(payload)
                signed_at = now_iso()
                status = "SIGNED"

            encrypted = {
                key: encrypt_text(value)
                for key, value in fields.items()
            }

            with db() as conn:
                if record_id:
                    conn.execute(
                        """
                        UPDATE clinical_records SET reason_enc=?, diagnosis_enc=?,
                        treatment_enc=?, medications_enc=?, allergies_enc=?, notes_enc=?,
                        status=?, version=?, updated_at=?, content_hash=?,
                        digital_signature=?, signer_key_id=?, signed_at=? WHERE id=?
                        """,
                        (
                            encrypted["reason"],
                            encrypted["diagnosis"],
                            encrypted["treatment"],
                            encrypted["medications"],
                            encrypted["allergies"],
                            encrypted["notes"],
                            status,
                            version,
                            now_iso(),
                            content_hash,
                            signature_b64,
                            signer_key_id,
                            signed_at,
                            record_id,
                        ),
                    )
                    entity_id = str(record_id)
                else:
                    cursor = conn.execute(
                        """
                        INSERT INTO clinical_records
                        (patient_id, doctor_username, visit_date, reason_enc,
                         diagnosis_enc, treatment_enc, medications_enc, allergies_enc,
                         notes_enc, status, version, created_at, updated_at, content_hash,
                         digital_signature, signer_key_id, signed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            patient_id,
                            doctor_username,
                            visit_date,
                            encrypted["reason"],
                            encrypted["diagnosis"],
                            encrypted["treatment"],
                            encrypted["medications"],
                            encrypted["allergies"],
                            encrypted["notes"],
                            status,
                            version,
                            now_iso(),
                            now_iso(),
                            content_hash,
                            signature_b64,
                            signer_key_id,
                            signed_at,
                        ),
                    )
                    entity_id = str(cursor.lastrowid)

            audit(
                self.session.username,
                self.session.role,
                "SIGN" if sign_record else "SAVE",
                "CLINICAL_RECORD",
                entity_id,
                details=(
                    "Expediente firmado digitalmente con RSA-3072-PSS."
                    if sign_record
                    else "Borrador clínico guardado con hash SHA-384."
                ),
                metadata={
                    "sha384": content_hash,
                    "key_id": signer_key_id,
                    "version": version,
                    "algorithms": [
                        "AES-256-GCM",
                        "SHA-384",
                        "RSA-3072-PSS" if sign_record else None,
                    ],
                },
            )
            dialog.destroy()
            self.page_records()

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill=X, padx=25, pady=(0, 25))

        if not read_only:
            self.action_button(
                buttons,
                "Guardar borrador",
                lambda: persist(False),
                COLORS["blue"],
            ).pack(side=LEFT, fill=X, expand=True, padx=(0, 6))

            self.action_button(
                buttons,
                "Firmar y bloquear versión",
                lambda: persist(True),
                COLORS["green"],
            ).pack(side=RIGHT, fill=X, expand=True, padx=(6, 0))


    def page_appointments(self):
        self.clear_content()
        self.page_header(
            "Citas y calendario",
            "Agenda clínica interactiva con vistas Día y Mes.",
        )

        self.update_idletasks()

        selected_date = ctk.StringVar(
            value=datetime.now().strftime(
                "%Y-%m-%d"
            )
        )
        view_mode = ctk.StringVar(
            value="Día"
        )

        initial_date = datetime.now()
        month_cursor = [
            initial_date.replace(
                day=1,
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )
        ]

        available_height = max(
            700,
            self.winfo_height() - 150,
        )

        shell = ctk.CTkFrame(
            self.content,
            fg_color="transparent",
            height=available_height,
        )
        shell.pack(
            fill=X,
            padx=12,
            pady=(0, 12),
        )
        shell.pack_propagate(False)

        # -------------------------------------------------------------
        # Barra superior compacta
        # -------------------------------------------------------------
        toolbar = RoundedCard(
            shell,
            height=68,
        )
        toolbar.pack(
            fill=X,
            pady=(0, 9),
        )
        toolbar.pack_propagate(False)

        left_controls = ctk.CTkFrame(
            toolbar,
            fg_color="transparent",
        )
        left_controls.pack(
            side=LEFT,
            fill=Y,
            padx=16,
        )

        self.action_button(
            left_controls,
            "Nueva cita",
            lambda: self.appointment_form(
                prefill_date=selected_date.get()
            ),
            COLORS["purple"],
        ).pack(
            side=LEFT,
            pady=14,
        )

        date_entry = ctk.CTkEntry(
            left_controls,
            textvariable=selected_date,
            width=145,
            height=40,
            corner_radius=12,
        )
        date_entry.pack(
            side=LEFT,
            padx=(10, 7),
            pady=14,
        )

        mode_switch = ctk.CTkSegmentedButton(
            left_controls,
            values=[
                "Día",
                "Mes",
            ],
            variable=view_mode,
            height=38,
            corner_radius=12,
            selected_color=COLORS["blue"],
            selected_hover_color="#0E63D8",
            unselected_color="#EAF2FE",
            unselected_hover_color="#D7E8FF",
            text_color=COLORS["text"],
        )
        mode_switch.pack(
            side=LEFT,
            padx=(2, 0),
            pady=15,
        )

        navigation = ctk.CTkFrame(
            toolbar,
            fg_color="transparent",
        )
        navigation.pack(
            side=RIGHT,
            fill=Y,
            padx=16,
        )

        calendar_container = ctk.CTkFrame(
            shell,
            fg_color="transparent",
        )
        calendar_container.pack(
            fill=BOTH,
            expand=True,
        )

        def clear_calendar_container():
            for widget in (
                calendar_container.winfo_children()
            ):
                widget.destroy()

        def parse_selected():
            try:
                return datetime.strptime(
                    selected_date.get(),
                    "%Y-%m-%d",
                )
            except ValueError:
                current = datetime.now()
                selected_date.set(
                    current.strftime("%Y-%m-%d")
                )
                return current

        def change_period(offset):
            if view_mode.get() == "Mes":
                cursor = month_cursor[0]
                month_index = (
                    cursor.year * 12
                    + cursor.month
                    - 1
                    + offset
                )
                year = month_index // 12
                month = month_index % 12 + 1
                month_cursor[0] = datetime(
                    year,
                    month,
                    1,
                )

                selected = parse_selected()
                day = min(
                    selected.day,
                    pycalendar.monthrange(
                        year,
                        month,
                    )[1],
                )
                selected_date.set(
                    datetime(
                        year,
                        month,
                        day,
                    ).strftime("%Y-%m-%d")
                )
            else:
                selected = parse_selected()
                selected_date.set(
                    (
                        selected
                        + timedelta(days=offset)
                    ).strftime("%Y-%m-%d")
                )

            render_calendar()

        def go_today():
            today = datetime.now()
            selected_date.set(
                today.strftime("%Y-%m-%d")
            )
            month_cursor[0] = today.replace(
                day=1,
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )
            render_calendar()

        ctk.CTkButton(
            navigation,
            text="‹",
            width=40,
            height=38,
            corner_radius=12,
            fg_color="#EAF2FE",
            hover_color="#D7E8FF",
            text_color=COLORS["blue"],
            command=lambda: change_period(-1),
        ).pack(
            side=LEFT,
            padx=3,
            pady=15,
        )

        ctk.CTkButton(
            navigation,
            text="Hoy",
            width=76,
            height=38,
            corner_radius=12,
            fg_color="#EAF2FE",
            hover_color="#D7E8FF",
            text_color=COLORS["blue"],
            command=go_today,
        ).pack(
            side=LEFT,
            padx=3,
            pady=15,
        )

        ctk.CTkButton(
            navigation,
            text="›",
            width=40,
            height=38,
            corner_radius=12,
            fg_color="#EAF2FE",
            hover_color="#D7E8FF",
            text_color=COLORS["blue"],
            command=lambda: change_period(1),
        ).pack(
            side=LEFT,
            padx=3,
            pady=15,
        )

        # -------------------------------------------------------------
        # Vista Día
        # -------------------------------------------------------------
        def render_day():
            date_obj = parse_selected()
            month_cursor[0] = date_obj.replace(
                day=1,
                hour=0,
                minute=0,
                second=0,
                microsecond=0,
            )

            with db() as conn:
                rows = conn.execute(
                    """
                    SELECT a.*, p.full_name_enc
                    FROM appointments a
                    JOIN patients p
                        ON p.id=a.patient_id
                    WHERE a.appointment_date=?
                    ORDER BY a.start_time
                    """,
                    (
                        selected_date.get(),
                    ),
                ).fetchall()

            active_rows = [
                row
                for row in rows
                if row["status"] != "CANCELLED"
            ]
            confirmed = sum(
                1
                for row in active_rows
                if row["status"] == "CONFIRMED"
            )
            pending = sum(
                1
                for row in active_rows
                if row["status"] == "PENDING"
            )

            day_header = RoundedCard(
                calendar_container,
                height=88,
            )
            day_header.pack(
                fill=X,
                pady=(0, 9),
            )
            day_header.pack_propagate(False)

            heading = ctk.CTkFrame(
                day_header,
                fg_color="transparent",
            )
            heading.pack(
                side=LEFT,
                fill=BOTH,
                expand=True,
                padx=20,
                pady=14,
            )

            ctk.CTkLabel(
                heading,
                text=date_obj.strftime(
                    "%A, %d de %B de %Y"
                ).capitalize(),
                font=("Segoe UI", 20, "bold"),
                text_color=COLORS["text"],
                anchor="w",
            ).pack(
                fill=X,
                anchor="w",
            )

            ctk.CTkLabel(
                heading,
                text=(
                    "Seleccione un horario libre para crear una cita "
                    "o abra una cita existente para modificarla."
                ),
                text_color=COLORS["muted"],
                anchor="w",
            ).pack(
                fill=X,
                anchor="w",
                pady=(2, 0),
            )

            stats = ctk.CTkFrame(
                day_header,
                fg_color="transparent",
            )
            stats.pack(
                side=RIGHT,
                fill=Y,
                padx=(0, 18),
            )

            for title, value, color in [
                (
                    "Total",
                    len(active_rows),
                    COLORS["blue"],
                ),
                (
                    "Confirmadas",
                    confirmed,
                    COLORS["green"],
                ),
                (
                    "Pendientes",
                    pending,
                    COLORS["orange"],
                ),
            ]:
                box = ctk.CTkFrame(
                    stats,
                    fg_color="#F7FAFE",
                    corner_radius=11,
                    width=105,
                    height=58,
                )
                box.pack(
                    side=LEFT,
                    padx=4,
                    pady=15,
                )
                box.pack_propagate(False)

                ctk.CTkLabel(
                    box,
                    text=str(value),
                    font=("Segoe UI", 17, "bold"),
                    text_color=color,
                ).pack(
                    pady=(7, 0),
                )

                ctk.CTkLabel(
                    box,
                    text=title,
                    font=("Segoe UI", 10),
                    text_color=COLORS["muted"],
                ).pack()

            agenda_card = RoundedCard(
                calendar_container,
            )
            agenda_card.pack(
                fill=BOTH,
                expand=True,
            )

            agenda = ctk.CTkScrollableFrame(
                agenda_card,
                fg_color="#FBFDFF",
                corner_radius=14,
                scrollbar_button_color="#CAD8EA",
                scrollbar_button_hover_color="#AFC2D9",
            )
            agenda.pack(
                fill=BOTH,
                expand=True,
                padx=12,
                pady=12,
            )

            appointments_by_time = {}
            for row in rows:
                appointments_by_time.setdefault(
                    row["start_time"],
                    [],
                ).append(row)

            for hour in range(7, 20):
                for minute in (
                    0,
                    30,
                ):
                    slot_time = (
                        f"{hour:02d}:{minute:02d}"
                    )

                    slot = ctk.CTkFrame(
                        agenda,
                        fg_color="transparent",
                        height=64,
                    )
                    slot.pack(
                        fill=X,
                        padx=2,
                        pady=2,
                    )
                    slot.pack_propagate(False)

                    time_label = ctk.CTkLabel(
                        slot,
                        text=slot_time,
                        width=68,
                        anchor="n",
                        font=("Segoe UI", 11, "bold"),
                        text_color=COLORS["muted"],
                    )
                    time_label.pack(
                        side=LEFT,
                        fill=Y,
                        padx=(2, 8),
                        pady=9,
                    )

                    content_slot = ctk.CTkFrame(
                        slot,
                        fg_color="#F5F8FC",
                        corner_radius=10,
                        border_width=1,
                        border_color=COLORS["line"],
                    )
                    content_slot.pack(
                        side=LEFT,
                        fill=BOTH,
                        expand=True,
                    )

                    entries = (
                        appointments_by_time.get(
                            slot_time,
                            [],
                        )
                    )

                    if entries:
                        for row in entries:
                            color = {
                                "CONFIRMED": COLORS["green"],
                                "PENDING": COLORS["orange"],
                                "CANCELLED": COLORS["red"],
                                "COMPLETED": COLORS["blue"],
                                "NO_SHOW": COLORS["purple"],
                            }.get(
                                row["status"],
                                COLORS["blue"],
                            )

                            appointment = ctk.CTkFrame(
                                content_slot,
                                fg_color="white",
                                corner_radius=9,
                                border_width=1,
                                border_color=color,
                            )
                            appointment.pack(
                                side=LEFT,
                                fill=BOTH,
                                expand=True,
                                padx=5,
                                pady=5,
                            )

                            ctk.CTkFrame(
                                appointment,
                                width=5,
                                fg_color=color,
                                corner_radius=3,
                            ).pack(
                                side=LEFT,
                                fill=Y,
                                padx=(5, 8),
                                pady=6,
                            )

                            info = ctk.CTkFrame(
                                appointment,
                                fg_color="transparent",
                            )
                            info.pack(
                                side=LEFT,
                                fill=BOTH,
                                expand=True,
                                pady=6,
                            )

                            ctk.CTkLabel(
                                info,
                                text=decrypt_text(
                                    row["full_name_enc"]
                                ),
                                font=("Segoe UI", 11, "bold"),
                                text_color=COLORS["text"],
                                anchor="w",
                            ).pack(
                                fill=X,
                            )

                            ctk.CTkLabel(
                                info,
                                text=(
                                    f"{row['professional']}  ·  "
                                    f"{row['specialty']}  ·  "
                                    f"{row['room'] or 'Sin consultorio'}  ·  "
                                    f"{row['duration_min']} min  ·  "
                                    f"{row['status']}"
                                ),
                                font=("Segoe UI", 10),
                                text_color=COLORS["muted"],
                                anchor="w",
                            ).pack(
                                fill=X,
                            )

                            ctk.CTkButton(
                                appointment,
                                text="Editar",
                                width=70,
                                height=31,
                                corner_radius=9,
                                fg_color="#EAF2FE",
                                hover_color="#D7E8FF",
                                text_color=COLORS["blue"],
                                command=lambda appointment_id=row["id"]: (
                                    self.appointment_form(
                                        appointment_id
                                    )
                                ),
                            ).pack(
                                side=RIGHT,
                                padx=8,
                                pady=11,
                            )
                    else:
                        ctk.CTkButton(
                            content_slot,
                            text="Disponible    + Agendar",
                            height=48,
                            corner_radius=9,
                            fg_color="transparent",
                            hover_color="#EAF2FE",
                            text_color=COLORS["blue"],
                            anchor="w",
                            command=lambda slot=slot_time: (
                                self.appointment_form(
                                    prefill_date=selected_date.get(),
                                    prefill_time=slot,
                                )
                            ),
                        ).pack(
                            fill=BOTH,
                            expand=True,
                            padx=5,
                            pady=5,
                        )

        # -------------------------------------------------------------
        # Vista Mes personalizada
        # -------------------------------------------------------------
        def render_month():
            cursor = month_cursor[0]

            with db() as conn:
                month_rows = conn.execute(
                    """
                    SELECT a.*, p.full_name_enc
                    FROM appointments a
                    JOIN patients p
                        ON p.id=a.patient_id
                    WHERE substr(a.appointment_date, 1, 7)=?
                    ORDER BY
                        a.appointment_date,
                        a.start_time
                    """,
                    (
                        cursor.strftime("%Y-%m"),
                    ),
                ).fetchall()

            by_day = {}
            for row in month_rows:
                by_day.setdefault(
                    row["appointment_date"],
                    [],
                ).append(row)

            month_card = RoundedCard(
                calendar_container,
            )
            month_card.pack(
                fill=BOTH,
                expand=True,
            )

            layout = ctk.CTkFrame(
                month_card,
                fg_color="transparent",
            )
            layout.pack(
                fill=BOTH,
                expand=True,
                padx=14,
                pady=14,
            )

            grid_panel = ctk.CTkFrame(
                layout,
                fg_color="transparent",
            )
            grid_panel.pack(
                side=LEFT,
                fill=BOTH,
                expand=True,
                padx=(0, 10),
            )

            summary_panel = ctk.CTkFrame(
                layout,
                width=350,
                fg_color="#F8FAFD",
                corner_radius=14,
                border_width=1,
                border_color=COLORS["line"],
            )
            summary_panel.pack(
                side=RIGHT,
                fill=Y,
            )
            summary_panel.pack_propagate(False)

            month_heading = ctk.CTkFrame(
                grid_panel,
                fg_color="transparent",
                height=45,
            )
            month_heading.pack(
                fill=X,
                pady=(0, 6),
            )
            month_heading.pack_propagate(False)

            ctk.CTkLabel(
                month_heading,
                text=cursor.strftime(
                    "%B %Y"
                ).capitalize(),
                font=("Segoe UI", 20, "bold"),
                text_color=COLORS["text"],
            ).pack(
                side=LEFT,
                padx=4,
                pady=8,
            )

            total_month = sum(
                1
                for row in month_rows
                if row["status"] != "CANCELLED"
            )

            ctk.CTkLabel(
                month_heading,
                text=f"{total_month} cita(s) activas en el mes",
                text_color=COLORS["muted"],
            ).pack(
                side=RIGHT,
                padx=4,
                pady=10,
            )

            weekdays = ctk.CTkFrame(
                grid_panel,
                fg_color="transparent",
                height=34,
            )
            weekdays.pack(
                fill=X,
                pady=(0, 4),
            )
            weekdays.pack_propagate(False)

            for index, day_name in enumerate(
                [
                    "Lun",
                    "Mar",
                    "Mié",
                    "Jue",
                    "Vie",
                    "Sáb",
                    "Dom",
                ]
            ):
                weekdays.grid_columnconfigure(
                    index,
                    weight=1,
                    uniform="weekday",
                )

                ctk.CTkLabel(
                    weekdays,
                    text=day_name,
                    font=("Segoe UI", 11, "bold"),
                    text_color=COLORS["muted"],
                ).grid(
                    row=0,
                    column=index,
                    sticky="nsew",
                    padx=2,
                )

            calendar_grid = ctk.CTkFrame(
                grid_panel,
                fg_color="transparent",
            )
            calendar_grid.pack(
                fill=BOTH,
                expand=True,
            )

            for column in range(7):
                calendar_grid.grid_columnconfigure(
                    column,
                    weight=1,
                    uniform="monthcol",
                )

            for row_index in range(6):
                calendar_grid.grid_rowconfigure(
                    row_index,
                    weight=1,
                    uniform="monthrow",
                )

            selected_obj = parse_selected()
            today = datetime.now()

            def select_day(day_number):
                selected = datetime(
                    cursor.year,
                    cursor.month,
                    day_number,
                )
                selected_date.set(
                    selected.strftime("%Y-%m-%d")
                )
                render_calendar()

            month_matrix = pycalendar.monthcalendar(
                cursor.year,
                cursor.month,
            )

            while len(month_matrix) < 6:
                month_matrix.append(
                    [0] * 7
                )

            for week_index, week in enumerate(
                month_matrix[:6]
            ):
                for day_index, day_number in enumerate(
                    week
                ):
                    if day_number == 0:
                        empty = ctk.CTkFrame(
                            calendar_grid,
                            fg_color="#F7F9FC",
                            corner_radius=10,
                            border_width=1,
                            border_color="#EEF2F7",
                        )
                        empty.grid(
                            row=week_index,
                            column=day_index,
                            sticky="nsew",
                            padx=2,
                            pady=2,
                        )
                        continue

                    cell_date = datetime(
                        cursor.year,
                        cursor.month,
                        day_number,
                    )
                    date_key = cell_date.strftime(
                        "%Y-%m-%d"
                    )
                    entries = by_day.get(
                        date_key,
                        [],
                    )
                    active_entries = [
                        row
                        for row in entries
                        if row["status"] != "CANCELLED"
                    ]

                    is_selected = (
                        cell_date.date()
                        == selected_obj.date()
                    )
                    is_today = (
                        cell_date.date()
                        == today.date()
                    )

                    preview_lines = [
                        str(day_number)
                    ]

                    if active_entries:
                        first = active_entries[0]
                        preview_lines.append(
                            f"{first['start_time']}  "
                            f"{decrypt_text(first['full_name_enc']).split()[0]}"
                        )

                        if len(active_entries) > 1:
                            preview_lines.append(
                                f"+{len(active_entries) - 1} más"
                            )
                    else:
                        preview_lines.append(
                            "Disponible"
                        )

                    background = (
                        COLORS["blue"]
                        if is_selected
                        else (
                            "#EAF7F1"
                            if is_today
                            else "white"
                        )
                    )
                    foreground = (
                        "white"
                        if is_selected
                        else COLORS["text"]
                    )
                    hover = (
                        "#0E63D8"
                        if is_selected
                        else "#EAF2FE"
                    )

                    button = ctk.CTkButton(
                        calendar_grid,
                        text="\n".join(
                            preview_lines
                        ),
                        corner_radius=10,
                        fg_color=background,
                        hover_color=hover,
                        text_color=foreground,
                        border_width=1,
                        border_color=(
                            COLORS["blue"]
                            if is_selected
                            else COLORS["line"]
                        ),
                        anchor="nw",
                        font=("Segoe UI", 10),
                        command=lambda day=day_number: (
                            select_day(day)
                        ),
                    )
                    button.grid(
                        row=week_index,
                        column=day_index,
                        sticky="nsew",
                        padx=2,
                        pady=2,
                    )

            # Resumen lateral del día seleccionado
            selected_key = selected_date.get()
            selected_entries = by_day.get(
                selected_key,
                [],
            )

            selected_date_obj = parse_selected()

            ctk.CTkLabel(
                summary_panel,
                text="Detalle del día",
                font=("Segoe UI", 18, "bold"),
                text_color=COLORS["text"],
            ).pack(
                anchor="w",
                padx=18,
                pady=(18, 2),
            )

            ctk.CTkLabel(
                summary_panel,
                text=selected_date_obj.strftime(
                    "%A, %d de %B"
                ).capitalize(),
                text_color=COLORS["muted"],
                wraplength=300,
                justify="left",
            ).pack(
                anchor="w",
                padx=18,
                pady=(0, 10),
            )

            count_box = ctk.CTkFrame(
                summary_panel,
                fg_color="white",
                corner_radius=11,
                border_width=1,
                border_color=COLORS["line"],
            )
            count_box.pack(
                fill=X,
                padx=14,
                pady=(0, 8),
            )

            ctk.CTkLabel(
                count_box,
                text=str(
                    len(
                        [
                            row
                            for row in selected_entries
                            if row["status"]
                            != "CANCELLED"
                        ]
                    )
                ),
                font=("Segoe UI", 24, "bold"),
                text_color=COLORS["blue"],
            ).pack(
                pady=(10, 0),
            )

            ctk.CTkLabel(
                count_box,
                text="cita(s) activas",
                text_color=COLORS["muted"],
            ).pack(
                pady=(0, 10),
            )

            summary_list = ctk.CTkScrollableFrame(
                summary_panel,
                fg_color="transparent",
                scrollbar_button_color="#CAD8EA",
            )
            summary_list.pack(
                fill=BOTH,
                expand=True,
                padx=8,
                pady=(0, 8),
            )

            if not selected_entries:
                ctk.CTkLabel(
                    summary_list,
                    text="No hay citas programadas.",
                    text_color=COLORS["muted"],
                    wraplength=260,
                ).pack(
                    padx=10,
                    pady=18,
                )
            else:
                for row in selected_entries:
                    color = {
                        "CONFIRMED": COLORS["green"],
                        "PENDING": COLORS["orange"],
                        "CANCELLED": COLORS["red"],
                        "COMPLETED": COLORS["blue"],
                        "NO_SHOW": COLORS["purple"],
                    }.get(
                        row["status"],
                        COLORS["blue"],
                    )

                    item = ctk.CTkFrame(
                        summary_list,
                        fg_color="white",
                        corner_radius=10,
                        border_width=1,
                        border_color=color,
                    )
                    item.pack(
                        fill=X,
                        padx=3,
                        pady=4,
                    )

                    ctk.CTkLabel(
                        item,
                        text=(
                            f"{row['start_time']}  ·  "
                            f"{decrypt_text(row['full_name_enc'])}"
                        ),
                        font=("Segoe UI", 10, "bold"),
                        text_color=COLORS["text"],
                        anchor="w",
                        wraplength=255,
                        justify="left",
                    ).pack(
                        fill=X,
                        padx=10,
                        pady=(9, 2),
                    )

                    ctk.CTkLabel(
                        item,
                        text=(
                            f"{row['professional']}  ·  "
                            f"{row['status']}"
                        ),
                        font=("Segoe UI", 9),
                        text_color=color,
                        anchor="w",
                    ).pack(
                        fill=X,
                        padx=10,
                        pady=(0, 8),
                    )

            self.action_button(
                summary_panel,
                "Abrir vista diaria",
                lambda: (
                    view_mode.set("Día"),
                    render_calendar(),
                ),
                COLORS["blue"],
            ).pack(
                fill=X,
                padx=14,
                pady=(0, 7),
            )

            self.action_button(
                summary_panel,
                "Nueva cita este día",
                lambda: self.appointment_form(
                    prefill_date=selected_date.get()
                ),
                COLORS["purple"],
            ).pack(
                fill=X,
                padx=14,
                pady=(0, 14),
            )

        def render_calendar():
            clear_calendar_container()

            if view_mode.get() == "Mes":
                render_month()
            else:
                render_day()

        mode_switch.configure(
            command=lambda _value: render_calendar()
        )

        date_entry.bind(
            "<Return>",
            lambda _event: (
                month_cursor.__setitem__(
                    0,
                    parse_selected().replace(
                        day=1,
                        hour=0,
                        minute=0,
                        second=0,
                        microsecond=0,
                    ),
                ),
                render_calendar(),
            ),
        )

        render_calendar()


    def appointment_form(self, appointment_id=None, prefill_date=None, prefill_time=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Cita")
        dialog.geometry("700x790")
        dialog.grab_set()

        with db() as conn:
            patients = conn.execute("SELECT id, full_name_enc FROM patients ORDER BY id").fetchall()
        patient_map = {f"{p['id']} - {decrypt_text(p['full_name_enc'])}": p["id"] for p in patients}

        data = None
        if appointment_id:
            with db() as conn:
                data = conn.execute("SELECT * FROM appointments WHERE id=?", (appointment_id,)).fetchone()

        frame = ctk.CTkScrollableFrame(dialog, fg_color=COLORS["bg"])
        frame.pack(fill=BOTH, expand=True)

        variables = {
            "patient": ctk.StringVar(),
            "professional": ctk.StringVar(value=data["professional"] if data else ""),
            "specialty": ctk.StringVar(value=data["specialty"] if data else "Medicina general"),
            "date": ctk.StringVar(
                value=data["appointment_date"]
                if data
                else (prefill_date or datetime.now().strftime("%Y-%m-%d"))
            ),
            "time": ctk.StringVar(
                value=data["start_time"]
                if data
                else (prefill_time or "08:00")
            ),
            "duration": ctk.StringVar(value=str(data["duration_min"]) if data else "30"),
            "room": ctk.StringVar(value=data["room"] if data else "Consultorio 1"),
            "status": ctk.StringVar(value=data["status"] if data else "PENDING"),
            "reason": ctk.StringVar(value=data["reason_admin"] if data else ""),
        }

        if data:
            for label, pid in patient_map.items():
                if pid == data["patient_id"]:
                    variables["patient"].set(label)
                    break

        ctk.CTkLabel(
            frame,
            text="Programación de cita",
            font=("Segoe UI", 24, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=25, pady=(20, 18))

        for key, label, combo_values in [
            ("patient", "Paciente", list(patient_map.keys())),
            ("professional", "Profesional", None),
            ("specialty", "Especialidad", None),
            ("date", "Fecha (AAAA-MM-DD)", None),
            ("time", "Hora (HH:MM)", None),
            ("duration", "Duración en minutos", None),
            ("room", "Consultorio", None),
            ("status", "Estado", ["PENDING", "CONFIRMED", "CANCELLED", "COMPLETED", "NO_SHOW"]),
            ("reason", "Motivo administrativo", None),
        ]:
            ctk.CTkLabel(frame, text=label, text_color=COLORS["text"]).pack(anchor="w", padx=25)
            if combo_values:
                ctk.CTkComboBox(
                    frame,
                    variable=variables[key],
                    values=combo_values,
                    height=41,
                    corner_radius=12,
                ).pack(fill=X, padx=25, pady=(5, 12))
            else:
                ctk.CTkEntry(
                    frame,
                    textvariable=variables[key],
                    height=41,
                    corner_radius=12,
                ).pack(fill=X, padx=25, pady=(5, 12))

        def save():
            if variables["patient"].get() not in patient_map:
                messagebox.showwarning("Cita", "Seleccione un paciente.")
                return

            try:
                duration = int(variables["duration"].get())
            except ValueError:
                messagebox.showwarning("Cita", "La duración debe ser numérica.")
                return

            with db() as conn:
                conflict = conn.execute(
                    """
                    SELECT COUNT(*) AS total FROM appointments
                    WHERE professional=? AND appointment_date=? AND start_time=?
                    AND status!='CANCELLED' AND id != COALESCE(?, -1)
                    """,
                    (
                        variables["professional"].get(),
                        variables["date"].get(),
                        variables["time"].get(),
                        appointment_id,
                    ),
                ).fetchone()["total"]

                if conflict:
                    messagebox.showerror(
                        "Horario ocupado",
                        "Ese profesional ya tiene una cita en el horario seleccionado.",
                    )
                    return

                if appointment_id:
                    conn.execute(
                        """
                        UPDATE appointments SET patient_id=?, professional=?, specialty=?,
                        appointment_date=?, start_time=?, duration_min=?, room=?, status=?,
                        reason_admin=?, updated_at=? WHERE id=?
                        """,
                        (
                            patient_map[variables["patient"].get()],
                            variables["professional"].get(),
                            variables["specialty"].get(),
                            variables["date"].get(),
                            variables["time"].get(),
                            duration,
                            variables["room"].get(),
                            variables["status"].get(),
                            variables["reason"].get(),
                            now_iso(),
                            appointment_id,
                        ),
                    )
                    entity_id = str(appointment_id)
                else:
                    cursor = conn.execute(
                        """
                        INSERT INTO appointments
                        (patient_id, professional, specialty, appointment_date, start_time,
                         duration_min, room, status, reason_admin, created_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            patient_map[variables["patient"].get()],
                            variables["professional"].get(),
                            variables["specialty"].get(),
                            variables["date"].get(),
                            variables["time"].get(),
                            duration,
                            variables["room"].get(),
                            variables["status"].get(),
                            variables["reason"].get(),
                            self.session.username,
                            now_iso(),
                            now_iso(),
                        ),
                    )
                    entity_id = str(cursor.lastrowid)

            audit(self.session.username, self.session.role, "SAVE", "APPOINTMENT", entity_id)
            dialog.destroy()
            self.page_appointments()

        self.action_button(frame, "Guardar cita", save, COLORS["purple"]).pack(
            fill=X,
            padx=25,
            pady=(0, 25),
        )

    def page_reminders(self):
        self.clear_content()
        self.page_header("Recordatorios", "Mensajes discretos que no exponen información médica.")

        tree = self.tree_card(
            ("date", "time", "patient", "status", "contact"),
            ("Fecha", "Hora", "Paciente", "Estado", "Contacto"),
            (120, 90, 280, 120, 220),
        )

        with db() as conn:
            rows = conn.execute(
                """
                SELECT a.*, p.full_name_enc, p.phone_enc, p.email_enc
                FROM appointments a JOIN patients p ON p.id=a.patient_id
                WHERE a.status IN ('PENDING','CONFIRMED')
                ORDER BY appointment_date, start_time
                """
            ).fetchall()

        for row in rows:
            phone = decrypt_text(row["phone_enc"])
            email = decrypt_text(row["email_enc"])
            masked = (phone[:3] + "***" + phone[-2:] if len(phone) >= 5 else phone) or email
            tree.insert(
                "",
                END,
                iid=str(row["id"]),
                values=(
                    row["appointment_date"],
                    row["start_time"],
                    decrypt_text(row["full_name_enc"]),
                    row["status"],
                    masked,
                ),
            )

        def register_reminder():
            if not tree.selection():
                messagebox.showwarning("Recordatorio", "Seleccione una cita.")
                return
            appointment_id = int(tree.selection()[0])
            with db() as conn:
                row = conn.execute(
                    """
                    SELECT a.*, p.phone_enc, p.email_enc FROM appointments a
                    JOIN patients p ON p.id=a.patient_id WHERE a.id=?
                    """,
                    (appointment_id,),
                ).fetchone()
            message = (
                f"Estimado paciente, le recordamos su cita programada para el "
                f"{row['appointment_date']} a las {row['start_time']}. "
                "Para confirmar o reprogramar, comuníquese con el centro médico."
            )
            phone = decrypt_text(row["phone_enc"])
            email = decrypt_text(row["email_enc"])
            recipient = (phone[:3] + "***" + phone[-2:] if len(phone) >= 5 else phone) or email
            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO reminders
                    (appointment_id, channel, recipient_masked, message, status, sent_by, sent_at)
                    VALUES (?, 'SIMULATED', ?, ?, 'RECORDED', ?, ?)
                    """,
                    (appointment_id, recipient, message, self.session.username, now_iso()),
                )
            audit(self.session.username, self.session.role, "CREATE", "REMINDER", str(appointment_id))
            messagebox.showinfo("Recordatorio registrado", message)

        self.action_button(self.content, "Registrar recordatorio", register_reminder, COLORS["orange"]).pack(anchor="e", padx=12, pady=8)

    def export_logs(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Archivo CSV", "*.csv")],
            initialfile="cryptoaccess_professional_audit_chain.csv",
        )
        if not path:
            return
        with db() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
        with open(path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            if rows:
                writer.writerow(rows[0].keys())
                for row in rows:
                    writer.writerow(list(row))
        messagebox.showinfo("Exportación", "Los logs fueron exportados correctamente.")


    def page_secure_documents(self):
        self.clear_content()
        self.page_header(
            "Documentos protegidos",
            "Cifrado híbrido real: AES-256-GCM, RSA-3072-OAEP, SHA-384 y firma RSA-PSS.",
        )

        toolbar = ctk.CTkFrame(self.content, fg_color="transparent")
        toolbar.pack(fill=X, padx=12)

        tree = self.tree_card(
            ("name", "patient", "category", "owner", "hash", "key", "status", "date"),
            ("Documento", "Paciente", "Categoría", "Propietario", "SHA-384", "Key ID", "Verificación", "Fecha"),
            (220, 190, 130, 120, 210, 180, 110, 165),
            height=17,
        )

        def refresh():
            for item in tree.get_children():
                tree.delete(item)
            with db() as conn:
                rows = conn.execute(
                    """
                    SELECT sd.*, p.full_name_enc FROM secure_documents sd
                    LEFT JOIN patients p ON p.id=sd.patient_id
                    ORDER BY sd.id DESC
                    """
                ).fetchall()
            for row in rows:
                patient = decrypt_text(row["full_name_enc"]) if row["full_name_enc"] else "Sin paciente"
                tree.insert(
                    "",
                    END,
                    iid=str(row["id"]),
                    values=(
                        row["original_name"],
                        patient,
                        row["category"],
                        row["owner_username"],
                        row["plaintext_sha384"][:22] + "...",
                        row["key_id"][:21] + "...",
                        row["verification_status"],
                        row["created_at"],
                    ),
                )

        def protect_document():
            source_text = filedialog.askopenfilename(title="Seleccione un documento clínico")
            if not source_text:
                return

            dialog = ctk.CTkToplevel(self)
            dialog.title("Proteger documento")
            dialog.geometry("610x480")
            dialog.grab_set()

            with db() as conn:
                patients = conn.execute(
                    "SELECT id, full_name_enc FROM patients ORDER BY id"
                ).fetchall()
            patient_map = {"Sin paciente asociado": None}
            patient_map.update({
                f"{p['id']} - {decrypt_text(p['full_name_enc'])}": p["id"]
                for p in patients
            })

            frame = ctk.CTkFrame(dialog, fg_color=COLORS["bg"])
            frame.pack(fill=BOTH, expand=True)
            patient_var = ctk.StringVar(value="Sin paciente asociado")
            category_var = ctk.StringVar(value="Documento clínico")

            ctk.CTkLabel(
                frame,
                text="Protección criptográfica",
                font=("Segoe UI", 24, "bold"),
                text_color=COLORS["text"],
            ).pack(anchor="w", padx=28, pady=(28, 8))

            ctk.CTkLabel(
                frame,
                text=Path(source_text).name,
                wraplength=530,
                text_color=COLORS["muted"],
            ).pack(anchor="w", padx=28, pady=(0, 18))

            ctk.CTkLabel(frame, text="Paciente", text_color=COLORS["text"]).pack(anchor="w", padx=28)
            ctk.CTkComboBox(
                frame,
                variable=patient_var,
                values=list(patient_map.keys()),
                height=42,
                corner_radius=12,
            ).pack(fill=X, padx=28, pady=(5, 14))

            ctk.CTkLabel(frame, text="Categoría", text_color=COLORS["text"]).pack(anchor="w", padx=28)
            ctk.CTkComboBox(
                frame,
                variable=category_var,
                values=[
                    "Documento clínico",
                    "Resultado de laboratorio",
                    "Imagen médica",
                    "Consentimiento",
                    "Receta",
                    "Documento odontológico",
                    "Otro",
                ],
                height=42,
                corner_radius=12,
            ).pack(fill=X, padx=28, pady=(5, 18))

            ctk.CTkLabel(
                frame,
                text=(
                    "El contenido se cifrará con AES-256-GCM. La clave AES será "
                    "encapsulada con RSA-3072-OAEP. Se calculará SHA-384 y se firmará "
                    "digitalmente con RSA-3072-PSS."
                ),
                wraplength=540,
                text_color=COLORS["muted"],
            ).pack(anchor="w", padx=28, pady=(0, 18))

            def execute():
                try:
                    package = create_secure_document_package(
                        Path(source_text),
                        patient_map[patient_var.get()],
                        category_var.get(),
                        self.session.username,
                    )
                    with db() as conn:
                        cursor = conn.execute(
                            """
                            INSERT INTO secure_documents
                            (document_uuid, patient_id, original_name, package_path,
                             category, owner_username, plaintext_sha384, package_sha384,
                             signature_b64, key_id, algorithm_summary, original_size,
                             created_at, verification_status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED')
                            """,
                            (
                                package["document_uuid"],
                                package["patient_id"],
                                package["original_name"],
                                package["package_path"],
                                package["category"],
                                package["owner_username"],
                                package["plaintext_sha384"],
                                package["package_sha384"],
                                package["signature_b64"],
                                package["key_id"],
                                package["algorithm_summary"],
                                package["original_size"],
                                package["created_at"],
                            ),
                        )
                        document_id = cursor.lastrowid

                    audit(
                        self.session.username,
                        self.session.role,
                        "ENCRYPT_AND_SIGN",
                        "SECURE_DOCUMENT",
                        str(document_id),
                        details=f"Documento protegido: {package['original_name']}",
                        metadata={
                            "document_uuid": package["document_uuid"],
                            "plaintext_sha384": package["plaintext_sha384"],
                            "package_sha384": package["package_sha384"],
                            "key_id": package["key_id"],
                            "algorithms": package["algorithm_summary"],
                            "size": package["original_size"],
                        },
                    )
                    dialog.destroy()
                    refresh()
                    messagebox.showinfo(
                        "Documento protegido",
                        "El paquete fue creado y verificado correctamente.\n\n"
                        f"SHA-384:\n{package['plaintext_sha384']}\n\n"
                        f"Key ID:\n{package['key_id']}",
                    )
                except Exception as error:
                    audit(
                        self.session.username,
                        self.session.role,
                        "ENCRYPT_AND_SIGN",
                        "SECURE_DOCUMENT",
                        result="FAILED",
                        details=str(error),
                        severity="HIGH",
                    )
                    messagebox.showerror("Protección fallida", str(error))

            self.action_button(frame, "Cifrar y firmar documento", execute, COLORS["green"]).pack(fill=X, padx=28, pady=(0, 24))

        def verify_selected():
            if not tree.selection():
                messagebox.showwarning("Documento", "Seleccione un documento.")
                return
            document_id = int(tree.selection()[0])
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM secure_documents WHERE id=?",
                    (document_id,),
                ).fetchone()

            try:
                package_path = Path(row["package_path"])
                current_package_hash = sha384_hex(package_path.read_bytes())
                if current_package_hash != row["package_sha384"]:
                    raise ValueError("El paquete cifrado fue modificado desde su registro.")

                with zipfile.ZipFile(package_path, "r") as package:
                    manifest = json.loads(package.read("manifest.json").decode("utf-8"))
                    signature_b64 = package.read("signature.b64").decode("ascii")
                    nonce = package.read("nonce.bin")
                    wrapped_key = package.read("wrapped_key.bin")
                    ciphertext = package.read("ciphertext.bin")

                private_key, _record = load_private_key(manifest["key_id"])
                aes_key = private_key.decrypt(
                    wrapped_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA384()),
                        algorithm=hashes.SHA384(),
                        label=None,
                    ),
                )
                plaintext = AESGCM(aes_key).decrypt(
                    nonce,
                    ciphertext,
                    base64.b64decode(manifest["aad_b64"]),
                )
                calculated_hash = sha384_hex(plaintext)
                if calculated_hash != row["plaintext_sha384"]:
                    raise ValueError("El hash SHA-384 del contenido no coincide.")
                if not rsa_verify_sha384(plaintext, signature_b64, row["key_id"]):
                    raise ValueError("La firma digital RSA-PSS no es válida.")

                with db() as conn:
                    conn.execute(
                        """
                        UPDATE secure_documents SET verification_status='VERIFIED',
                        last_verified_at=? WHERE id=?
                        """,
                        (now_iso(), document_id),
                    )
                audit(
                    self.session.username,
                    self.session.role,
                    "VERIFY",
                    "SECURE_DOCUMENT",
                    str(document_id),
                    details="Cifrado, hash y firma digital verificados.",
                    metadata={
                        "plaintext_sha384": calculated_hash,
                        "package_sha384": current_package_hash,
                        "key_id": row["key_id"],
                    },
                )
                refresh()
                messagebox.showinfo(
                    "Verificación correcta",
                    f"Integridad y autenticidad confirmadas.\n\nSHA-384:\n{calculated_hash}",
                )
            except Exception as error:
                with db() as conn:
                    conn.execute(
                        """
                        UPDATE secure_documents SET verification_status='FAILED',
                        last_verified_at=? WHERE id=?
                        """,
                        (now_iso(), document_id),
                    )
                audit(
                    self.session.username,
                    self.session.role,
                    "VERIFY",
                    "SECURE_DOCUMENT",
                    str(document_id),
                    result="FAILED",
                    details=str(error),
                    severity="CRITICAL",
                )
                refresh()
                messagebox.showerror("Verificación fallida", str(error))

        def open_selected():
            if not tree.selection():
                messagebox.showwarning("Documento", "Seleccione un documento.")
                return
            document_id = int(tree.selection()[0])
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM secure_documents WHERE id=?",
                    (document_id,),
                ).fetchone()

            destination = filedialog.asksaveasfilename(
                title="Guardar copia descifrada",
                initialfile=row["original_name"],
            )
            if not destination:
                return

            try:
                manifest = verify_and_open_secure_document(
                    Path(row["package_path"]),
                    Path(destination),
                )
                with db() as conn:
                    conn.execute(
                        """
                        UPDATE secure_documents SET verification_status='VERIFIED',
                        last_verified_at=? WHERE id=?
                        """,
                        (now_iso(), document_id),
                    )
                audit(
                    self.session.username,
                    self.session.role,
                    "DECRYPT",
                    "SECURE_DOCUMENT",
                    str(document_id),
                    details=f"Documento descifrado a una ubicación autorizada.",
                    metadata={
                        "document_uuid": manifest["document_uuid"],
                        "sha384": manifest["plaintext_sha384"],
                        "key_id": manifest["key_id"],
                        "destination_name": Path(destination).name,
                    },
                )
                messagebox.showinfo(
                    "Documento recuperado",
                    "El documento fue descifrado después de verificar SHA-384 y firma RSA-PSS.",
                )
            except Exception as error:
                audit(
                    self.session.username,
                    self.session.role,
                    "DECRYPT",
                    "SECURE_DOCUMENT",
                    str(document_id),
                    result="FAILED",
                    details=str(error),
                    severity="CRITICAL",
                )
                messagebox.showerror("Descifrado fallido", str(error))

        self.action_button(toolbar, "Proteger documento", protect_document, COLORS["green"]).pack(side=LEFT)
        self.action_button(toolbar, "Verificar", verify_selected, COLORS["cyan"]).pack(side=LEFT, padx=8)
        self.action_button(toolbar, "Descifrar copia", open_selected, COLORS["purple"]).pack(side=LEFT)
        refresh()


    def page_crypto_center(self):
        self.clear_content()
        self.page_header(
            "Centro criptográfico y PKI",
            "RSA-3072, certificados X.509, rotación, revocación, TLS y respuesta ante compromiso.",
        )

        with db() as conn:
            active = conn.execute(
                "SELECT * FROM key_registry WHERE status='ACTIVE' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            total_keys = conn.execute("SELECT COUNT(*) AS n FROM key_registry").fetchone()["n"]
            valid_certs = conn.execute(
                "SELECT COUNT(*) AS n FROM certificates WHERE status='VALID'"
            ).fetchone()["n"]
            incidents = conn.execute(
                "SELECT COUNT(*) AS n FROM incidents"
            ).fetchone()["n"]

        tls_ok, tls_detail = self.tls_service.self_test()
        cards = ctk.CTkFrame(self.content, fg_color="transparent")
        cards.pack(fill=X, padx=12)
        for title, value, color in [
            ("Clave RSA activa", active["key_id"][-12:] if active else "N/A", COLORS["blue"]),
            ("Certificados válidos", valid_certs, COLORS["green"]),
            ("Claves registradas", total_keys, COLORS["purple"]),
            ("Incidentes", incidents, COLORS["orange"]),
            ("TLS", "OPERATIVO" if tls_ok else "ERROR", COLORS["green"] if tls_ok else COLORS["red"]),
        ]:
            card = RoundedCard(cards)
            card.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 7), pady=5)
            ctk.CTkLabel(card, text=title, text_color=COLORS["muted"]).pack(anchor="w", padx=15, pady=(15, 3))
            ctk.CTkLabel(card, text=str(value), font=("Segoe UI", 16, "bold"), text_color=color).pack(anchor="w", padx=15, pady=(0, 15))

        toolbar = ctk.CTkFrame(self.content, fg_color="transparent")
        toolbar.pack(fill=X, padx=12, pady=(8, 4))

        key_tree = self.tree_card(
            ("key", "size", "status", "created", "expires", "fingerprint"),
            ("Key ID", "Bits", "Estado", "Creada", "Vence", "Huella SHA-384"),
            (255, 70, 115, 165, 165, 360),
            height=9,
        )

        def refresh_keys():
            for item in key_tree.get_children():
                key_tree.delete(item)
            with db() as conn:
                rows = conn.execute(
                    "SELECT * FROM key_registry ORDER BY created_at DESC"
                ).fetchall()
            for row in rows:
                key_tree.insert(
                    "",
                    END,
                    iid=row["key_id"],
                    values=(
                        row["key_id"],
                        row["key_size"],
                        row["status"],
                        row["created_at"],
                        row["expires_at"] or "",
                        row["fingerprint_sha384"],
                    ),
                )

        def selected_key_id():
            return key_tree.selection()[0] if key_tree.selection() else None

        def rotate():
            key_id = create_rsa_key_pair(self.session.username, activate=True)
            audit(
                self.session.username,
                self.session.role,
                "ROTATE",
                "CRYPTO_KEY",
                key_id,
                details="Rotación RSA-3072 realizada y certificado X.509 emitido.",
                severity="HIGH",
                metadata={"rotation_policy_days": 180},
            )
            messagebox.showinfo("Rotación", f"Nueva clave activa:\n{key_id}")
            self.page_crypto_center()

        def revoke():
            key_id = selected_key_id()
            if not key_id:
                messagebox.showwarning("Revocación", "Seleccione una clave.")
                return

            dialog = ctk.CTkToplevel(self)
            dialog.title("Revocar clave comprometida")
            dialog.geometry("600x390")
            dialog.grab_set()
            frame = RoundedCard(dialog)
            frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
            ctk.CTkLabel(
                frame,
                text="Respuesta ante compromiso",
                font=("Segoe UI", 22, "bold"),
                text_color=COLORS["text"],
            ).pack(anchor="w", padx=24, pady=(24, 6))
            ctk.CTkLabel(
                frame,
                text=f"Clave seleccionada:\n{key_id}",
                wraplength=510,
                text_color=COLORS["muted"],
            ).pack(anchor="w", padx=24, pady=(0, 14))
            reason = ctk.StringVar(value="Sospecha de exposición o uso no autorizado de la clave privada.")
            ctk.CTkEntry(
                frame,
                textvariable=reason,
                height=44,
                corner_radius=12,
            ).pack(fill=X, padx=24, pady=(0, 16))

            def confirm():
                if not reason.get().strip():
                    messagebox.showwarning("Motivo", "Indique el motivo de la revocación.")
                    return
                try:
                    result = revoke_compromised_key(
                        key_id,
                        reason.get().strip(),
                        self.session.username,
                    )
                    audit(
                        self.session.username,
                        self.session.role,
                        "REVOKE",
                        "CRYPTO_KEY",
                        key_id,
                        details=reason.get().strip(),
                        severity="CRITICAL",
                        metadata=result,
                    )
                    dialog.destroy()
                    messagebox.showinfo(
                        "Clave revocada",
                        f"Incidente: {result['incident_uuid']}\n"
                        f"Nueva clave: {result['new_key_id']}\n"
                        f"Documentos reprotegidos: {result['documents_reprotected']}\n"
                        f"Expedientes atestados: {result['records_attested']}",
                    )
                    self.page_crypto_center()
                except Exception as error:
                    messagebox.showerror("Revocación", str(error))

            self.action_button(
                frame,
                "Revocar, rotar y reproteger",
                confirm,
                COLORS["red"],
            ).pack(fill=X, padx=24, pady=(0, 24))

        def export_public():
            key_id = selected_key_id() or active["key_id"]
            key = get_key_record(key_id)
            destination = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("Clave pública PEM", "*.pem")],
                initialfile=f"{key_id}_public.pem",
            )
            if destination:
                shutil.copy2(key["public_path"], destination)
                audit(
                    self.session.username,
                    self.session.role,
                    "EXPORT",
                    "PUBLIC_KEY",
                    key_id,
                    metadata={"file": Path(destination).name},
                )

        def export_certificate():
            key_id = selected_key_id() or active["key_id"]
            with db() as conn:
                cert = conn.execute(
                    """
                    SELECT * FROM certificates WHERE key_id=?
                    AND certificate_type='SIGNING'
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (key_id,),
                ).fetchone()
            if not cert:
                messagebox.showwarning("Certificado", "La clave no tiene certificado.")
                return
            destination = filedialog.asksaveasfilename(
                defaultextension=".pem",
                filetypes=[("Certificado X.509", "*.pem")],
                initialfile=f"{cert['certificate_id']}.pem",
            )
            if destination:
                shutil.copy2(cert["pem_path"], destination)
                audit(
                    self.session.username,
                    self.session.role,
                    "EXPORT",
                    "CERTIFICATE",
                    cert["certificate_id"],
                )

        def self_test():
            sample = secrets.token_bytes(128)
            try:
                public_key, key_record = load_public_key()
                private_key, _ = load_private_key(key_record["key_id"])
                aes_key = AESGCM.generate_key(bit_length=256)
                nonce = os.urandom(12)
                encrypted = AESGCM(aes_key).encrypt(nonce, sample, b"SELF-TEST")
                restored_sample = AESGCM(aes_key).decrypt(nonce, encrypted, b"SELF-TEST")
                wrapped = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA384()),
                        algorithm=hashes.SHA384(),
                        label=None,
                    ),
                )
                restored_key = private_key.decrypt(
                    wrapped,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA384()),
                        algorithm=hashes.SHA384(),
                        label=None,
                    ),
                )
                signature, key_id = rsa_sign_sha384(sample)
                cert_ok, cert_detail = verify_certificate_for_key(key_id)
                tls_ok, tls_detail = self.tls_service.self_test()
                valid = (
                    restored_sample == sample
                    and restored_key == aes_key
                    and rsa_verify_sha384(sample, signature, key_id)
                    and cert_ok
                    and tls_ok
                )
                if not valid:
                    raise ValueError("Alguna validación criptográfica no fue satisfactoria.")
                audit(
                    self.session.username,
                    self.session.role,
                    "SELF_TEST",
                    "CRYPTO_ENGINE",
                    details="Prueba completa AES, RSA, SHA-384, X.509, TLS y anti-repetición.",
                    metadata={"certificate": cert_detail, "tls": tls_detail},
                )
                messagebox.showinfo(
                    "Prueba completa",
                    "AES-256-GCM, RSA-3072-OAEP, RSA-PSS, SHA-384, X.509 y TLS funcionan correctamente.",
                )
            except Exception as error:
                audit(
                    self.session.username,
                    self.session.role,
                    "SELF_TEST",
                    "CRYPTO_ENGINE",
                    result="FAILED",
                    details=str(error),
                    severity="CRITICAL",
                )
                messagebox.showerror("Prueba criptográfica", str(error))

        self.action_button(toolbar, "Rotar clave", rotate, COLORS["orange"]).pack(side=LEFT)
        self.action_button(toolbar, "Revocar comprometida", revoke, COLORS["red"]).pack(side=LEFT, padx=6)
        self.action_button(toolbar, "Exportar pública", export_public, COLORS["cyan"]).pack(side=LEFT)
        self.action_button(toolbar, "Exportar certificado", export_certificate, COLORS["purple"]).pack(side=LEFT, padx=6)
        self.action_button(toolbar, "Prueba completa", self_test, COLORS["green"]).pack(side=LEFT)

        refresh_keys()

        ctk.CTkLabel(
            self.content,
            text=f"Canal TLS: {tls_detail}",
            wraplength=1100,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=16, pady=(8, 4))

        cert_tree = self.tree_card(
            ("id", "type", "key", "status", "subject", "valid_to", "fingerprint"),
            ("Certificate ID", "Tipo", "Key ID", "Estado", "Sujeto", "Válido hasta", "Huella SHA-384"),
            (210, 105, 210, 90, 290, 165, 300),
            height=7,
        )
        with db() as conn:
            certs = conn.execute(
                "SELECT * FROM certificates ORDER BY created_at DESC"
            ).fetchall()
        for cert in certs:
            cert_tree.insert(
                "",
                END,
                values=(
                    cert["certificate_id"],
                    cert["certificate_type"],
                    cert["key_id"] or "",
                    cert["status"],
                    cert["subject"],
                    cert["valid_to"],
                    cert["fingerprint_sha384"],
                ),
            )

        incident_tree = self.tree_card(
            ("uuid", "type", "severity", "status", "key", "docs", "records", "created"),
            ("Incidente", "Tipo", "Severidad", "Estado", "Clave", "Docs", "Expedientes", "Fecha"),
            (240, 145, 90, 100, 225, 65, 90, 170),
            height=5,
        )
        with db() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY id DESC"
            ).fetchall()
        for row in rows:
            incident_tree.insert(
                "",
                END,
                values=(
                    row["incident_uuid"],
                    row["incident_type"],
                    row["severity"],
                    row["status"],
                    row["key_id"] or "",
                    row["affected_documents"],
                    row["affected_records"],
                    row["created_at"],
                ),
            )

    def page_logs(self):
        if self.session.role != "AUDITOR":
            messagebox.showerror(
                "Acceso restringido",
                "La bitácora detallada solo puede ser consultada por el auditor criptográfico único.",
            )
            self.page_home()
            return
        self.clear_content()
        self.page_header(
            "Auditoría profesional",
            "Eventos encadenados mediante SHA-384, con severidad, estación y metadatos técnicos.",
        )

        toolbar = ctk.CTkFrame(self.content, fg_color="transparent")
        toolbar.pack(fill=X, padx=12)

        self.action_button(toolbar, "Exportar CSV", self.export_logs, COLORS["cyan"]).pack(side=LEFT)

        def verify_chain_ui():
            valid, detail, count = verify_audit_chain()
            audit(
                self.session.username,
                self.session.role,
                "VERIFY_CHAIN",
                "AUDIT_LOG",
                result="OK" if valid else "FAILED",
                details=detail,
                severity="INFO" if valid else "CRITICAL",
                metadata={"events_verified": count},
            )
            if valid:
                messagebox.showinfo(
                    "Cadena íntegra",
                    f"{detail}\nEventos verificados: {count}",
                )
            else:
                messagebox.showerror(
                    "Cadena comprometida",
                    f"{detail}\nEventos verificados antes del fallo: {count}",
                )
            self.page_logs()

        self.action_button(
            toolbar,
            "Verificar cadena SHA-384",
            verify_chain_ui,
            COLORS["green"],
        ).pack(side=LEFT, padx=8)

        tree = self.tree_card(
            ("id", "time", "severity", "user", "role", "action", "entity", "result", "workstation", "hash", "details"),
            ("ID", "Fecha", "Severidad", "Usuario", "Rol", "Acción", "Entidad", "Resultado", "Estación", "Event hash", "Detalle"),
            (65, 165, 90, 110, 85, 115, 130, 90, 140, 195, 310),
            height=18,
        )

        with db() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1000"
            ).fetchall()

        for row in rows:
            tree.insert(
                "",
                END,
                iid=str(row["id"]),
                values=(
                    row["id"],
                    row["timestamp"],
                    row["severity"] or "INFO",
                    row["username"],
                    row["role"],
                    row["action"],
                    row["entity"],
                    row["result"],
                    row["workstation"] or "",
                    (row["event_hash"][:20] + "...") if row["event_hash"] else "Legacy",
                    row["details"],
                ),
            )

        def show_event_detail(_event=None):
            if not tree.selection():
                return
            event_id = int(tree.selection()[0])
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM audit_logs WHERE id=?",
                    (event_id,),
                ).fetchone()

            dialog = ctk.CTkToplevel(self)
            dialog.title(f"Evento de auditoría #{event_id}")
            dialog.geometry("850x720")
            dialog.grab_set()

            textbox = ctk.CTkTextbox(
                dialog,
                wrap="word",
                font=("Consolas", 11),
                corner_radius=14,
            )
            textbox.pack(fill=BOTH, expand=True, padx=20, pady=20)

            detail = {
                key: row[key]
                for key in row.keys()
            }
            try:
                detail["metadata_json"] = json.loads(detail["metadata_json"] or "{}")
            except Exception:
                pass

            textbox.insert(
                "1.0",
                json.dumps(detail, ensure_ascii=False, indent=2),
            )
            textbox.configure(state="disabled")

        tree.bind("<Double-1>", show_event_detail)


    def page_it_status(self):
        self.clear_content()
        self.page_header(
            "Estado técnico",
            "Información operativa sin nombres, diagnósticos ni contenido de pacientes.",
        )

        tls_ok, tls_detail = self.tls_service.self_test()
        db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        docs_size = sum(
            path.stat().st_size
            for path in SECURE_DOCUMENTS_DIR.glob("*.cahs")
            if path.is_file()
        )
        with db() as conn:
            critical = conn.execute(
                "SELECT COUNT(*) AS n FROM audit_logs WHERE severity IN ('HIGH','CRITICAL') AND result='FAILED'"
            ).fetchone()["n"]
            certs = conn.execute(
                "SELECT COUNT(*) AS n FROM certificates WHERE status='VALID'"
            ).fetchone()["n"]

        cards = ctk.CTkFrame(self.content, fg_color="transparent")
        cards.pack(fill=X, padx=12)
        for title, value, color in [
            ("Canal TLS", "OPERATIVO" if tls_ok else "ERROR", COLORS["green"] if tls_ok else COLORS["red"]),
            ("Base de datos", f"{db_size / 1024:.1f} KB", COLORS["blue"]),
            ("Documentos cifrados", f"{docs_size / 1024:.1f} KB", COLORS["purple"]),
            ("Certificados válidos", certs, COLORS["cyan"]),
            ("Alertas técnicas", critical, COLORS["orange"]),
        ]:
            card = RoundedCard(cards)
            card.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 8), pady=5)
            ctk.CTkLabel(card, text=title, text_color=COLORS["muted"]).pack(anchor="w", padx=16, pady=(16, 3))
            ctk.CTkLabel(card, text=str(value), font=("Segoe UI", 18, "bold"), text_color=color).pack(anchor="w", padx=16, pady=(0, 16))

        status = RoundedCard(self.content)
        status.pack(fill=X, padx=12, pady=12)
        ctk.CTkLabel(
            status,
            text="Diagnóstico del canal seguro",
            font=("Segoe UI", 18, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(20, 8))
        ctk.CTkLabel(
            status,
            text=tls_detail,
            wraplength=980,
            justify="left",
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(0, 20))

        ctk.CTkLabel(
            status,
            text=(
                "El soporte TI no tiene acceso a pacientes, expedientes, diagnósticos "
                "ni a la bitácora detallada. La revisión de logs corresponde exclusivamente "
                "al auditor criptográfico."
            ),
            wraplength=980,
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=22, pady=(0, 20))


    def page_backup(self):
        self.clear_content()
        self.page_header(
            "Respaldo y recuperación",
            "Paquetes cifrados con PBKDF2-HMAC-SHA256, AES-256-GCM y verificación SHA-384.",
        )

        card = RoundedCard(self.content)
        card.pack(fill=X, padx=12, pady=8)
        ctk.CTkLabel(
            card,
            text="Disponibilidad y recuperación",
            font=("Segoe UI", 20, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=24, pady=(24, 8))
        ctk.CTkLabel(
            card,
            text=(
                "El respaldo incluye la base de datos, claves privadas ya cifradas, "
                "certificados, almacén seguro y documentos .cahs. El paquete completo "
                "se cifra nuevamente con una contraseña de recuperación."
            ),
            wraplength=1000,
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=24, pady=(0, 18))

        password = ctk.StringVar()
        ctk.CTkLabel(card, text="Contraseña de respaldo", text_color=COLORS["text"]).pack(anchor="w", padx=24)
        ctk.CTkEntry(
            card,
            textvariable=password,
            show="•",
            height=42,
            corner_radius=12,
            placeholder_text="Mínimo 12 caracteres",
        ).pack(fill=X, padx=24, pady=(5, 16))

        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.pack(fill=X, padx=24, pady=(0, 24))

        def create_backup_ui():
            destination = filedialog.asksaveasfilename(
                defaultextension=".cahbak",
                filetypes=[("Respaldo CryptoAccess", "*.cahbak")],
                initialfile=f"CryptoAccess_Backup_{datetime.now().strftime('%Y%m%d_%H%M')}.cahbak",
            )
            if not destination:
                return
            try:
                result = create_encrypted_backup(Path(destination), password.get())
                audit(
                    self.session.username,
                    self.session.role,
                    "CREATE",
                    "ENCRYPTED_BACKUP",
                    details=Path(destination).name,
                    metadata=result,
                )
                messagebox.showinfo(
                    "Respaldo creado",
                    f"Paquete cifrado correctamente.\n\nSHA-384:\n{result['sha384']}",
                )
            except Exception as error:
                messagebox.showerror("Respaldo", str(error))

        def verify_backup_ui():
            source = filedialog.askopenfilename(
                filetypes=[("Respaldo CryptoAccess", "*.cahbak")]
            )
            if not source:
                return
            try:
                result = open_encrypted_backup(Path(source), password.get())
                audit(
                    self.session.username,
                    self.session.role,
                    "VERIFY",
                    "ENCRYPTED_BACKUP",
                    details=Path(source).name,
                    metadata=result,
                )
                messagebox.showinfo(
                    "Respaldo íntegro",
                    f"El paquete fue descifrado en memoria y verificado.\n\nSHA-384:\n{result['sha384']}",
                )
            except Exception as error:
                messagebox.showerror("Verificación", str(error))

        def extract_backup_ui():
            source = filedialog.askopenfilename(
                filetypes=[("Respaldo CryptoAccess", "*.cahbak")]
            )
            if not source:
                return
            destination = filedialog.askdirectory(title="Carpeta de recuperación")
            if not destination:
                return
            try:
                result = open_encrypted_backup(
                    Path(source),
                    password.get(),
                    Path(destination),
                )
                audit(
                    self.session.username,
                    self.session.role,
                    "RECOVER",
                    "ENCRYPTED_BACKUP",
                    details=Path(source).name,
                    severity="HIGH",
                    metadata={"output": Path(destination).name, **result},
                )
                messagebox.showinfo(
                    "Recuperación preparada",
                    "Los archivos se extrajeron en una carpeta separada para revisión controlada.",
                )
            except Exception as error:
                messagebox.showerror("Recuperación", str(error))

        self.action_button(buttons, "Crear respaldo", create_backup_ui, COLORS["green"]).pack(side=LEFT)
        self.action_button(buttons, "Verificar respaldo", verify_backup_ui, COLORS["cyan"]).pack(side=LEFT, padx=8)
        self.action_button(buttons, "Extraer para recuperación", extract_backup_ui, COLORS["purple"]).pack(side=LEFT)

        note = RoundedCard(self.content, fg_color="#FFF9EC")
        note.pack(fill=X, padx=12, pady=8)
        ctk.CTkLabel(
            note,
            text=(
                "Para un despliegue comercial se recomienda almacenamiento externo, "
                "copias fuera de línea, pruebas periódicas de restauración y custodia "
                "separada de material de recuperación."
            ),
            wraplength=1050,
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=18)




    def render_user_admin(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill=X, padx=10, pady=(8, 4))

        ctk.CTkLabel(
            header,
            text="Usuarios y roles",
            font=("Segoe UI", 21, "bold"),
            text_color=COLORS["text"],
        ).pack(side=LEFT)

        self.action_button(
            header,
            "Crear usuario",
            self.user_form,
            COLORS["blue"],
        ).pack(side=RIGHT)

        ctk.CTkLabel(
            parent,
            text=(
                "Gestione cuentas, roles, bloqueo y recuperación MFA desde este apartado. "
                "El auditor es único y permanece separado del administrador."
            ),
            wraplength=1000,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=12, pady=(0, 10))

        table_card = RoundedCard(
            parent,
            height=390,
        )
        table_card.pack(
            fill=X,
            padx=10,
            pady=(0, 10),
        )
        table_card.pack_propagate(False)

        columns = (
            "username",
            "name",
            "role",
            "mfa",
            "recovery",
            "active",
        )
        headings = (
            "Usuario",
            "Nombre",
            "Rol",
            "MFA",
            "Recuperación",
            "Estado",
        )
        widths = (
            165,
            250,
            145,
            110,
            120,
            105,
        )

        table_wrap = ctk.CTkFrame(
            table_card,
            fg_color="transparent",
        )
        table_wrap.pack(
            fill=BOTH,
            expand=True,
            padx=14,
            pady=14,
        )

        tree = ttk.Treeview(
            table_wrap,
            columns=columns,
            show="headings",
            height=13,
            style="Health.Treeview",
        )

        for column, heading, width in zip(
            columns,
            headings,
            widths,
        ):
            tree.heading(
                column,
                text=heading,
            )
            tree.column(
                column,
                width=width,
                minwidth=70,
                anchor="w",
            )

        vertical = ttk.Scrollbar(
            table_wrap,
            orient="vertical",
            command=tree.yview,
        )
        horizontal = ttk.Scrollbar(
            table_wrap,
            orient="horizontal",
            command=tree.xview,
        )

        tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        tree.grid(
            row=0,
            column=0,
            sticky="nsew",
        )
        vertical.grid(
            row=0,
            column=1,
            sticky="ns",
        )
        horizontal.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_wrap.grid_rowconfigure(
            0,
            weight=1,
        )
        table_wrap.grid_columnconfigure(
            0,
            weight=1,
        )

        def refresh():
            for item in tree.get_children():
                tree.delete(item)

            with db() as conn:
                rows = conn.execute(
                    "SELECT * FROM users ORDER BY id"
                ).fetchall()

            for row in rows:
                tree.insert(
                    "",
                    END,
                    iid=str(row["id"]),
                    values=(
                        row["username"],
                        row["full_name"],
                        self.role_label(row["role"]),
                        (
                            "Activo"
                            if row["mfa_enabled"]
                            and row["totp_secret_enc"]
                            and not row["mfa_reset_pending"]
                            else (
                                "Recuperación"
                                if row["mfa_reset_pending"]
                                else "Sin activar"
                            )
                        ),
                        (
                            "Sí"
                            if row["mfa_reset_pending"]
                            else "No"
                        ),
                        (
                            "Activo"
                            if row["active"]
                            else "Inactivo"
                        ),
                    ),
                )

        actions = RoundedCard(parent)
        actions.pack(
            fill=X,
            padx=10,
            pady=(0, 10),
        )

        ctk.CTkLabel(
            actions,
            text="Administración de acceso",
            font=("Segoe UI", 17, "bold"),
            text_color=COLORS["text"],
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 8),
        )

        ctk.CTkLabel(
            actions,
            text=(
                "Si una persona pierde o cambia el teléfono, el MFA no se elimina "
                "de forma permanente. Se revoca el secreto anterior y se genera "
                "un código temporal de recuperación para registrar Authy nuevamente."
            ),
            wraplength=1000,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 12),
        )

        buttons = ctk.CTkFrame(
            actions,
            fg_color="transparent",
        )
        buttons.pack(
            fill=X,
            padx=20,
            pady=(0, 18),
        )

        def selected_user():
            if not tree.selection():
                messagebox.showwarning(
                    "Usuario",
                    "Seleccione una cuenta.",
                )
                return None

            user_id = int(tree.selection()[0])

            with db() as conn:
                return conn.execute(
                    "SELECT * FROM users WHERE id=?",
                    (user_id,),
                ).fetchone()

        def reset_mfa():
            row = selected_user()
            if not row:
                return

            token = (
                secrets.token_urlsafe(8)
                .replace("-", "")
                .replace("_", "")[:12]
            )

            expires = (
                datetime.now() + timedelta(minutes=20)
            ).isoformat(timespec="seconds")

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET totp_secret_enc=NULL,
                        mfa_enabled=0,
                        last_totp_counter=NULL,
                        mfa_recovery_token_hash=?,
                        mfa_recovery_expires=?,
                        mfa_reset_pending=1
                    WHERE id=?
                    """,
                    (
                        ph.hash(token),
                        expires,
                        row["id"],
                    ),
                )

            audit(
                self.session.username,
                self.session.role,
                "RESET_MFA",
                "USER",
                str(row["id"]),
                details=(
                    f"MFA revocado para {row['username']}. "
                    "Se emitió recuperación temporal."
                ),
                severity="HIGH",
                metadata={
                    "target_user": row["username"],
                    "expires": expires,
                },
            )

            refresh()

            messagebox.showinfo(
                "Recuperación MFA",
                (
                    f"Se revocó el Authy anterior de {row['username']}.\n\n"
                    f"Código temporal de recuperación:\n{token}\n\n"
                    "Vence en 20 minutos. Entréguelo al usuario por un canal seguro. "
                    "El código solo se muestra una vez."
                ),
            )

        def unlock():
            row = selected_user()
            if not row:
                return

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts=0,
                        locked_until=NULL
                    WHERE id=?
                    """,
                    (row["id"],),
                )

            audit(
                self.session.username,
                self.session.role,
                "UNLOCK",
                "USER",
                str(row["id"]),
                details=f"Cuenta desbloqueada: {row['username']}",
            )

            messagebox.showinfo(
                "Cuenta",
                "La cuenta fue desbloqueada.",
            )

        def toggle_active():
            row = selected_user()
            if not row:
                return

            if row["role"] == "AUDITOR":
                messagebox.showwarning(
                    "Auditor",
                    "La cuenta del auditor único no puede desactivarse desde esta pantalla.",
                )
                return

            new_state = 0 if row["active"] else 1

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET active=?
                    WHERE id=?
                    """,
                    (
                        new_state,
                        row["id"],
                    ),
                )

            audit(
                self.session.username,
                self.session.role,
                (
                    "ACTIVATE"
                    if new_state
                    else "DEACTIVATE"
                ),
                "USER",
                str(row["id"]),
                details=f"Cuenta {row['username']} actualizada.",
                severity="HIGH",
            )

            refresh()

        self.action_button(
            buttons,
            "Restablecer MFA",
            reset_mfa,
            COLORS["orange"],
        ).pack(side=LEFT)

        self.action_button(
            buttons,
            "Desbloquear cuenta",
            unlock,
            COLORS["cyan"],
        ).pack(
            side=LEFT,
            padx=8,
        )

        self.action_button(
            buttons,
            "Activar / desactivar",
            toggle_active,
            COLORS["purple"],
        ).pack(side=LEFT)

        refresh()


    def page_users(self):
        """
        Se conserva únicamente como compatibilidad interna.
        La administración de usuarios ya no aparece en el menú principal.
        """
        self.clear_content()
        self.page_header(
            "Configuración",
            "Administración de usuarios, roles y accesos.",
        )
        self.render_user_admin(self.content)

    def user_form(self):
        role_dialog = ctk.CTkToplevel(self)
        role_dialog.title("Seleccionar rol")
        role_dialog.geometry("470x350")
        role_dialog.grab_set()

        frame = RoundedCard(role_dialog)
        frame.pack(fill=BOTH, expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            frame,
            text="Nuevo usuario",
            font=("Segoe UI", 23, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=26, pady=(28, 6))
        ctk.CTkLabel(
            frame,
            text="El auditor es único y se crea durante la configuración inicial.",
            wraplength=380,
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=26, pady=(0, 18))

        role = ctk.StringVar(value="DOCTOR")
        ctk.CTkComboBox(
            frame,
            variable=role,
            values=["DOCTOR", "RECEPTION", "IT", "ADMIN"],
            height=42,
            corner_radius=12,
        ).pack(fill=X, padx=26, pady=(0, 18))

        def continue_provision():
            selected = role.get()
            role_dialog.destroy()
            self.provision_user_dialog(
                selected,
                on_success=self.page_settings,
                title=f"Crear {self.role_label(selected)}",
            )

        self.action_button(
            frame,
            "Continuar con usuario, contraseña y MFA",
            continue_provision,
        ).pack(fill=X, padx=26, pady=(0, 26))



    def page_legal(self):
        self.clear_content()

        ctk.CTkLabel(
            self.content,
            text="Centro de privacidad y cumplimiento",
            font=("Segoe UI", 27, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=4, pady=(6, 1))

        ctk.CTkLabel(
            self.content,
            text=(
                "Políticas, normas, privacidad, incidentes, conservación, seguridad y condiciones de uso."
            ),
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=4, pady=(0, 8))

        # Altura fija amplia porque self.content es un CTkScrollableFrame.
        available_height = max(670, self.winfo_height() - 145)

        main = ctk.CTkFrame(
            self.content,
            fg_color="transparent",
            height=available_height,
        )
        main.pack(
            fill=X,
            expand=False,
            padx=4,
            pady=(0, 6),
        )
        main.pack_propagate(False)

        menu = RoundedCard(
            main,
            width=255,
        )
        menu.pack(
            side=LEFT,
            fill=Y,
            padx=(0, 8),
        )
        menu.pack_propagate(False)

        viewer = RoundedCard(main)
        viewer.pack(
            side=RIGHT,
            fill=BOTH,
            expand=True,
        )
        viewer.pack_propagate(False)

        top = ctk.CTkFrame(
            viewer,
            fg_color="transparent",
            height=78,
        )
        top.pack(fill=X, padx=22, pady=(16, 4))
        top.pack_propagate(False)

        title_container = ctk.CTkFrame(
            top,
            fg_color="transparent",
        )
        title_container.pack(
            side=LEFT,
            fill=BOTH,
            expand=True,
        )

        title_label = ctk.CTkLabel(
            title_container,
            text="",
            font=("Segoe UI", 22, "bold"),
            text_color=COLORS["text"],
            anchor="w",
        )
        title_label.pack(
            anchor="w",
            fill=X,
        )

        version_label = ctk.CTkLabel(
            title_container,
            text="",
            text_color=COLORS["muted"],
            anchor="w",
        )
        version_label.pack(
            anchor="w",
            fill=X,
            pady=(3, 0),
        )

        current_document = {
            "name": "",
            "version": "",
        }

        def accept():
            if not current_document["name"]:
                return

            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO legal_acceptance
                    (username,document_name,document_version,accepted_at)
                    VALUES(?,?,?,?)
                    """,
                    (
                        self.session.username,
                        current_document["name"],
                        current_document["version"],
                        now_iso(),
                    ),
                )

            audit(
                self.session.username,
                self.session.role,
                "ACCEPT",
                "LEGAL_DOCUMENT",
                current_document["name"],
            )

            messagebox.showinfo(
                "Aceptación registrada",
                "La lectura y aceptación quedaron registradas.",
            )

        ctk.CTkButton(
            top,
            text="Registrar lectura",
            width=145,
            height=38,
            corner_radius=12,
            fg_color=COLORS["green"],
            hover_color="#128455",
            command=accept,
        ).pack(side=RIGHT, padx=(12, 0), pady=4)

        text_box = ctk.CTkTextbox(
            viewer,
            height=available_height - 122,
            wrap="word",
            corner_radius=14,
            fg_color="#FCFDFE",
            text_color=COLORS["text"],
            border_width=1,
            border_color=COLORS["line"],
            font=("Segoe UI", 14),
            spacing1=7,
            spacing2=4,
            spacing3=10,
        )
        text_box.pack(
            fill=BOTH,
            expand=True,
            padx=22,
            pady=(0, 18),
        )

        ctk.CTkLabel(
            menu,
            text="Documentos",
            font=("Segoe UI", 18, "bold"),
            text_color=COLORS["text"],
        ).pack(
            anchor="w",
            padx=15,
            pady=(17, 8),
        )

        document_menu = ctk.CTkScrollableFrame(
            menu,
            fg_color="transparent",
            scrollbar_button_color="#CAD8EA",
            scrollbar_button_hover_color="#AFC2D9",
        )
        document_menu.pack(
            fill=BOTH,
            expand=True,
            padx=6,
            pady=(0, 10),
        )

        buttons = {}

        def show_document(name):
            item = LEGAL_DOCUMENTS[name]
            current_document["name"] = name
            current_document["version"] = item["version"]

            title_label.configure(text=name)
            version_label.configure(
                text=f"Versión {item['version']} | Documento vigente"
            )

            text_box.configure(state="normal")
            text_box.delete("1.0", END)
            text_box.insert(
                "1.0",
                item["text"].strip(),
            )
            text_box.configure(state="disabled")
            text_box.yview_moveto(0)

            for document_name, button in buttons.items():
                if document_name == name:
                    button.configure(
                        fg_color=COLORS["blue"],
                        hover_color="#0E63D8",
                        text_color="white",
                    )
                else:
                    button.configure(
                        fg_color="transparent",
                        hover_color="#EAF2FE",
                        text_color=COLORS["text"],
                    )

        for name in LEGAL_DOCUMENTS:
            button = ctk.CTkButton(
                document_menu,
                text=name,
                anchor="w",
                height=42,
                corner_radius=11,
                fg_color="transparent",
                hover_color="#EAF2FE",
                text_color=COLORS["text"],
                font=("Segoe UI", 11),
                command=lambda document=name: show_document(document),
            )
            button.pack(
                fill=X,
                padx=2,
                pady=2,
            )
            buttons[name] = button

        show_document(next(iter(LEGAL_DOCUMENTS)))


    def page_security(self):
        # Alias conservado para compatibilidad con versiones anteriores.
        self.page_settings()


    def page_settings(self):
        self.clear_content()
        self.page_header(
            "Configuración",
            "Cuenta, contraseña, MFA, seguridad y administración de accesos.",
        )

        self.update_idletasks()
        available_height = max(
            720,
            self.winfo_height() - 145,
        )

        with db() as conn:
            current = conn.execute(
                """
                SELECT *
                FROM users
                WHERE id=?
                """,
                (self.session.id,),
            ).fetchone()

        notebook = ctk.CTkTabview(
            self.content,
            height=available_height,
            corner_radius=16,
            fg_color=COLORS["card"],
            segmented_button_selected_color=COLORS["blue"],
            segmented_button_selected_hover_color="#0E63D8",
            segmented_button_unselected_color="#EAF2FE",
            segmented_button_unselected_hover_color="#D7E8FF",
            text_color=COLORS["text"],
        )
        notebook.pack(
            fill=X,
            padx=12,
            pady=(0, 12),
        )

        account_tab = notebook.add("Mi cuenta")
        security_tab = notebook.add("Seguridad")

        access_tab = None
        if self.session.role == "ADMIN":
            access_tab = notebook.add(
                "Administración de accesos"
            )

        # Cada pestaña utiliza su propio scroll para evitar que el CTkTabview
        # colapse dentro del contenedor principal desplazable.
        account_body = ctk.CTkScrollableFrame(
            account_tab,
            fg_color="transparent",
            corner_radius=0,
        )
        account_body.pack(
            fill=BOTH,
            expand=True,
            padx=6,
            pady=6,
        )

        security_body = ctk.CTkScrollableFrame(
            security_tab,
            fg_color="transparent",
            corner_radius=0,
        )
        security_body.pack(
            fill=BOTH,
            expand=True,
            padx=6,
            pady=6,
        )

        access_body = None
        if access_tab is not None:
            access_body = ctk.CTkScrollableFrame(
                access_tab,
                fg_color="transparent",
                corner_radius=0,
            )
            access_body.pack(
                fill=BOTH,
                expand=True,
                padx=6,
                pady=6,
            )

        # -------------------------------------------------------------
        # MI CUENTA
        # -------------------------------------------------------------
        profile = RoundedCard(account_body)
        profile.pack(
            fill=X,
            padx=10,
            pady=(10, 8),
        )

        ctk.CTkLabel(
            profile,
            text="Información de la cuenta",
            font=("Segoe UI", 19, "bold"),
            text_color=COLORS["text"],
        ).pack(
            anchor="w",
            padx=22,
            pady=(20, 10),
        )

        mfa_status = (
            "Activo"
            if current["mfa_enabled"]
            and current["totp_secret_enc"]
            and not current["mfa_reset_pending"]
            else (
                "Recuperación pendiente"
                if current["mfa_reset_pending"]
                else "Sin activar"
            )
        )

        account_rows = [
            (
                "Nombre",
                current["full_name"],
            ),
            (
                "Usuario",
                current["username"],
            ),
            (
                "Rol",
                self.role_label(
                    current["role"]
                ),
            ),
            (
                "MFA Authy",
                mfa_status,
            ),
            (
                "Estado",
                (
                    "Activo"
                    if current["active"]
                    else "Inactivo"
                ),
            ),
            (
                "Último cambio de contraseña",
                (
                    current["password_changed_at"]
                    or "No registrado"
                ),
            ),
        ]

        for label, value in account_rows:
            row_frame = ctk.CTkFrame(
                profile,
                fg_color="transparent",
            )
            row_frame.pack(
                fill=X,
                padx=22,
                pady=4,
            )

            ctk.CTkLabel(
                row_frame,
                text=label,
                width=220,
                anchor="w",
                font=("Segoe UI", 11, "bold"),
                text_color=COLORS["muted"],
            ).pack(side=LEFT)

            ctk.CTkLabel(
                row_frame,
                text=str(value),
                anchor="w",
                text_color=COLORS["text"],
            ).pack(
                side=LEFT,
                fill=X,
                expand=True,
            )

        ctk.CTkLabel(
            profile,
            text=(
                "El nombre de usuario y el rol se mantienen fijos para preservar "
                "la trazabilidad de las acciones realizadas en el sistema."
            ),
            wraplength=950,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(
            anchor="w",
            padx=22,
            pady=(12, 20),
        )

        password_card = RoundedCard(account_body)
        password_card.pack(
            fill=X,
            padx=10,
            pady=(0, 10),
        )

        ctk.CTkLabel(
            password_card,
            text="Cambiar contraseña",
            font=("Segoe UI", 19, "bold"),
            text_color=COLORS["text"],
        ).pack(
            anchor="w",
            padx=22,
            pady=(20, 10),
        )

        current_password = ctk.StringVar()
        new_password = ctk.StringVar()
        confirm_password = ctk.StringVar()

        for label, variable in [
            (
                "Contraseña actual",
                current_password,
            ),
            (
                "Nueva contraseña",
                new_password,
            ),
            (
                "Confirmar nueva contraseña",
                confirm_password,
            ),
        ]:
            ctk.CTkLabel(
                password_card,
                text=label,
                text_color=COLORS["text"],
            ).pack(
                anchor="w",
                padx=22,
            )

            ctk.CTkEntry(
                password_card,
                textvariable=variable,
                show="•",
                height=41,
                corner_radius=12,
            ).pack(
                fill=X,
                padx=22,
                pady=(5, 10),
            )

        def change_password():
            with db() as conn:
                row = conn.execute(
                    """
                    SELECT *
                    FROM users
                    WHERE id=?
                    """,
                    (self.session.id,),
                ).fetchone()

            try:
                ph.verify(
                    row["password_hash"],
                    current_password.get(),
                )
            except VerifyMismatchError:
                messagebox.showerror(
                    "Contraseña",
                    "La contraseña actual no es correcta.",
                )
                return

            ok, detail = validate_password(
                new_password.get()
            )

            if not ok:
                messagebox.showwarning(
                    "Contraseña",
                    detail,
                )
                return

            if (
                new_password.get()
                != confirm_password.get()
            ):
                messagebox.showwarning(
                    "Contraseña",
                    "Las nuevas contraseñas no coinciden.",
                )
                return

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET password_hash=?,
                        password_changed_at=?
                    WHERE id=?
                    """,
                    (
                        ph.hash(
                            new_password.get()
                        ),
                        now_iso(),
                        self.session.id,
                    ),
                )

            audit(
                self.session.username,
                self.session.role,
                "CHANGE_PASSWORD",
                "USER",
                str(self.session.id),
                details=(
                    "El usuario cambió su propia contraseña."
                ),
                severity="MEDIUM",
            )

            current_password.set("")
            new_password.set("")
            confirm_password.set("")

            messagebox.showinfo(
                "Contraseña",
                "La contraseña fue actualizada correctamente.",
            )

        self.action_button(
            password_card,
            "Actualizar contraseña",
            change_password,
            COLORS["blue"],
        ).pack(
            anchor="e",
            padx=22,
            pady=(5, 20),
        )

        # -------------------------------------------------------------
        # SEGURIDAD
        # -------------------------------------------------------------
        mfa_card = RoundedCard(security_body)
        mfa_card.pack(
            fill=X,
            padx=10,
            pady=(10, 8),
        )

        ctk.CTkLabel(
            mfa_card,
            text="Autenticación multifactor",
            font=("Segoe UI", 19, "bold"),
            text_color=COLORS["text"],
        ).pack(
            anchor="w",
            padx=22,
            pady=(20, 8),
        )

        mfa_active = bool(
            current["mfa_enabled"]
            and current["totp_secret_enc"]
            and not current["mfa_reset_pending"]
        )

        ctk.CTkLabel(
            mfa_card,
            text=(
                "Estado: "
                + (
                    "ACTIVO"
                    if mfa_active
                    else (
                        "RECUPERACIÓN PENDIENTE"
                        if current["mfa_reset_pending"]
                        else "PENDIENTE DE ACTIVAR"
                    )
                )
            ),
            font=("Segoe UI", 13, "bold"),
            text_color=(
                COLORS["green"]
                if mfa_active
                else COLORS["orange"]
            ),
        ).pack(
            anchor="w",
            padx=22,
            pady=(0, 7),
        )

        ctk.CTkLabel(
            mfa_card,
            text=(
                "Authy se configura después de crear la cuenta. "
                "Si todavía no lo ha activado, puede registrar su teléfono aquí. "
                "Si ya está activo, también puede reemplazar el dispositivo mientras "
                "todavía tenga acceso a la cuenta."
            ),
            wraplength=950,
            justify="left",
            text_color=COLORS["muted"],
        ).pack(
            anchor="w",
            padx=22,
            pady=(0, 14),
        )

        if not current["mfa_reset_pending"]:
            self.action_button(
                mfa_card,
                (
                    "Reconfigurar mi Authy"
                    if mfa_active
                    else "Activar Authy"
                ),
                self.reconfigure_own_mfa,
                COLORS["green"],
            ).pack(
                anchor="w",
                padx=22,
                pady=(0, 20),
            )
        else:
            ctk.CTkLabel(
                mfa_card,
                text=(
                    "El administrador inició una recuperación de MFA. "
                    "Complete el procedimiento desde la pantalla de inicio utilizando "
                    "el código temporal recibido."
                ),
                wraplength=900,
                justify="left",
                text_color=COLORS["orange"],
            ).pack(
                anchor="w",
                padx=22,
                pady=(0, 20),
            )

        session_card = RoundedCard(security_body)
        session_card.pack(
            fill=X,
            padx=10,
            pady=(0, 8),
        )

        ctk.CTkLabel(
            session_card,
            text="Controles de sesión",
            font=("Segoe UI", 19, "bold"),
            text_color=COLORS["text"],
        ).pack(
            anchor="w",
            padx=22,
            pady=(20, 10),
        )

        tls_ok, tls_detail = (
            self.tls_service.self_test()
        )

        controls = [
            (
                "Contraseña",
                "Argon2id y política de complejidad.",
                COLORS["green"],
            ),
            (
                "Bloqueo",
                "Cinco intentos fallidos producen un bloqueo temporal.",
                COLORS["blue"],
            ),
            (
                "TOTP",
                "Los códigos Authy aceptados no pueden reutilizarse.",
                COLORS["purple"],
            ),
            (
                "Sesión",
                "Cierre automático después del periodo de inactividad.",
                COLORS["orange"],
            ),
            (
                "TLS",
                (
                    "Canal interno verificado correctamente."
                    if tls_ok
                    else f"Incidencia: {tls_detail}"
                ),
                (
                    COLORS["green"]
                    if tls_ok
                    else COLORS["red"]
                ),
            ),
        ]

        for label, description, color in controls:
            line = ctk.CTkFrame(
                session_card,
                fg_color="#F8FAFD",
                corner_radius=11,
            )
            line.pack(
                fill=X,
                padx=22,
                pady=4,
            )

            ctk.CTkFrame(
                line,
                width=5,
                fg_color=color,
                corner_radius=3,
            ).pack(
                side=LEFT,
                fill=Y,
                padx=(8, 10),
                pady=8,
            )

            info = ctk.CTkFrame(
                line,
                fg_color="transparent",
            )
            info.pack(
                side=LEFT,
                fill=X,
                expand=True,
                pady=8,
            )

            ctk.CTkLabel(
                info,
                text=label,
                font=("Segoe UI", 11, "bold"),
                text_color=COLORS["text"],
                anchor="w",
            ).pack(fill=X)

            ctk.CTkLabel(
                info,
                text=description,
                text_color=COLORS["muted"],
                anchor="w",
                wraplength=850,
                justify="left",
            ).pack(fill=X)

        ctk.CTkFrame(
            session_card,
            fg_color="transparent",
            height=12,
        ).pack()

        # -------------------------------------------------------------
        # ADMINISTRACIÓN DE ACCESOS
        # -------------------------------------------------------------
        if access_body is not None:
            intro = RoundedCard(access_body)
            intro.pack(
                fill=X,
                padx=10,
                pady=(10, 8),
            )

            ctk.CTkLabel(
                intro,
                text="Administración de usuarios y accesos",
                font=("Segoe UI", 19, "bold"),
                text_color=COLORS["text"],
            ).pack(
                anchor="w",
                padx=22,
                pady=(20, 7),
            )

            ctk.CTkLabel(
                intro,
                text=(
                    "El administrador crea cuentas, asigna roles, desbloquea usuarios "
                    "y gestiona la recuperación de Authy desde esta misma pestaña. "
                    "La bitácora detallada continúa reservada exclusivamente para el auditor."
                ),
                wraplength=950,
                justify="left",
                text_color=COLORS["muted"],
            ).pack(
                anchor="w",
                padx=22,
                pady=(0, 18),
            )

            self.render_user_admin(
                access_body
            )

            separation = RoundedCard(
                access_body
            )
            separation.pack(
                fill=X,
                padx=10,
                pady=(0, 12),
            )

            ctk.CTkLabel(
                separation,
                text="Separación administrador / auditor",
                font=("Segoe UI", 19, "bold"),
                text_color=COLORS["text"],
            ).pack(
                anchor="w",
                padx=22,
                pady=(20, 8),
            )

            ctk.CTkLabel(
                separation,
                text=(
                    "El administrador controla cuentas, MFA, claves, certificados "
                    "y respaldos. El auditor es una cuenta única dedicada a revisar "
                    "la bitácora criptográfica, evitando que una misma cuenta administre "
                    "el sistema y audite sus propias acciones."
                ),
                wraplength=950,
                justify="left",
                text_color=COLORS["text"],
            ).pack(
                anchor="w",
                padx=22,
                pady=(0, 20),
            )


    def reconfigure_own_mfa(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Configurar Authy")
        dialog.geometry("590x680")
        dialog.grab_set()

        frame = ctk.CTkScrollableFrame(
            dialog,
            fg_color=COLORS["bg"],
        )
        frame.pack(fill=BOTH, expand=True)

        ctk.CTkLabel(
            frame,
            text="Configurar Authy",
            font=("Segoe UI", 24, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=28, pady=(26, 6))

        ctk.CTkLabel(
            frame,
            text=(
                "Confirme su contraseña. Luego escanee el QR con Authy y valide el código temporal."
            ),
            wraplength=520,
            text_color=COLORS["muted"],
        ).pack(anchor="w", padx=28, pady=(0, 15))

        password = ctk.StringVar()
        code = ctk.StringVar()

        ctk.CTkEntry(
            frame,
            textvariable=password,
            show="•",
            placeholder_text="Contraseña actual",
            height=42,
            corner_radius=12,
        ).pack(fill=X, padx=28, pady=(0, 15))

        qr_holder = ctk.CTkFrame(
            frame,
            fg_color="transparent",
        )
        qr_holder.pack(fill=X, padx=28)

        state = {
            "secret": None,
            "qr_path": None,
            "image": None,
        }

        def begin():
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE id=?",
                    (self.session.id,),
                ).fetchone()

            try:
                ph.verify(
                    row["password_hash"],
                    password.get(),
                )
            except VerifyMismatchError:
                messagebox.showerror(
                    "Contraseña",
                    "La contraseña no es correcta.",
                )
                return

            for widget in qr_holder.winfo_children():
                widget.destroy()

            secret = pyotp.random_base32()
            qr_path = DATA_DIR / f"own_mfa_{uuid.uuid4().hex}.png"
            uri = pyotp.TOTP(secret).provisioning_uri(
                name=self.session.username,
                issuer_name=APP_NAME,
            )
            qrcode.make(uri).save(qr_path)

            image = ctk.CTkImage(
                Image.open(qr_path),
                size=(220, 220),
            )

            state.update(
                {
                    "secret": secret,
                    "qr_path": qr_path,
                    "image": image,
                }
            )

            ctk.CTkLabel(
                qr_holder,
                image=image,
                text="",
            ).pack()

            ctk.CTkLabel(
                qr_holder,
                text=(
                    "Escanee el QR con Authy. Si ya tenía MFA configurado, el secreto anterior "
                    "seguirá siendo válido hasta que confirme el nuevo código."
                ),
                wraplength=500,
                text_color=COLORS["muted"],
            ).pack(pady=(5, 8))

            ctk.CTkEntry(
                qr_holder,
                textvariable=code,
                placeholder_text="Código del nuevo Authy",
                height=42,
                corner_radius=12,
            ).pack(fill=X)

            confirm_button.pack(
                fill=X,
                padx=28,
                pady=(10, 24),
            )

        def confirm():
            if not state["secret"]:
                return

            activation_ok, activation_counter, activation_detail = (
                verify_totp_secret(
                    state["secret"],
                    code.get(),
                    last_counter=None,
                    valid_window=1,
                )
            )

            if not activation_ok:
                messagebox.showerror(
                    "Authy",
                    activation_detail,
                )
                return

            encrypted_secret = encrypt_text(
                state["secret"].strip()
            )

            # Verificación de ida y vuelta antes de persistir:
            # el mismo secreto se cifra, descifra y vuelve a validar.
            recovered_secret = decrypt_text(
                encrypted_secret
            ).strip()

            roundtrip_ok, _, roundtrip_detail = verify_totp_secret(
                recovered_secret,
                code.get(),
                last_counter=None,
                valid_window=1,
            )

            if not roundtrip_ok:
                messagebox.showerror(
                    "Authy",
                    "No fue posible validar el secreto MFA después de cifrarlo. "
                    + roundtrip_detail,
                )
                return

            with db() as conn:
                conn.execute(
                    """
                    UPDATE users
                    SET totp_secret_enc=?,mfa_enabled=1,
                        last_totp_counter=NULL,
                        mfa_reset_pending=0,
                        mfa_recovery_token_hash=NULL,
                        mfa_recovery_expires=NULL
                    WHERE id=?
                    """,
                    (
                        encrypted_secret,
                        self.session.id,
                    ),
                )

            audit(
                self.session.username,
                self.session.role,
                "RECONFIGURE_MFA",
                "USER",
                str(self.session.id),
                details="El usuario activó o reconfiguró su propio Authy.",
                severity="HIGH",
                metadata={
                    "mfa": "enabled",
                    "activation_counter": activation_counter,
                    "secret_roundtrip": "verified",
                },
            )

            if state["qr_path"]:
                Path(state["qr_path"]).unlink(missing_ok=True)

            messagebox.showinfo(
                "Authy",
                "Authy quedó configurado correctamente. El estado ahora está ACTIVO.",
            )
            dialog.destroy()

            # Volver a consultar la base de datos y reconstruir Configuración
            # para reflejar inmediatamente mfa_enabled=1.
            self.after(
                150,
                self.page_settings,
            )

        self.action_button(
            frame,
            "Confirmar contraseña",
            begin,
            COLORS["blue"],
        ).pack(fill=X, padx=28, pady=(0, 12))

        confirm_button = self.action_button(
            frame,
            "Activar nuevo Authy",
            confirm,
            COLORS["green"],
        )

    def page_about(self):
        self.clear_content()
        self.page_header("Acerca del producto", f"{APP_NAME} | {VERSION}")

        card = RoundedCard(self.content)
        card.pack(fill=X, padx=12, pady=8)

        ctk.CTkLabel(card, image=self.logo_large, text="").pack(pady=(20, 0))
        ctk.CTkLabel(
            card,
            text=(
                f"{APP_NAME} es un producto académico avanzado desarrollado por {COMPANY}. "
                "Integra gestión de pacientes, expedientes clínicos cifrados, citas, recordatorios, "
                "roles, MFA con Authy, auditoría encadenada, documentos protegidos mediante "
                "criptografía híbrida y un centro legal completo.\n\n"
                "Esta edición implementa usuario, contraseña y MFA de acceso, TLS con PKI interna, "
                "certificados X.509, firmas digitales, revocación y reprotección. "
                "Antes de tratar información real todavía requiere revisión jurídica independiente, "
                "pruebas de penetración, infraestructura cliente-servidor empresarial, "
                "respaldo validado, alta disponibilidad y validación clínica."
            ),
            wraplength=980,
            justify="left",
            text_color=COLORS["text"],
            font=("Segoe UI", 13),
        ).pack(anchor="w", padx=34, pady=(10, 30))


if __name__ == "__main__":
    HealthApp().mainloop()
