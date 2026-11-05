r"""
Pruebas automáticas de CryptoAccess Health Secure 3.0.
Ejecutar después de instalar las dependencias:

    .\venv\Scripts\python.exe pruebas_criptograficas.py
"""
from pathlib import Path
import secrets
import tempfile

import main


def result(name, ok, detail):
    mark = "OK" if ok else "ERROR"
    print(f"[{mark}] {name}: {detail}")
    return 1 if ok else 0


def run():
    main.ensure_dirs()
    main.initialize_database()
    main.ensure_internal_ca()
    key_id = main.ensure_active_rsa_key()

    passed = 0
    total = 0

    total += 1
    mfa_secret = main.pyotp.random_base32()
    mfa_totp = main.pyotp.TOTP(mfa_secret)
    mfa_code = mfa_totp.now()

    encrypted_mfa_secret = main.encrypt_text(mfa_secret)
    recovered_mfa_secret = main.decrypt_text(encrypted_mfa_secret)

    mfa_ok, mfa_counter, mfa_detail = main.verify_totp_secret(
        recovered_mfa_secret,
        mfa_code,
        last_counter=None,
        valid_window=1,
    )
    passed += result(
        "MFA Authy TOTP",
        mfa_ok and mfa_counter is not None,
        mfa_detail,
    )

    total += 1
    cert_ok, cert_detail = main.verify_certificate_for_key(key_id)
    passed += result("Certificado X.509", cert_ok, cert_detail)

    total += 1
    sample = secrets.token_bytes(256)
    signature, signing_key = main.rsa_sign_sha384(sample)
    sign_ok = main.rsa_verify_sha384(sample, signature, signing_key)
    passed += result("Firma RSA-3072-PSS", sign_ok, signing_key)

    total += 1
    aes_key = main.AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    encrypted = main.AESGCM(aes_key).encrypt(nonce, sample, b"TEST")
    decrypted = main.AESGCM(aes_key).decrypt(nonce, encrypted, b"TEST")
    passed += result("AES-256-GCM", decrypted == sample, "cifrado y descifrado correctos")

    total += 1
    service = main.SecureTLSService()
    service.start()
    tls_ok, tls_detail = service.self_test()
    service.stop()
    passed += result("TLS y anti-repetición", tls_ok, tls_detail)

    with tempfile.TemporaryDirectory() as temp:
        temp_dir = Path(temp)
        source = temp_dir / "evidencia.txt"
        source.write_text("Documento clínico de prueba", encoding="utf-8")

        total += 1
        package = main.create_secure_document_package(
            source,
            None,
            "Prueba automática",
            "AUTOMATED_TEST",
        )
        restored = temp_dir / "restaurado.txt"
        manifest = main.verify_and_open_secure_document(
            Path(package["package_path"]),
            restored,
        )
        document_ok = restored.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
        passed += result(
            "Paquete híbrido .cahs",
            document_ok,
            f"SHA-384 {manifest['plaintext_sha384'][:24]}...",
        )
        Path(package["package_path"]).unlink(missing_ok=True)

        total += 1
        backup = temp_dir / "test.cahbak"
        created = main.create_encrypted_backup(backup, "BackupStrong#2026")
        verified = main.open_encrypted_backup(backup, "BackupStrong#2026")
        backup_ok = created["sha384"] == verified["sha384"]
        passed += result("Respaldo PBKDF2 + AES", backup_ok, created["sha384"][:24] + "...")

    total += 1
    chain_ok, chain_detail, count = main.verify_audit_chain()
    passed += result("Cadena de auditoría SHA-384", chain_ok, f"{chain_detail} Eventos: {count}")

    print()
    print(f"Resultado: {passed}/{total} pruebas superadas.")
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    run()
