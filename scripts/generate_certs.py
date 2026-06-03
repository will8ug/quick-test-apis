#!/usr/bin/env python3
"""Generate test certificates for mTLS testing.

Creates a certs/ directory with:
  - CA certificate and key
  - Server certificate and key (signed by CA)
  - Client certificate and key (signed by CA)
  - Encrypted client key (with passphrase)
  - PFX/P12 bundle of client cert
  - A separate "untrusted" CA + client cert (for rejection testing)

Usage:
    uv run python scripts/generate_certs.py
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"
PASSPHRASE = b"test-passphrase"


def generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_ca(name: str, cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def build_leaf(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    cn: str,
    san_dns: list[str] | None = None,
    is_client: bool = False,
    is_server: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Quick Test APIs"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )
    if is_server:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    if is_client:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, key


def save_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def save_key(
    key: rsa.RSAPrivateKey,
    path: Path,
    password: bytes | None = None,
) -> None:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, enc)
    )


def save_pfx(
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    path: Path,
    password: bytes | None = None,
) -> None:
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"client",
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption(),
    )
    path.write_bytes(pfx_data)


def main() -> None:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- Trusted CA ---
    ca_cert, ca_key = build_ca("Quick Test CA", "Quick Test Root CA")
    save_cert(ca_cert, CERTS_DIR / "ca.crt")
    save_key(ca_key, CERTS_DIR / "ca.key")
    print(f"  CA cert: {CERTS_DIR / 'ca.crt'}")

    # --- Server cert (for localhost) ---
    server_cert, server_key = build_leaf(
        ca_cert, ca_key, "localhost",
        san_dns=["localhost"],
        is_server=True,
    )
    save_cert(server_cert, CERTS_DIR / "server.crt")
    save_key(server_key, CERTS_DIR / "server.key")
    print(f"  Server cert: {CERTS_DIR / 'server.crt'}")

    # --- Client cert (trusted) ---
    client_cert, client_key = build_leaf(
        ca_cert, ca_key, "test-client",
        is_client=True,
    )
    save_cert(client_cert, CERTS_DIR / "client.crt")
    save_key(client_key, CERTS_DIR / "client.key")
    print(f"  Client cert: {CERTS_DIR / 'client.crt'}")

    # --- Encrypted client key (with passphrase) ---
    save_key(client_key, CERTS_DIR / "client-encrypted.key", password=PASSPHRASE)
    print(f"  Encrypted client key: {CERTS_DIR / 'client-encrypted.key'}  (passphrase: {PASSPHRASE.decode()})")

    # --- PFX/P12 bundle ---
    save_pfx(client_cert, client_key, ca_cert, CERTS_DIR / "client.p12", password=PASSPHRASE)
    print(f"  Client PFX: {CERTS_DIR / 'client.p12'}  (passphrase: {PASSPHRASE.decode()})")

    # --- Untrusted CA + client cert ---
    untrusted_ca_cert, untrusted_ca_key = build_ca("Untrusted CA", "Untrusted Root CA")
    save_cert(untrusted_ca_cert, CERTS_DIR / "untrusted-ca.crt")
    save_key(untrusted_ca_key, CERTS_DIR / "untrusted-ca.key")

    untrusted_client_cert, untrusted_client_key = build_leaf(
        untrusted_ca_cert, untrusted_ca_key, "untrusted-client",
        is_client=True,
    )
    save_cert(untrusted_client_cert, CERTS_DIR / "untrusted-client.crt")
    save_key(untrusted_client_key, CERTS_DIR / "untrusted-client.key")
    print(f"  Untrusted client cert: {CERTS_DIR / 'untrusted-client.crt'}")

    print("\nAll certificates generated successfully!")
    print(f"Output directory: {CERTS_DIR}")


if __name__ == "__main__":
    main()
