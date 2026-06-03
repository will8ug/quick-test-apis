"""mTLS test API routes.

These endpoints are served by the mTLS HTTPS server (run_mtls.py).
They extract client certificate info from the TLS connection
to help verify httptui's client certificate feature.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/mtls", tags=["mTLS"])


def _get_peer_cert_info(request: Request) -> dict | None:
    """Extract client certificate info from request state (set by middleware)."""
    return getattr(request.state, "peer_cert", None)


@router.get("/echo-cert")
async def echo_client_cert(request: Request):
    """Return the client certificate details.

    The server REQUIRES a valid client certificate (signed by the test CA).
    If the client cert is missing or untrusted, the TLS handshake fails
    before this endpoint is reached.
    """
    cert_info = _get_peer_cert_info(request)
    if cert_info is None:
        return JSONResponse(
            status_code=400,
            content={"error": "No client certificate presented"},
        )
    return {
        "message": "Client certificate verified successfully",
        "client_certificate": cert_info,
    }


@router.get("/optional")
async def optional_client_cert(request: Request):
    """Work with or without a client certificate.

    Returns cert details if presented, or a message indicating no cert.
    Useful for testing that httptui correctly sends (or doesn't send) certs.
    """
    cert_info = _get_peer_cert_info(request)
    if cert_info is None:
        return {
            "message": "No client certificate presented",
            "client_certificate": None,
        }
    return {
        "message": "Client certificate detected",
        "client_certificate": cert_info,
    }


@router.get("/verify")
async def verify_client_cert(request: Request):
    """Verify the client certificate and return validation details.

    Checks that the client cert is:
    - Present
    - Signed by the trusted CA
    - Not expired
    - Has clientAuth extended key usage
    """
    cert_info = _get_peer_cert_info(request)
    if cert_info is None:
        return JSONResponse(
            status_code=403,
            content={"error": "Client certificate required"},
        )

    return {
        "verified": True,
        "client_certificate": cert_info,
        "tls_version": getattr(request.state, "tls_version", "unknown"),
        "cipher": getattr(request.state, "cipher", "unknown"),
    }


@router.get("/headers")
async def echo_headers(request: Request):
    """Echo back all request headers.

    Useful for verifying that httptui sends the correct headers
    when making mTLS requests.
    """
    headers = dict(request.headers)
    return {
        "headers": headers,
        "client_certificate": _get_peer_cert_info(request),
    }
