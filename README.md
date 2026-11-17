# license_guard.py
pip install cryptography
import base64
import datetime
import json
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
# --- 1. KEY GENERATION (Run once offline to create your signing keys) ---
def generate_keypair():
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  priv_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
encryption_algorithm=serialization.NoEncryption(),)
  pub_pem = private_key.public_key().public_bytes(
  encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo,)
  return priv_pem, pub_pem
# --- 2. LICENSE ISSUER (Run by you to issue a customer certificate) ---
def issue_license(
    priv_pem: bytes, licensee: str, hardware_id: str, expires_iso: str
) -> str:
  if not licensee or not hardware_id or not expires_iso:
    raise ValueError("License fields cannot be empty or null.")

  payload = {
      "licensee": licensee,
      "hardware_id": hardware_id,
      "expires_at": expires_iso,
      "terms": (
          "PROPRIETARY COMMERCIAL LICENSE. Unauthorized use, null-value bypass,"
          " or deployment on unincorporated hardware is strictly prohibited."
      ),
  }
  # Canonical JSON serialization ensures exact byte-for-byte signature matching
  payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

  private_key = serialization.load_pem_private_key(priv_pem, password=None)
  signature = private_key.sign(
      payload_bytes,
      padding.PSS(
          mgf=padding.MGF1(hashes.SHA256()),
          salt_length=padding.PSS.MAX_LENGTH,
      ),
      hashes.SHA256(),
  )

  certificate = {
      "payload": payload,
      "signature": base64.b64encode(signature).decode("utf-8"),
  }
  return json.dumps(certificate, indent=2)


# --- 3. FAIL-CLOSED VERIFIER (Embedded in your application startup) ---
def verify_license_or_exit(
    cert_json: str, pub_pem: bytes, current_hardware_id: str
):
  try:
    if not cert_json or cert_json.strip().lower() == "null":
      raise ValueError("License certificate is missing or null.")
 cert = json.loads(cert_json)
    if not isinstance(cert, dict):
      raise ValueError("Invalid certificate structure.")
payload = cert.get("payload")
    sig_b64 = cert.get("signature")
# Reject null or missing payload/signature immediately
if not isinstance(payload, dict) or not isinstance(sig_b64, str):  raise ValueError("Payload or signature is null or malformed.")
# Reject null values inside any required claim
   required_fields = ("licensee", "hardware_id", "expires_at", "terms")
    for field in required_fields:
      val = payload.get(field)
      if not isinstance(val, str) or not val.strip() or val.lower() == "null":
        raise ValueError(
            f"Required field '{field}' is missing, empty, or null."
        )
   # Verify cryptographic signature against embedded public key
   public_key = serialization.load_pem_public_key(pub_pem)
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = base64.b64decode(sig_b64)

 public_key.verify(
        signature,
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
          salt_length=padding.PSS.MAX_LENGTH  ),
        hashes.SHA256(),
    )# Enforce hardware binding
  if payload["hardware_id"] != current_hardware_id:
   raise ValueError(
    f"Hardware mismatch: expected '{payload['hardware_id']}', got"
          f" '{current_hardware_id}'.)
  # Enforce expiration date
expires_at=datetime.datetime.fromisoformat(payload["expires_at"])
  now=datetime.datetime.now(datetime.timezone.utc)
    if now >= expires_at:
      raise ValueError(f"License expired on {payload['expires_at']}.")
  print(f"License verified for: {payload['licensee']}" except (InvalidSignature, ValueError, KeyError, json.JSONDecodeError) as exc:
    print(f"FATAL LICENSE VIOLATION: {exc}", file=sys.stderr)
    sys.exit(1)
if __name__ == "__main__":
  priv_key, pub_key = generate_keypair()
# Issue a valid certificate bound to a specific motherboard/machine ID
  valid_cert = issue_license(
      priv_pem=priv_key,
      licensee="Authorized Manufacturing Partner LLC", hardware_id="MB-SERIAL-99887766",
      expires_iso="2027-01-01T00:00:00+00:00",)
  # Application startup check (succeeds)
  verify_license_or_exit(valid_cert, pub_key, "MB-SERIAL-99887766")
 # Simulated tampering or 'null' bypass attempt (exits with code 1)
  verify_license_or_exit("null", pub_key, "MB-SERIAL-99887766")
