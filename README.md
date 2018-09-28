# pySafetyNet-Attestation

A package for verifying JWS-attestations from Google's SafetyNet.

## Introduction

This package verifies [SafetyNet attestations](https://developer.android.com/training/safetynet/) by following the steps described on the page. It allows you to specify what parts of the JWS-body you wish to verify, but will always atleast verify the certificate and validity of the JWS.


## Usage

### Online verification

```python
from safetynet_attestation import Attestation

jws_token = "..."
api_key = "..."

attestation = Attestation(jws_token)
attestation.verify_online(api_key)
```

**`verify_online` takes the following optional parameters:**

* `url="<standard url>"`: If you for some reason wish to validate against some other url.

`<standard url>` can be found at [Google's SafetyNet documentation](https://developer.android.com/training/safetynet/).

### Offline verification

```python
from safetynet_attestation import Attestation


jws_token = "..."

attestation = Attestation(jws_token)
attestation.verify_offline()
```

**`verify_offline` takes the following optional parameters:**

* `apkPackageName=None`

* `nonce=None`

* `apkDigestSha256=None`
	* `str` of hex-values.

* `apkCertificateDigestSha256=None`
	* Can be `list` of `str` or `str`.

* `check_basicIntegrity=True`

* `check_ctsProfileMatch=True`

* `hostname="attest.android.com"`
	* Used for TLS validation of the certificate. Only modify if you know what you are doing.

A full explanation of the parameters above can be found at [Google's SafetyNet documentation](https://developer.android.com/training/safetynet/)

Once a token has been verified, the following fields can be used:

* `header`
	* A `dict`of the token's header.

* `body`
	* A `dict` of the token's body.

* `certificates`
	* A `list`of base64-decoded certificates present in the `header`.

* `public_key_pem`
	* The public key of the certificate.