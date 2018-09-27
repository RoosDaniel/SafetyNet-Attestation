# SafetyNet-Attestation

A package for verifying JWS-attestations from Google's SafetyNet


## Usage

```python
from safetynet_attestation import Attestation


attestation = Attestation(<jws_token>)
attestation.verify_offline()
```
