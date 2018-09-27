import json
import base64

import requests

from OpenSSL import crypto
from certvalidator import CertificateValidator
from jwcrypto import jws, jwk


_attestation_url = "https://www.googleapis.com/androidcheck/v1/attestations/verify?key="


class InvalidJWSBodyException(Exception):
    @classmethod
    def no_match_exc(cls, item, v1=None, v2=None):
        if v1 and v2:
            message = "%s doesn't match (%s != %s)." % (item, v1, v2)
        else:
            message = "%s doesn't match any variants." % item

        return cls(message)

    @classmethod
    def missing_exc(cls, item):
        return cls("%s missing or False." % item)


class Attestation:
    jws_token = ""

    header = None
    body = None
    certificates = []
    public_key_pem = ""

    def __init__(self, jws_token):
        self.jws_token = jws_token

    def verify_online(self, api_key, url=_attestation_url):
        r = requests.post(url + api_key, json={"signedAttestation": self.jws_token})

        return r.json()["isValidSignature"]

    def _get_json_at_index(self, index):
        data = self.jws_token.split(".")[index]

        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += '=' * (4 - missing_padding)

        return json.loads(base64.b64decode(data).decode())

    def _get_certificates(self):
        if self.header is None:
            self.header = self._get_json_at_index(0)

        return [base64.b64decode(c) for c in self.header["x5c"]]

    def _get_public_key(self, certificate_index):
        crt_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, self.certificates[certificate_index])

        return crypto.dump_publickey(crypto.FILETYPE_PEM, crt_obj.get_pubkey())

    def _verify_certificates(self, hostname):
        validator = CertificateValidator(self.certificates[0], self.certificates[1:])
        validator.validate_tls(hostname)

    def _verify_hash(self):
        key = jwk.JWK.from_pem(self.public_key_pem)

        verifier = jws.JWS()
        verifier.deserialize(self.jws_token)
        verifier.verify(key)

    def _get_apkCertificateDigestSha256(self):
        if self.body is None:
            self.body = self._get_json_at_index(1)

        return base64.b64decode(self.body["apkCertificateDigestSha256"][0])

    def _verify_apkCertificateDigestSha256(self, apkCertificateDigestSha256):
        apkCertificateDigestSha256 = [bytes.fromhex(fp.replace(":", "")) for fp in apkCertificateDigestSha256]
        to_verify = self._get_apkCertificateDigestSha256()

        for fp in apkCertificateDigestSha256:
            if fp == to_verify:
                return True
        return False

    def _verify_body(self, apkPackageName, apkDigestSha256, apkCertificateDigestSha256,
                     check_basicIntegrity, check_ctsProfileMatch):
        if check_basicIntegrity and not self.body.get("basicIntegrity", False):
            raise InvalidJWSBodyException.missing_exc("basicIntegrity")

        if check_ctsProfileMatch and not self.body.get("ctsProfileMatch", False):
            raise InvalidJWSBodyException.missing_exc("ctsProfileMatch")

        if apkPackageName is not None and apkPackageName != self.body["apkPackageName"]:
            raise InvalidJWSBodyException.no_match_exc("apkPackageName",
                                                       apkPackageName, self.body["apkPackageName"])

        if apkDigestSha256 is not None and apkDigestSha256 != self.body["apkDigestSha256"]:
            raise InvalidJWSBodyException.no_match_exc("apkDigestSha256",
                                                       apkDigestSha256, self.body["apkDigestSha256"])

        if apkCertificateDigestSha256 is not None:
            if type(apkCertificateDigestSha256) == str:
                apkCertificateDigestSha256 = [apkCertificateDigestSha256]

            if not self._verify_apkCertificateDigestSha256(apkCertificateDigestSha256):
                raise InvalidJWSBodyException.no_match_exc("apkCertificateDigestSha256")

    def verify_offline(self, hostname="attest.android.com", apkPackageName=None, apkDigestSha256=None,
                       apkCertificateDigestSha256=None, check_basicIntegrity=True, check_ctsProfileMatch=True):
        self.header = self._get_json_at_index(index=0)
        self.body = self._get_json_at_index(index=1)
        self.certificates = self._get_certificates()
        self.public_key_pem = self._get_public_key(certificate_index=0)

        self._verify_certificates(hostname=hostname)
        self._verify_hash()
        self._verify_body(apkPackageName, apkDigestSha256, apkCertificateDigestSha256, check_basicIntegrity,
                          check_ctsProfileMatch)
