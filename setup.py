import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pySafetyNet-Attestation",
    version="0.0.2",
    author="Daniel Roos",
    author_email="daniel@roos.io",
    description="Verify JWS-attestations from Google's SafetyNet.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RoosDaniel/SafetyNet-Attestation",
    packages=setuptools.find_packages(),
    install_requires=[
        "pyOpenSSL",
        "certvalidator",
        "jwcrypto"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
