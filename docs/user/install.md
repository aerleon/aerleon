# Installation

## Prerequisites
* [Python 3.7+](https://www.python.org/downloads/)
  * If your system Python does not meet that requirement you can leverage [pyenv](https://github.com/pyenv/pyenv) to maintain one or more Python versions that can be set on a per directory basis.
* [pip](https://pip.pypa.io/en/stable/getting-started/)

**_NOTE:_** It is recommended to use a virtual environment such as the Python built-in [venv](https://docs.python.org/3/library/venv.html) module or the [virtualenv](https://virtualenv.pypa.io/en/latest/) package. 

Option 1: Install from PyPI.

```bash
$ pip install aerleon
```

Option 2: Install from a GitHub branch, such as main as shown below.

```bash
$ pip install git+https://github.com/aerleon/aerleon.git@main
```

At this point you should be able to verify `aclgen` was installed. The path may be different for you depending on your environment.

```bash
which aclgen
/home/rob/.cache/pypoetry/virtualenvs/aerleon-1XT7bGG2-py3.10/bin/aclgen
```
If you do not see a path it is possible the installation did not work successfully. Please reach out to us by filing an [issue](https://github.com/aerleon/aerleon/issues)


## Verifying Installation

At each release we sign build artifacts with [Sigstore](https://www.sigstore.dev/) to allow for validation [SLSA](https://slsa.dev/) file to help provide integrity from supply chain attacks. The instructions provided here will work on most linux distributions. Windows may require a different but comparable tool listed in the prerequisites and modifications to the instructions. Some of the tools may already be installed, if not they are likely available via your package management system.

## Prerequisites
- [openssl](https://github.com/openssl/openssl)
- [jq](https://stedolan.github.io/jq/manual/)
- [curl](https://curl.se/)
- [base64](https://github.com/coreutils/gnulib/blob/master/lib/base64.c)

## Instructions
1. Download the `whl`, `whl.crt`, `whl.sig`, and `jsonl` files from the latest release
```bash
REPO="aerleon/aerleon"
VER=$(curl --silent -qI https://github.com/$REPO/releases/latest |
      awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}');
wget https://github.com/$REPO/releases/download/$VER/provenance-sigstore-$VER.intoto.jsonl
wget https://github.com/$REPO/releases/download/$VER/aerleon-$VER-py3-none-any.whl
wget https://github.com/$REPO/releases/download/$VER/aerleon-$VER-py3-none-any.whl.crt
wget https://github.com/$REPO/releases/download/$VER/aerleon-$VER-py3-none-any.whl.sig
wget https://github.com/$REPO/releases/download/$VER/aerleon-$VER-py3-none-any.whl.rekor
```


2. Inspect the certificate
```bash
openssl x509 -in aerleon-0.0.0-py3-none-any.whl.crt -text -noout
```
We use OpenID to sign our code, the keys should be ephemeral and thus short lived.
```bash
        Validity
            Not Before: Jan  4 06:52:20 2023 GMT
            Not After : Jan  4 07:02:20 2023 GMT
```
This section tells you information about the origin of the certificate. It should match our repo. More information about each OID can be found at [sigstore](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
```bash
URI: fill me in
            1.3.6.1.4.1.57264.1.1: 
                https://token.actions.githubusercontent.com
            1.3.6.1.4.1.57264.1.2: 
                release
            1.3.6.1.4.1.57264.1.3: 
                fill me in
            1.3.6.1.4.1.57264.1.4: 
                Release
            1.3.6.1.4.1.57264.1.5: 
                fill me in
            1.3.6.1.4.1.57264.1.6: 
                fill me in
```

3. Extract the public key from the certificate.
```bash
openssl x509 -pubkey -noout -in aerleon-0.0.0-py3-none-any.whl.crt  > public.pem
cat public.pem 
-----BEGIN PUBLIC KEY-----
fooooooooooo
-----END PUBLIC KEY----
```

4. Get the log index from the rekor file
```bash
cat foooo.whl.rekor | jq '.Payload.logIndex'
```

5. Compare the certificates published in Rekor to the certificate we provide.
```bash
curl https://rekor.sigstore.dev/api/v1/log/entries/?logIndex=10441108 | jq -r '.[].body' | base64 -d | jq -r '.[]' | tail -n +3 | jq -r '.signature.publicKey.content' | (base64 -d && echo "") | diff foo-0.1.0-py3-none-any.whl.crt -
```

6. Compare the hash published in Rekor to the hash of our `whl` file
```bash
curl https://rekor.sigstore.dev/api/v1/log/entries/?logIndex=10441108 | jq -r '.[].body' | base64 -d | jq -r '.[]' | tail -n +3 | jq -r '.data.hash.value'
46e983a84971699b21cad675c0c231f0a1cedbb8cdf3d2eb23331d0e7eddbdc2
(aerleon-py3.10) rob@rob:~/tmp$ sha2
sha224sum  sha256sum  
(aerleon-py3.10) rob@rob:~/tmp$ sha256sum foo-0.1.0-py3-none-any.whl
46e983a84971699b21cad675c0c231f0a1cedbb8cdf3d2eb23331d0e7eddbdc2  foo-0.1.0-py3-none-any.whl
```

7. Inspect the SLSA file
The SLSA file contains information on what went into building the whl. This information includes things such as who initiated the build and hashes of every artifact.
```bash
cat provenance-sigstore-1.0.3.intoto.jsonl | jq -r '.payload' | base64 -d | jq
```
