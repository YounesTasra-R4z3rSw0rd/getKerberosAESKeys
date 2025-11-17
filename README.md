## About

This tool derives Kerberos AES-128 and AES-256 keys from a plaintext password and a Kerberos salt. It can be used for offline Kerberos key derivation, password analysis, or interoperability testing.</br>
Given a password, domain/realm, and username (or any valid Kerberos salt), the script computes the corresponding AES keys using PBKDF2 (default 4096 iterations).

## Installation

Clone the repository:
```bash
git clone https://github.com/<you>/getKerberosAESKey.git
cd getKerberosAESKey
```

No additional dependencies are required.

Run it with Python 3:
```bash
python3 getKerberosAESKey.py --help                                       
```

## Understanding the Salt

Kerberos salts typically follow one of these forms:

User principal:
`<REALM><username>`
Example: `DOMAIN.LOCALjohn.doe`

Host/service principal:
`<REALM>host/fqdn`
Example: `DOMAIN.LOCALhost/server.domain.local`

You must supply the full salt string as required by the principal type.

## Help Menu

```bash
python3 getKerberosAESKey.py --help                                       
usage: getKerberosAESKey.py [-h] [-p PASSWORD] -s SALT [-i ITERATIONS] [-o {AES,AES128,AES256,AES128ByteArray,AES256ByteArray}]

Derive Kerberos AES keys from password + salt

options:
  -h, --help            show this help message and exit
  -p, --password PASSWORD
                        Password (if omitted, you will be prompted)
  -s, --salt SALT       Kerberos salt (e.g., REALMusername or REALMhost/fqdn)
  -i, --iterations ITERATIONS
                        PBKDF2 iteration count (default 4096)
  -o, --output {AES,AES128,AES256,AES128ByteArray,AES256ByteArray}
                        Output format (default: AES)
```

## Example

```bash
python3 getKerberosAESKey.py -p 'samplePassword' -s 'DOMAIN.LOCALjohn.doe'
AES128 Key: 1386aaefde8ed99da4cb91cea52fa49a
AES256 Key: 118d20bb408be1a28f7eec0b52573772761e5f2a8b48be6c3db7b35525da238b
```

## Output Formats

| Format | Description |
|--------|-------------|
| `AES` | Outputs both AES128 and AES256 keys |
| `AES128` | Outputs only the AES128 key (hex) |
| `AES256` | Outputs only the AES256 key (hex) |
| `AES128ByteArray` | Python byte array representation of the AES128 key |
| `AES256ByteArray` | Python byte array representation of the AES256 key |
