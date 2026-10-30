# ssh-key-auditor

Audit an authorized_keys file: flag DSA keys and RSA keys shorter than 2048 bits, measuring the real modulus from the key blob.

## How to run

```sh
python3 main.py authorized_keys
```

## Example output

```
1 issue(s).
- line 2: short RSA key (1024 bits, use at least 2048)
```

Standard library only. Run the tests with `python3 -m unittest discover`.
