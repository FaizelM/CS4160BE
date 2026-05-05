# Blockchain Engineering

## Assignment 1

### How to run?

To mine the nonce run the command below. Once a nonce is found it is saved to "nonce.txt".
To find the nonce we need to find 28 leading zeros, which means 3 full zero bytes, and the fourth byte should satisfy: 0XF0 (11110000) & byte == 0.
The hash is constructed like: `SHA256( email_utf8 || "\n" || github_url_utf8 || "\n" || nonce_as_8_byte_big_endian )`

```python
uv run python pow.py --email <my_mail>@student.tudelft.nl --url https://github.com/<my_public_repo>
```

To submit to the server:

```python
uv run python client.py --email <my_mail>@student.tudelft.nl --url https://github.com/<my_public_repo>
```
