# heira-eyaml

<!-- alias heira-eyaml="${HOME}/.rbenv/shims/eyaml" -->

```sh
❯ eyaml --help
Welcome to eyaml 3.2.2

Usage:
eyaml subcommand [global-opts] [subcommand-opts]

Available subcommands:
        decrypt: decrypt some data
        recrypt: recrypt an eyaml file
        version: show version information
           edit: edit an eyaml file
     createkeys: create a set of keys with which to encrypt/decrypt eyaml data
        encrypt: encrypt some data

For more help on an individual command, use --help on that command
```
```sh
❯ eyaml createkeys --help
eyaml createkeys: create a set of keys with which to encrypt/decrypt eyaml data

Usage: eyaml createkeys [options]

Options:
  -n, --encrypt-method=<s>           Override default encryption and decryption method (default is PKCS7) (default: pkcs7)
  --version                          Show version information
  -v, --verbose                      Be more verbose
  -t, --trace                        Enable trace debug
  -q, --quiet                        Be less verbose
  -h, --help                         Information on how to use this command
  --pkcs7-private-key=<s>            Path to private key (default: /Users/stuart.warren/.eyaml/default.private.key)
  --pkcs7-public-key=<s>             Path to public key (default: /Users/stuart.warren/.eyaml/default.public.key)
  --pkcs7-private-key-env-var=<s>    Name of environment variable to read private key from
  --pkcs7-public-key-env-var=<s>     Name of environment variable to read public key from
  --pkcs7-subject=<s>                Subject to use for certificate when creating keys (default: /)
  --pkcs7-keysize=<i>                Key size used for encryption (default: 2048)
  --pkcs7-digest=<s>                 Hash function used for PKCS7 (default: SHA256)
```
```sh
❯ eyaml decrypt --help
eyaml decrypt: decrypt some data

Usage: eyaml decrypt [options]

Options:
  -n, --encrypt-method=<s>           Override default encryption and decryption method (default is PKCS7) (default: pkcs7)
  --version                          Show version information
  -v, --verbose                      Be more verbose
  -t, --trace                        Enable trace debug
  -q, --quiet                        Be less verbose
  -h, --help                         Information on how to use this command
  -s, --string=<s>                   Source input is a string provided as an argument
  -f, --file=<s>                     Source input is a regular file
  -e, --eyaml=<s>                    Source input is an eyaml file
  --stdin                            Source input is taken from stdin
  --pkcs7-private-key=<s>            Path to private key (default: /Users/stuart.warren/.eyaml/default.private.key)
  --pkcs7-public-key=<s>             Path to public key (default: /Users/stuart.warren/.eyaml/default.public.key)
  --pkcs7-private-key-env-var=<s>    Name of environment variable to read private key from
  --pkcs7-public-key-env-var=<s>     Name of environment variable to read public key from
  --pkcs7-subject=<s>                Subject to use for certificate when creating keys (default: /)
  --pkcs7-keysize=<i>                Key size used for encryption (default: 2048)
  --pkcs7-digest=<s>                 Hash function used for PKCS7 (default: SHA256)
```
```sh
❯ eyaml encrypt --help
eyaml encrypt: encrypt some data

Usage: eyaml encrypt [options]

Options:
  -n, --encrypt-method=<s>           Override default encryption and decryption method (default is PKCS7) (default: pkcs7)
  --version                          Show version information
  -v, --verbose                      Be more verbose
  -t, --trace                        Enable trace debug
  -q, --quiet                        Be less verbose
  -h, --help                         Information on how to use this command
  -p, --password                     Source input is a password entered on the terminal
  -s, --string=<s>                   Source input is a string provided as an argument
  -f, --file=<s>                     Source input is a regular file
  --stdin                            Source input is taken from stdin
  -e, --eyaml=<s>                    Source input is an eyaml file
  -o, --output=<s>                   Output format of final result (examples, block, string) (default: examples)
  -l, --label=<s>                    Apply a label to the encrypted result
  --pkcs7-private-key=<s>            Path to private key (default: /Users/stuart.warren/.eyaml/default.private.key)
  --pkcs7-public-key=<s>             Path to public key (default: /Users/stuart.warren/.eyaml/default.public.key)
  --pkcs7-private-key-env-var=<s>    Name of environment variable to read private key from
  --pkcs7-public-key-env-var=<s>     Name of environment variable to read public key from
  --pkcs7-subject=<s>                Subject to use for certificate when creating keys (default: /)
  --pkcs7-keysize=<i>                Key size used for encryption (default: 2048)
  --pkcs7-digest=<s>                 Hash function used for PKCS7 (default: SHA256)
```
```sh
❯ eyaml edit --help
eyaml edit: edit an eyaml file

Usage: eyaml edit [options] <some-eyaml-file>

Options:
  -n, --encrypt-method=<s>           Override default encryption and decryption method (default is PKCS7) (default: pkcs7)
  --version                          Show version information
  -v, --verbose                      Be more verbose
  -t, --trace                        Enable trace debug
  -q, --quiet                        Be less verbose
  -h, --help                         Information on how to use this command
  --no-preamble                      Dont prefix edit sessions with the informative preamble
  -d, --no-decrypt                   Do not decrypt existing encrypted content. New content marked properly will be encrypted.
  --pkcs7-private-key=<s>            Path to private key (default: /Users/stuart.warren/.eyaml/default.private.key)
  --pkcs7-public-key=<s>             Path to public key (default: /Users/stuart.warren/.eyaml/default.public.key)
  --pkcs7-private-key-env-var=<s>    Name of environment variable to read private key from
  --pkcs7-public-key-env-var=<s>     Name of environment variable to read public key from
  --pkcs7-subject=<s>                Subject to use for certificate when creating keys (default: /)
  --pkcs7-keysize=<i>                Key size used for encryption (default: 2048)
  --pkcs7-digest=<s>                 Hash function used for PKCS7 (default: SHA256)
```
```sh
❯ eyaml recrypt --help
eyaml recrypt: recrypt an eyaml file

Usage: eyaml recrypt [options] <some-eyaml-file>

Options:
  -n, --encrypt-method=<s>           Override default encryption and decryption method (default is PKCS7) (default: pkcs7)
  --version                          Show version information
  -v, --verbose                      Be more verbose
  -t, --trace                        Enable trace debug
  -q, --quiet                        Be less verbose
  -h, --help                         Information on how to use this command
  -d, --change-encryption=<s>        Specify the new encryption method that should be used for the file (default: pkcs7)
  --pkcs7-private-key=<s>            Path to private key (default: /Users/stuart.warren/.eyaml/default.private.key)
  --pkcs7-public-key=<s>             Path to public key (default: /Users/stuart.warren/.eyaml/default.public.key)
  --pkcs7-private-key-env-var=<s>    Name of environment variable to read private key from
  --pkcs7-public-key-env-var=<s>     Name of environment variable to read public key from
  --pkcs7-subject=<s>                Subject to use for certificate when creating keys (default: /)
  --pkcs7-keysize=<i>                Key size used for encryption (default: 2048)
  --pkcs7-digest=<s>                 Hash function used for PKCS7 (default: SHA256)
```