# example

This directory provides example of SSH password crack for penetration tests using brute force and dictionary attacks.

## Example

### Run test ssh server

```zsh
$ make ssh/server/start
```

### Attack using dictionary

```zsh
$ crssh user_1@127.0.0.1 -p 2222 -d
```
