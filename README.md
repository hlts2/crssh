# crssh

SSH password cracker for penetration tests using [brute force](https://github.com/hlts2/gobf) and [dictionary attacks](https://github.com/hlts2/godict).

## Requirement

Go 1.15+

## Install

```shell
go get github.com/hlts2/crssh
```

## Usage

```bash
$ crssh --help
penetration testing tool for ssh server

Usage:
  crssh [flags]

Flags:
  -b, --bruteforce    set brute force attack
  -d, --dictionary    set dictionary attack
  -h, --help          help for crssh
  -p, --port uint     set port number (default 22)
  -s, --size uint     set password size for brute force attack (default 4)
  -u, --user string   set user name (default "root")
  -v, --version       version for crssh
```

## Example

#### Dictionary Attack

Execute a dictionary attack with the `d` option.

```bash
$ crssh root@127.0.0.1 -p 2222 -d
```

#### Brute Force Attack

Execute a brute force attack with the `b` option.

```bash
$ crssh root@127.0.0.1 -p 2222 -b
```

#### Dictionary Attack & Brute Force Attack

Execute dictionary and brute force attacks with the `d` and `b` options.

```bash
$ crssh root@127.0.0.1 -p 2222 -db
```
