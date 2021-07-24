# 'whois' queries, in batch

given a set of ip addresses (v4 and v6), concurrently queries whois servers
about them.

## example

1. populate a file with one ipv4 addr per row

```console
$ cat ips.txt
162.250.189.53
163.172.62.166
168.119.12.182
170.130.55.119
172.86.181.178
```

2. point `drwho` at such file

```
$ drwho -f ips.txt
162.250.189.53,Rica Web Services
163.172.62.166,ERX-NETBLOCK
168.119.12.182,RIPE Network Coordination Centre
170.130.55.119,Eonix Corporation
172.86.181.178,Joe's Datacenter, LLC
```

## usage

```console
$ drwho --help
batch whois resolver

Usage:
  drwho [flags]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  help        Help about any command
  version     print the version of this CLI

Flags:
      --concurrency uint   maximum number of whois queries to have in-flight at the same time (default 10)
  -f, --file string        location of a file containing ipv4 addresses to resolve
  -h, --help               help for drwho
  -x, --proxy string       socks5 proxy to send queries through
  -v, --verbose            whether we should be verbose or not

Use "drwho [command] --help" for more information about a command.
```

## install

using go

```console
$ GO111MODULE=on go get github.com/cirocosta/drwho/cmd/drwho
```


## license

see [./LICENSE](./LICENSE)
