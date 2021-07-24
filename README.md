# 'whois' queries, in batch

given a set of ip addresses (v4 and v6), concurrently queries whois servers
about them.


## usage

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

## install

using go

```console
$ GO111MODULE=on go get github.com/cirocosta/drwho/cmd/drwho
```

or fetching the binary for your distribution from the [releases page]. See
[INSTALL.md](./INSTALL.md) for details and examples.

[releases page]: https://github.com/cirocosta/drwho/releases

## license

see [./LICENSE](./LICENSE)
