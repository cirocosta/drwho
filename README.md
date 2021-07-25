# drwho - concurrent 'whois' queries

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

## but really, why?

recently, there's been some sus activity in monero's network, so being able to
get (maybe) useful extra information about connections/peers seemed
interesting.

```
$ monero daemon get-connections --json | \
  jq '.connections[] | .address' -r | \
  awk -F':' '{print $1}' | \
  drwho -f- --concurrency=20

ADDR,ORG,COUNTRY,RECURSE ERR
51.79.54.168,ovh hosting, inc.,ca,false
134.209.67.213,digitalocean, llc,us,false
185.39.114.27,infotelecom-sp-net,ru,false
198.50.179.156,ovh hosting, inc.,ca,false
84.237.229.84,apollo-ltc-home-static,lv,false
90.252.85.255,vodafone-dyn-ip,gb,false
73.21.51.28,comcast cable communications, llc,us,false
194.195.241.243,linode, llc,gb,false
168.119.12.182,hetzner online gmbh,de,false
61.54.142.182,unicom-ha,cn,false
52.231.33.214,microsoft corporation,us,false
104.248.45.85,digitalocean, llc,us,false
136.56.170.96,google fiber inc.,,false
...
```

_(^ check [cirocosta/go-monero](https://github.com/cirocosta/go-monero) to find
out more about such cli.)_


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
