# Node root certificates

Each `<node>.pem` is the public root certificate of Caddy's local CA on that node
(`/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt`). It is public, not a
secret. The control program trusts exactly this root, and only for that node's agent at
`<node>.agent.internal:8443` (decision 006).

| File | Node | Expires | SHA-256 fingerprint |
|---|---|---|---|
| `toronto.pem` | <toronto ip> | 2036-09-18 | `48:A8:3C:31:71:39:09:1A:AA:88:51:72:58:62:6A:38:F8:E5:AB:61:0A:8C:B2:FF:B4:DA:05:57:BC:EC:EF:1C` |
| `dallas.pem` | <dallas ip> | 2036-09-18 | `D9:0C:B8:96:56:13:B7:5D:08:1F:61:E8:DD:84:C6:19:4A:4E:D5:3C:08:FA:FF:68:00:DD:09:B2:FA:C1:64:0E` |
| `toronto-wg.pem` | <toronto ip> (second agent, WireGuard) | same file as `toronto.pem` | same |
| `dallas-awg.pem` | <dallas ip> (second agent, AmneziaWG) | same file as `dallas.pem` | same |

A server's two agents (`deploy/node-add-protocol.sh`, `specs/dual-protocol.md`) are served by the same Caddy, so their certificates come from the same local CA: the second agent's file is a copy of the first's, under its own name. Replace both together if the server is reinstalled.

If a node is reinstalled, Caddy makes a new root. Fetch it again and replace the file:

```sh
ssh -i ~/.ssh/<key> -o IdentitiesOnly=yes root@<node ip> \
  cat /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt > deploy/node-roots/<node>.pem
```

Check a node from your own machine (needs a current OpenSSL; the Mac's built-in one is LibreSSL):

```sh
printf '' | openssl s_client -connect <node ip>:8443 -servername <node>.agent.internal \
  -CAfile deploy/node-roots/<node>.pem -verify_return_error | grep -E 'Verification|Protocol'
```
