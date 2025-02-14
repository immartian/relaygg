# relaygg
 
 Inspired by several communities(e.g. https://github.com/net4people/bbs/issues/412, and https://github.com/yggdrasil-network/yggdrasil-go/issues), this project aims to verify a secure TLS proxy that enables access to blocked websites by modifying the SNI (Server Name Indication) field in the TLS handshake and securely relaying the correct destination via an out-of-band (OOB) communication channel over QUIC (or [YggQuic](https://github.com/yggdrasil-network/yggquic/tree/main) iff deemed an optimal OOB solution).

The proxy intercepts TLS connections at the local node, extracts the real SNI, replaces it with a camouflage SNI, and transmits the real SNI to a remote peer over an encrypted QUIC channel. The remote peer then initiates a genuine TLS handshake with the intended server and returns the correct `ServerHello` response. This mechanism allows users to bypass SNI-based censorship while maintaining a valid end-to-end TLS session.

## Config file:
```json
{
    "local_proxy_addr": "127.0.0.1:8443",
    "oob_port": "[::]:8008",
    "oob_peers": [

    ],
    "fake_sni": "harvard.edu"
  }
```


## Key challenges include:
- Ensuring all clients, including cURL, properly send the intended SNI when connecting through the proxy.
- Maintaining TLS handshake integrity despite modifying the SNI.
- Efficiently handling multiple concurrent connections while preserving low-latency OOB transmission.
- Ensuring Yggdrasil peer configuration is user-friendly and resistant to firewall restrictions.

