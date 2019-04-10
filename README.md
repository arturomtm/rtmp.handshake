_Note: this is a fork from [rtmp.handshake](https://github.com/raininfall/rtmp.handshake)_

# rtmp-handshake

This module contains the entities needed to generate C0, C1 and C2 packets exchanged in RTMP digest-handshake process.

This handshake type differs from plain handshake because contains a digest and a key to verify it, in contrast to the random bytes present in plain one.
