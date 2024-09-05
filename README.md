# tap-house 🍺

An ebpf based packet analyser. You can tap packets using Soracom Junction and feed them into tap-house🍺.

tap-house comes from "Tap House Grill", a bar in downtown Seattle :)
https://www.instagram.com/taphousegrill/

## Run

```
sudo bash run.sh tap-house.py
```

For detail, see: https://github.com/iovisor/bcc/issues/2278#issuecomment-1582090173

## Prerequisites

### Install BCC

You need to have BCC installed. See: https://github.com/iovisor/bcc/blob/master/INSTALL.md

### MTU and combined queue issue

https://zenn.dev/suicide_student/articles/2755385740fb2b

### NIC Multi Purpose channel number issue

https://trying2adult.com/what-is-xdp-and-how-do-you-use-it-in-linux-amazon-ec2-example/
