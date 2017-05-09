Honeypot for Intel's AMT Firmware Vulnerability CVE-2017-5689.

Webserver that listens on TCP port 16922. Replicates the behaviour of Intel's AMT management service.

Building -

```# go build server.go```

Running - 

```# ./server logfile.txt```

### TODO
- [ ] Daemonize
- [ ] Add templating to make content dynamic / random
- [ ] Add error checking
- [ ] Add some form of RCE?
