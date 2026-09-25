# Running DNAS1Server as a Linux service

## Build

Self-contained single file, so the server does not need the .NET runtime installed.
Works from Windows or Linux.

```bash
dotnet publish DNAS1Server.csproj -c Release -o publish/linux-x64
```

The output is `publish/linux-x64/DNAS1Server` plus the `keys/` folder it reads at startup.

## Install

There is one unit per region: `deploy/us.dnas1server.service` and `deploy/jp.dnas1server.service`.
Copy `publish/linux-x64/DNAS1Server`, `publish/linux-x64/keys/` and the unit(s) you need to the Linux host, then:

```bash
cd <where you copied the files to>
sudo mkdir -p /opt/dnas1server
sudo cp DNAS1Server /opt/dnas1server/
sudo cp -r keys /opt/dnas1server/
sudo chmod 755 /opt/dnas1server/DNAS1Server /opt/dnas1server/keys
sudo chmod 644 /opt/dnas1server/keys/*
sudo cp us.dnas1server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now us.dnas1server
```

Use `jp.dnas1server` instead for the JP region.

## Both regions on one host

Each instance binds port 443, so each needs its own IPv4 address. Set `DNAS_BIND_IP` in each unit
(empty = all interfaces) before copying them.

On a DigitalOcean droplet, give the droplet a Reserved IP. The US instance binds the droplet's public IP,
the JP instance binds the droplet's anchor IP (traffic to the Reserved IP arrives there):

```bash
curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/address
```

Install as above with both units, then:

```bash
sudo systemctl enable --now us.dnas1server jp.dnas1server
```

Point the US DNAS hostname at the public IP and the JP DNAS hostname at the Reserved IP.

## Operate

View Status: `systemctl status us.dnas1server`
View Log: `journalctl -u us.dnas1server -f`
Control: `systemctl start/stop/restart us.dnas1server`

Replace `us` with `jp` for the JP instance.

## Notes

- The service runs as an unprivileged dynamic user; `CAP_NET_BIND_SERVICE` in the unit is what lets it bind port 443.
- Open 443/tcp in the firewall (`sudo ufw allow 443/tcp` or the firewalld equivalent) and make sure nothing else (nginx, apache) already holds the port.
