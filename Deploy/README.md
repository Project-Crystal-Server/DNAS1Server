# Running DNAS1Server as a Linux service

## Build

Self-contained single file, so the server does not need the .NET runtime installed.
Works from Windows or Linux.

```bash
dotnet publish DNAS1Server.csproj -c Release -o publish/linux-x64
```

The output is `publish/linux-x64/DNAS1Server` plus the `keys/` folder it reads at startup.

## Install

Copy `publish/linux-x64/DNAS1Server`, `publish/linux-x64/keys/` and `deploy/dnas1server.service` to the Linux host, then:

To set region (`us` or `jp`), edit the `DNAS_REGION` variable in `deploy/dnas1server.service`. Default is `us`.

```bash
cd <where you copied the files to>
sudo mkdir -p /opt/dnas1server
sudo cp DNAS1Server /opt/dnas1server/
sudo cp -r keys /opt/dnas1server/
sudo chmod 755 /opt/dnas1server/DNAS1Server /opt/dnas1server/keys
sudo chmod 644 /opt/dnas1server/keys/*
sudo cp dnas1server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dnas1server
```

## Operate

View Status: `systemctl status dnas1server`
View Log: `journalctl -u dnas1server -f`
Control: `systemctl start/stop/restart dnas1server`

## Notes

- The service runs as an unprivileged dynamic user; `CAP_NET_BIND_SERVICE` in the unit is what lets it bind port 443.
- Open 443/tcp in the firewall (`sudo ufw allow 443/tcp` or the firewalld equivalent) and make sure nothing else (nginx, apache) already holds the port.
