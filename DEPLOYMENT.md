# Deployment

This service is a single Node.js process with file-backed persistence. The only directory that must survive restarts is `DATA_DIR`.

## Production Checklist

- Run on Node.js 20 or newer.
- Put the service behind HTTPS.
- Set `PUBLIC_BASE_URL` to the public HTTPS origin, such as `https://gist.example.com`.
- Set `COOKIE_SECURE=true` when HTTPS is used.
- Keep `DATA_DIR` outside the source tree, for example `/var/lib/text-gist-service`.
- Back up `DATA_DIR` regularly.
- Do not publish or commit `DATA_DIR`; it contains users, sessions, metadata, and gist contents.

## Environment

Create an environment file on the server:

```sh
sudo useradd --system --home /var/lib/text-gist-service --shell /usr/sbin/nologin node
sudo install -d -m 0750 -o node -g node /var/lib/text-gist-service
sudo install -d -m 0755 /etc/text-gist-service
sudo cp .env.example /etc/text-gist-service/env
sudo editor /etc/text-gist-service/env
```

If the `node` user already exists, keep using it or replace `User=node` and `Group=node` in the systemd unit with the service account you prefer.

Example values:

```sh
HOST=127.0.0.1
PORT=3456
DATA_DIR=/var/lib/text-gist-service
PUBLIC_BASE_URL=https://gist.example.com
MAX_TEXT_BYTES=1048576
COOKIE_SECURE=true
```

Use `HOST=127.0.0.1` when Nginx or another reverse proxy runs on the same machine. Use `HOST=0.0.0.0` only when the process must accept direct network traffic.

## systemd

Create `/etc/systemd/system/text-gist-service.service`:

```ini
[Unit]
Description=Text Gist Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/text-gist-service
EnvironmentFile=/etc/text-gist-service/env
ExecStart=/usr/bin/node src/server.js
Restart=on-failure
RestartSec=5
User=node
Group=node
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/text-gist-service

[Install]
WantedBy=multi-user.target
```

Install and start:

```sh
sudo install -d -m 0755 /opt/text-gist-service
sudo rsync -a --delete ./ /opt/text-gist-service/
sudo systemctl daemon-reload
sudo systemctl enable --now text-gist-service
sudo systemctl status text-gist-service
curl -fsS http://127.0.0.1:3456/healthz
```

View logs:

```sh
journalctl -u text-gist-service -f
```

## Nginx Reverse Proxy

Example server block:

```nginx
server {
    listen 80;
    server_name gist.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name gist.example.com;

    ssl_certificate /etc/letsencrypt/live/gist.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gist.example.com/privkey.pem;

    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:3456;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Reload after testing:

```sh
sudo nginx -t
sudo systemctl reload nginx
```

## Docker

Build:

```sh
docker build -t text-gist-service .
```

Run:

```sh
docker run -d \
  --name text-gist-service \
  --restart unless-stopped \
  -p 127.0.0.1:3456:3456 \
  -v text-gist-data:/data \
  -e HOST=0.0.0.0 \
  -e PORT=3456 \
  -e PUBLIC_BASE_URL=https://gist.example.com \
  -e COOKIE_SECURE=true \
  text-gist-service
```

Check:

```sh
curl -fsS http://127.0.0.1:3456/healthz
```

## Backups

Back up the complete data directory:

```sh
sudo tar -C /var/lib -czf text-gist-service-data-$(date +%F).tar.gz text-gist-service
```

Restore by stopping the service, replacing `DATA_DIR`, then starting it again:

```sh
sudo systemctl stop text-gist-service
sudo rm -rf /var/lib/text-gist-service
sudo tar -C /var/lib -xzf text-gist-service-data-YYYY-MM-DD.tar.gz
sudo systemctl start text-gist-service
```

## Upgrades

```sh
sudo systemctl stop text-gist-service
sudo rsync -a --delete ./ /opt/text-gist-service/
sudo systemctl start text-gist-service
curl -fsS http://127.0.0.1:3456/healthz
```

The current implementation has no migrations. Preserve `DATA_DIR` across upgrades.