# RACG service units

These are examples for the two-process deployment. Create users and
`/etc/racg/service.toml` before enabling them:

```sh
sudo useradd --system --home /var/lib/racg-broker --shell /usr/sbin/nologin racg-broker
sudo install -d -m 0700 -o root -g racg-broker /var/lib/racg-authority
sudo install -d -m 0700 -o racg-broker -g racg-broker /var/lib/racg-broker
sudo install -m 0600 service.toml /etc/racg/service.toml
sudo install -m 0644 deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now racg-service-authority.service racg-service-broker.service
```

The authority runs as the privileged executor. The broker must run as the exact
`broker_uid` named in service.toml. Do not expose a listener publicly without
network isolation/authentication such as Tailscale.
