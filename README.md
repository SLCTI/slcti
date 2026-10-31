# SLCTI
A corporate website, including a resume, created from scratch using Node.js.

## Usage
1. Install and configure prerequisites ([Node.js](https://nodejs.org/en/download)):
```bash
sudo apt install nodejs npm
npm install
npm audit fix --force
sudo ufw allow 3000
sudo ufw enable
```
```powershell
. "C:\Program Files\nodejs\npm" install
. "C:\Program Files\nodejs\npm" audit fix --force
. "C:\Program Files\nodejs\node" src/server.js
```
2. Run Node.js solution:
```bash
node src/server.js
```
```powershell
. "C:\Program Files\nodejs\node" src/server.js
```
3. Open solution: [https://localhost:3000/](https://localhost:3000/).

## Documentation
### Prerequisites

#### Generate key
```bash
ssh-keygen -t rsa -b 4096 -C "USERNAME"
```

#### Add key to agent
```bash
ssh-add $env:USERPROFILE\.ssh\id_rsa
```

#### Append key to the authorized_keys
```bash
type $env:USERPROFILE\.ssh\id_rsa.pub | ssh USERNAME@HOST "cat >> ~/.ssh/authorized_keys"
```

#### Connect to web server
```bash
ssh USERNAME@HOST
```

#### Grant permissions
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

#### Grant the user permission to run the specified systemctl commands without needing to enter their password
```bash
sudo visudo
USERNAME ALL=(ALL) NOPASSWD: /bin/chmod
USERNAME ALL=(ALL) NOPASSWD: /bin/chown
USERNAME ALL=(ALL) NOPASSWD: /bin/systemctl daemon-reload, /bin/systemctl restart resume.service
```

#### Change user permissions on solution directory structure
```bash
sudo chown -R ${$USER}:$USER $DIRECTORY &&
sudo chmod -R 755 $DIRECTORY &&
```

#### Enable VPN
```bash
sudo openvpn --config /etc/openvpn/ca.protonvpn.udp.ovpn --auth-user-pass /etc/openvpn/ca.protonvpn.udp.txt
```

#### Disabled VPN
```bash
sudo systemctl stop openvpn@client
```

#### Request a certificate from Let's Encrypt
```bash
sudo certbot certonly --webroot -w ~/source/resume/public -d DOMAIN
```

#### Set permissions for certificates
```bash
sudo usermod -aG ssl-cert LOGIN
sudo chgrp ssl-cert /etc/letsencrypt/archive/DOMAIN/*.pem
sudo chmod 640 /etc/letsencrypt/archive/DOMAIN/privkey1.pem
sudo chmod 755 /etc/letsencrypt/archive/DOMAIN/cert1.pem /etc/letsencrypt/archive/DOMAIN/chain1.pem /etc/letsencrypt/archive/DOMAIN/fullchain1.pem
```

#### Set up automatic renewal
```bash
echo "0 0,12 * * * root /opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -q" | sudo tee -a /etc/crontab > /dev/null
```

#### Disconnect from web server
```bash
exit
```

#### Create new SSL certificate
```bash
sudo openssl req -new -newkey rsa:2048 -nodes -keyout /etc/ssl/private/slcti.key -out /etc/ssl/certs/slcti.csr
sudo chmod 600 /etc/ssl/private/slcti.key
sudo chown root:root /etc/ssl/private/slcti.key
cat /etc/ssl/certs/slcti.csr
```

### Secure section
Resources, timesheets, expenses, bills, payments and totals are available at `/secure`. Everything is stored in a single SQLite database, `private/slcti.db`, which is ignored by Git and created on first start. Set `SLCTI_DATABASE` in `.env` to store it elsewhere. The table definitions are in `src/secure_db.js`.

The database is encrypted with SQLCipher. Its key is `SLCTI_DB_KEY` in `.env` (see `.env.example`), which is never committed: keep a copy of it in a password manager, since the data cannot be read without it. SQLite tools without SQLCipher support (such as `sqlite3` or the SQLTools extension) cannot open the file.

Keep every private file (database, backups, source spreadsheets) in `private/` and every secret in `.env`: neither is committed, and `private/` is not served by the web server.

#### Configuration
All the settings are in `.env` (see `.env.example`): `NODE_ENV` (`development` or `production`), `SLCTI_CERTIFICATES` (folder of the HTTPS certificates, production only), `SLCTI_DATABASE` (optional) and `SLCTI_DB_KEY`. On a new machine, copy `.env` from an existing installation. To start from an empty database instead, copy `.env.example` to `.env` and fill in a new key.

The production settings are kept locally in `.env.production` (same key as `.env`), which `bin/deploy.ps1` sends to the server as `.env`.

#### Deploy
```powershell
.\bin\deploy.ps1            # commit, push and deploy the code, and send .env.production as .env
.\bin\deploy.ps1 -Database  # also replace the production database with the local one
```
The code goes through Git; `.env.production` and the database are copied with `scp` and never committed (the script refuses to commit them). The local database is only sent when the server has none yet, or with `-Database`: it then replaces the production data, after a backup of it on the server in `private/backups/`.

#### Create user or change password (on the web server)
```bash
cd ~/source/resume
node src/set_password.js USERNAME [admin|accountant]
```
Administrators have full access. Accountants have read-only access to timesheets (without descriptions), expenses, bills (without the client box), payments and totals, but not to resources. New users are accountants unless `admin` is given; the role of an existing user only changes when one is given.

#### Back up the database
Writes an encrypted copy (same key) to `private/backups/slcti-YYYY-MM-DD.db`:
```bash
cd ~/source/resume
node src/backup_db.js
```

## Contact
### SLCIT
- Simon Charest, Founder and CEO :
    - [Website](https://www.slcti.ca/);
    - [Email](mailto:info@slcti.ca);
    - [GitHub](https://github.com/slcti/);
    - [LinkedIn](https://www.linkedin.com/in/simoncharest/).

## Acknowledgments
- [ChatGPT](https://chat.openai.com/).
