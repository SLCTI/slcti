# SLCTI
A corporate website, including a resume, created from scratch using Node.js, now updraded using Claude Code.

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
Organisations, users, timesheets, invoices and totals are available at `/secure`. The Timesheets page lists and enters both the hours and the expenses (one form, whose type shows the fields of each); they stay in their own tables, `timesheet` and `expense`. Payments are added from the Totals page, where they are matched to the invoices. Everything is stored in a single SQLite database, `private/slcti.db`, which is ignored by Git and created on first start. Set `SLCTI_DATABASE` in `.env` to store it elsewhere. The table definitions are in `src/secure_db.js`.

The database is encrypted with SQLCipher. Its key is `SLCTI_DATABASE_KEY` in `.env` (see `.env.example`), which is never committed: keep a copy of it in a password manager, since the data cannot be read without it. SQLite tools without SQLCipher support (such as `sqlite3` or the SQLTools extension) cannot open the file.

Keep every private file (database, backups, source spreadsheets) in `private/` and every secret in `.env`: neither is committed, and `private/` is not served by the web server.

#### Configuration
All the settings are in `.env` (see `.env.example`): `NODE_ENV` (`development` or `production`), `SLCTI_CERTIFICATES` (folder of the HTTPS certificates, production only), `SLCTI_DATABASE` (optional) and `SLCTI_DATABASE_KEY`. On a new machine, copy `.env` from an existing installation. To start from an empty database instead, copy `.env.example` to `.env` and fill in a new key.

The production settings are kept locally in `.env.production` (same key as `.env`), which `bin/deploy.ps1` sends to the server as `.env`. The server it deploys to is set by `SLCTI_DEPLOY_USER`, `SLCTI_DEPLOY_HOST`, `SLCTI_DEPLOY_DIR` and `SLCTI_DEPLOY_SERVICE` in the local `.env`.

#### Deploy
```powershell
.\bin\deploy.ps1            # commit, push and deploy the code, and send .env.production as .env
.\bin\deploy.ps1 -Database  # also replace the production database with the local one
```
The code goes through Git; `.env.production` and the database are copied with `scp` and never committed (the script refuses to commit them). The local database is only sent when the server has none yet, or with `-Database`: it then replaces the production data, after a backup of it on the server in `private/backups/`.

At the end, production holds the reference data: a copy of the production database is kept in `private/backups/slcti-production-<time>.db` and replaces the local data (the local data is backed up first to `private/backups/slcti-local-<time>.db`), so local work is always on current data. This works while the local server runs. Both `.env` files must therefore use the same `SLCTI_DATABASE_KEY`. To restore any backup into the local database the same way: `node src/restore_db.js FILE`.

#### Logins and passwords
Administrators manage the people of the organisations on the Users page: name, title, email and telephone. An organisation can have several users, and its first user is its contact on the invoices. A user with a role (administrator, accountant, associate or client) and a password signs in with its email; choosing *No access* removes its password and leaves a contact only. Administrators have full access. Accountants have read-only access to timesheets (hours and expenses, without descriptions), invoices (without the client box) and totals, but not to organisations nor users. Associates (collaborators) have the same access as accountants for now. Clients have read-only access to the invoices and totals only (no timesheets nor expenses), limited to the data of their organisation (which they must have): those where it is the client, the billed resource or the payer. An administrator cannot remove their own administrator access nor delete their own user, so there is always one left; an organisation with users cannot be deleted.

To give a site access or reset a password without the site (for example, when nobody can sign in), on the web server:
```bash
cd ~/source/resume
node src/set_password.js EMAIL [admin|associate|accountant|client] [ORGANISATION_CODE]
```
It updates the user with this email, or creates one; a client needs the code of its organisation (for example `Paramed`).

#### Back up the database
Writes an encrypted copy (same key) to `private/backups/slcti-YYYY-MM-DD.db`:
```bash
cd ~/source/resume
node src/backup_db.js
```

## TODO
- Add invoices, linked to expenses, as downloadable attachments.

## Contact
### SLCIT
- Simon Charest, Founder and CEO:
    - [Email](mailto:info@slcti.ca);
    - [Website](https://www.slcti.ca/);
    - [GitHub](https://github.com/slcti/);
    - [LinkedIn](https://www.linkedin.com/in/simoncharest/).

## Acknowledgments
- [Claude Code](https://claude.com/product/claude-code).
