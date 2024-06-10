# Secure SSH Configuration on Ubuntu 22.04 LTS Server

Securing your SSH configuration is crucial to protect your server from unauthorized access. Here’s a step-by-step guide to enhance the security of your SSH server on Ubuntu 22.04 LTS.

## Change Default SSH Port

1. **Open SSH Configuration File:**

    sudo nano /etc/ssh/sshd_config

2. **Change Default Port:**

    Replace `22` with your desired port number:

    Port 2222  # Change this to your desired port

    Save the file and restart the SSH service:

    sudo systemctl restart ssh

Changing the default SSH port can help reduce automated attacks, as many bots target port 22 by default.

## Disable Password Authentication

1. **Open SSH Configuration File:**

    sudo nano /etc/ssh/sshd_config

2. **Update Authentication Settings:**

    Update the following lines:

    PasswordAuthentication no
    PermitEmptyPasswords no
    UsePAM no

    Save the file and restart the SSH service:

    sudo systemctl restart ssh

Disabling password authentication forces the use of SSH keys, which are more secure than passwords.

## Disable Root Login

1. **Open SSH Configuration File:**

    sudo nano /etc/ssh/sshd_config

2. **Disable Root Login:**

    Update the following line:

    PermitRootLogin no

    Save the file and restart the SSH service:

    sudo systemctl restart ssh

Disabling root login prevents attackers from accessing the server using the root account, adding an additional layer of security.

## Regenerate SSH Keys

1. **Regenerate RSA and ED25519 Keys:**

    sudo rm /etc/ssh/ssh_host_*
    sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

Regenerating SSH keys ensures that you are using the most secure and up-to-date keys.

## Remove Small Diffie-Hellman Moduli

1. **Remove Small Diffie-Hellman Moduli:**

    sudo awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    sudo mv /etc/ssh/moduli.safe /etc/ssh/moduli

Removing small Diffie-Hellman moduli enhances the security of the key exchange process.

## Update SSH Configuration

1. **Update SSH Configuration File:**

    sudo sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config

2. **Apply Secure Algorithms:**

    echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf

    Restart the SSH service:

    sudo systemctl restart ssh

Applying these secure algorithms strengthens the encryption and integrity of SSH connections.

# Automated Secure SSH Configuration

## Step 1: Download the Installer Script

    wget https://github.com/PrimeMurcia/Secure-SSH-Connection/main/secure_ssh_config.sh

## Step 2: Make the Script Executable

    chmod +x secure_ssh_config.sh

## Step 3: Run the Script

    ./secure_ssh_config.sh

This script automates the above steps to secure your SSH configuration.

# Basic Security on Ubuntu 22.04

In addition to securing SSH, consider these basic security measures:

## Install Fail2Ban

Fail2Ban helps protect your server from brute-force attacks by banning IPs that show malicious signs.

1. **Install Fail2Ban:**

    sudo apt update
    sudo apt install fail2ban

2. **Configure Fail2Ban:**

    Copy the default configuration file:

    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

    Open the configuration file:

    sudo nano /etc/fail2ban/jail.local

    Ensure the following settings are configured:

    [sshd]
    enabled = true
    port = 2222  # Your custom SSH port
    maxretry = 3

    Save the file and restart Fail2Ban:

    sudo systemctl restart fail2ban

## Install and Configure UFW (Uncomplicated Firewall)

UFW helps manage firewall rules on your server.

1. **Install UFW:**

    sudo apt install ufw

2. **Allow SSH Connections:**

    sudo ufw allow 2222/tcp  # Your custom SSH port

3. **Enable UFW:**

    sudo ufw enable

4. **Check UFW Status:**

    sudo ufw status

With these security measures in place, your Ubuntu 22.04 LTS server will be more resilient against common attack vectors, ensuring a safer and more secure environment for your applications and data.
