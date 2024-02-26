# Secure SSH Configuration on Ubuntu

## Change Default SSH Port

1. **Open SSH Configuration File:**

    ```bash
    sudo nano /etc/ssh/sshd_config
    ```

2. **Change Default Port:**

    Replace `22` with your desired port number:

    ```plaintext
    Port 2222  # Change this to your desired port
    ```

    Save the file and restart the SSH service:

    ```bash
    sudo systemctl restart ssh
    ```

## Disable Password Authentication

1. **Open SSH Configuration File:**

    ```bash
    sudo nano /etc/ssh/sshd_config
    ```

2. **Update Authentication Settings:**

    Update the following lines:

    ```plaintext
    PasswordAuthentication no
    PermitEmptyPasswords no
    UsePAM no
    ```

    Save the file and restart the SSH service:

    ```bash
    sudo systemctl restart ssh
    ```

## Disable Root Login

1. **Open SSH Configuration File:**

    ```bash
    sudo nano /etc/ssh/sshd_config
    ```

2. **Disable Root Login:**

    Update the following line:

    ```plaintext
    PermitRootLogin no
    ```

    Save the file and restart the SSH service:

    ```bash
    sudo systemctl restart ssh
    ```

## Regenerate SSH Keys

1. **Regenerate RSA and ED25519 Keys:**

    ```bash
    sudo rm /etc/ssh/ssh_host_*
    sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    ```

## Remove Small Diffie-Hellman Moduli

1. **Remove Small Diffie-Hellman Moduli:**

    ```bash
    sudo awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    sudo mv /etc/ssh/moduli.safe /etc/ssh/moduli
    ```

## Update SSH Configuration

1. **Update SSH Configuration File:**

    ```bash
    sudo sed -i 's/^\#HostKey \/etc\/ssh\/ssh_host_\(rsa\|ed25519\)_key$/HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config
    ```

2. **Restrict supported key exchange, cipher, and MAC algorithms:**

    ```bash
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf
    ```

    Restart the SSH service:

    ```bash
    sudo systemctl restart ssh
    ```
