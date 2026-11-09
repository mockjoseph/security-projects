# Certificate Management Lab

## Architecture Setup
Goal is to simulate how a company actually does this stuff. For this I setup two VMS and used my personal computer. 
- One VM simulates an App Server (The user or the client that has created an application and now needs a certificate for it.)
- One VM simulates the CA. This is to simulate the root cert and intermediate certs for signing certificates and such as a company would likely have this already setup or be using a thrid party CA such as Sectigo.
- The personal computer is simulating the PKI team, or the people that are responding to tickets and creating certificates for the application users to have for their app.

## CA Setup
First things first, we will setup a CA. 
**What we Need**
- Root CA: Private Key and Self-Signed Certificate
    - People inherently trust the root since someone created it, validity is   normally very long 10-20 years and used rarely
- Intermediate CA: Needs its own Private Key and CSR, signed by Root CA (similar to app server setup that will be done later)

### Root CA Setup
- Generating the Private Key: Will be using openssl mostly through this lab, a relevant command to do this would be: 
```bash
openssl genpkey -out private/root_ca.key -outform PEM -cipher des3 -algorithm rsa -pkeyopt rsa_keygen_bits:2048
```
- Generating the root cert (self-signed by private key). A relevant command to do this would be something like 
```bash
openssl req -new -key private/root_ca.key -outform PEM -out certs/root_ca.crt -x509 -days 3000 -sha256 -addext "basicConstraints = critical, CA:TRUE" -addext "keyUsage = critical, keyCertSign, cRLSign" -addext "subjectKeyIdentifier = hash"
```
    - For self signing we are not reading in an existing CSR
    - We are creating a new request
    - Outputting a cert not a CSR (-x509)


### Intermediate CA Setup
Now we want to create intermediate certificates because the Root should not be compromised. If the Root is compromised then the entire certificate chain will be useless from a security standpoint. Intermediate certificate can be used to sign lower level ones and expand the chain.

This is a similar process, but this time we need a CSR signed by the root so that the intermiediate is not self-signed.

1. Create the key
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes256 -out intermediate/private/inter_ca.key
```
The only change here is putting it in a different directory
2. Create the CSR
```bash
openssl req -new -key intermediate/private/inter_ca.key -outform PEM -out intermediate/csr/inter_ca.csr -sha256
```
- This is the minimum needed command, we need to pass in the intermediate CA's private key for creating the CSR, and just being consistent with the outform and the hash used to generate. Note also that for the subject we will keep it the same and stay consistent with the CN for the naming pattern that was used for the root.

3. Create the certificate
For creating an intermediate CA (we will call this an issuing CA because it will have a role of issuing certificates to app servers)
```bash
openssl x509 -req -in intermediate/csr/inter_ca.csr -CA root/certs/root_ca.crt -CAkey root/private/root_ca.key -out intermediate/certs/inter_ca.crt -outform PEM -days 365 -sha256 -extensions v3_intermediate -extfile intermediate/inter_ca_extensions.txt -CAcreateserial
```
Where the extfile will look like:
```ini
[ v3_intermediate ]
basicConstraints = critical, CA:TRUE, pathlen:0
subjectKeyIdentifier = hash
keyUsage = critical, keyCertSign, cRLSign
authorityKeyIdentifier = keyid:always
```

## App Server Setup

### Setup Private Key and CSR
This will be done on the app server (the app VM for this mini-project)

Setup another certs directory on the app server
- I will use /etc/nginx/ssl/private for private keys and /etc/nginx/ssl for certs and CSRs


1. Generate the private key
```bash
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/nginx/ssl/private/app_aaibim.key
```
- Here we are leaving out the cipher because we do not want the key to be encrypted. It can be but it cause s difficulties when a server restart happens or anything is needed where we would want to read this key automatically. If the key were to be read then it would need a passphrasse and it would have to be stored somewhere. Going to ensure that this directory and file can only be read by the root so it can not be exfiltrated by any user.

2. Generate the CSR
```bash
openssl req -new -key /etc/nginx/ssl/private/app_aaibim.key -outform PEM -out /etc/nginx/ssl/app_aaibim.csr -sha256 -addext "subjectAltName = DNS:app.aaibim.com"
```

5. Setup an openssh-server on the CA machine and allow connections from the app server
- There are notes about this at the bottom of the document

4. Copy the csr to the CA machine (from app server)
```bash
scp /etc/nginx/ssl/app_aaibim.csr <CA user>@<CA IP>:<path to your CA dir>/intermediate/csr/
```
- Think of this like adding the csr into the CAs inbox of CSR for the CA to handle
- Can verify this is the right csr on CA machine by running 
```bash
openssl req -in intermediate/csr/app_aaibim.csr -noout -text -verify
```

5. Set up an extensions file for this type of cert (can reuse for future certs to be issues)
- I put in /intermediate/server_extensions.txt
```ini
[ v3_server ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:app.aaibim.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
```

6. Sign and create the cert with the intermediate
```bash
openssl x509 -req \
  -in intermediate/csr/app_aaibim.csr \
  -CA intermediate/certs/inter_ca.crt \
  -CAkey intermediate/private/inter_ca.key \
  -CAcreateserial \
  -out intermediate/certs/app_aaibim.crt \
  -days 180 -sha256 \
  -extfile intermediate/server_extensions.txt -extensions v3_server
```

7. Can verify the chain worked:
```bash
openssl verify -CAfile root/certs/root_ca.crt -untrusted intermediate/certs/inter_ca.crt intermediate/certs/app_aaibim.crt
```

8. Now we need to build the full chain cert file (this is the one nginx will use)
```bash
cat intermediate/certs/app_aaibim.crt intermediate/certs/inter_ca.crt > intermediate/certs/app_aaibim_fullchain.crt
```

9. Finally, send it back to the app server
```bash
scp <CA user>@<CA IP>:<path to CA dir>/intermediate/certs/app_aaibim_fullchain.crt ~/
```

**Questions I had while doing this**
1. Whats the difference between cipher and algorithm?
- Algorithm is how the key is encrypted (what kind of key it is) (asymmetric encryption)
- Cipher is how the key is encrypted on disk (symmetric encryption)
    - Note that on ubuntu linux vm -cipher wasnt an option so just used -des3 for encrypting on disk
2. Items in -addext option when creating root CA cert
- The subjectKeyIdentifier is essentially an ID for the public key of the certificate being created. If CA name changes, this would still point to the right place, if the key is changed, then there would need to be changes down the chain. This is used so that we can build the "trust chain". A lower level cert that does not sign any others may have authorityKeyIdentifier which would be the subjectKeyIdentifier which then points to a private key that was used to sign the cert that is higher up on the chain. When we do subjectKeyIdentifier = hash, we are just saying that we are computing a hash of the certificates public key.
- The reason addext needs keyUsage is for verification, if something claims that this cert listed about is for digitalSignatures then that would be rejected as it is not stated. The reason we use keyCertSign is so that we can create intermediate certs likely for other actions like OCSP checks or signing documents. This cert needs to be the most safe so it has only the required things and should not be interacted with as much as possible.
3. Why not use ```openssl req ``` as a command for creating the intermediate cert?
- When creating an intermediate cert, we are not self signing, which is what the form is used for when creating things like private keys or certificates, so we will use something different in ```openssl x509```
4. When setting up on App Server, how do we communicate?
- In practice this can be one of the biggest headaches. Do we need to open firewalls? What IP addresses need to speak to eachother? Is there a VPN in place? Are they on the same network? What ports are open? Are protocols in place to be able to make this connection?
- For two VMs running on the same host computer this is pretty easy as they can just be both added to the host Network which gives them discoverable IPs from inbound connections, but in the real world this can cause a lot more difficulty.
- What protocol are we going to use to do this?
    - Here I am using ssh, so installing openssh on the CA machince, but this can also be done over HTTPS and other sorts. Tools like Venafi make this easier and all communication is done through SaaS or web apps.