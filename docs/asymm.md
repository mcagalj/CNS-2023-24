# **Kriptografija i mrežna sigurnost** <!-- omit in toc -->

- [Lab 7: Public key cryptography (RSA, Diffie-Hellman)](#lab-7-public-key-cryptography-rsa-diffie-hellman)
  - [Protokol za uspostavu zajedničkog ključa](#protokol-za-uspostavu-zajedničkog-ključa)
  - [Zadatak](#zadatak)
    - [Izvedite `key` za dekripciju](#izvedite-key-za-dekripciju)
  - [Implementacija u Python-u](#implementacija-u-python-u)
    - [Okvir rješenja](#okvir-rješenja)
    - [Implementacija u koracima](#implementacija-u-koracima)
      - [Step 2: Generate client RSA key pair](#step-2-generate-client-rsa-key-pair)
      - [Step 3: Exchnage RSA public keys and DH parameters](#step-3-exchnage-rsa-public-keys-and-dh-parameters)
      - [Step 4: Generate client DH key pair base on the DH parameters](#step-4-generate-client-dh-key-pair-base-on-the-dh-parameters)
      - [Step 5: Sign client DH public key with client's RSA private key](#step-5-sign-client-dh-public-key-with-clients-rsa-private-key)
      - [Step 6: Exchange signed DH public keys](#step-6-exchange-signed-dh-public-keys)
      - [Step 7: Verify authenticity of the server's DH public key, DH parameters](#step-7-verify-authenticity-of-the-servers-dh-public-key-dh-parameters)
      - [Step 8: Caculate DH shared secret](#step-8-caculate-dh-shared-secret)
      - [Step 9: Derive 256 bit decryption key](#step-9-derive-256-bit-decryption-key)


# Lab 7: Public key cryptography (RSA, Diffie-Hellman)

Student će realizirati sigurnosni protokol prikazan u nastavku. Protokol u osnovi implementira _Diffie-Hellman key exchange protocol_ i omogućava uspostavu dijeljenog simetričnog ključa između dva entiteta (klijent i server). Protokol koristi RSA kriptosustav za zaštitu integriteta Diffie-Hellman javnih ključeva. Uspostavljeni simetrični ključ koristi se za zaštitu povjerljivosti _challenge_-a.

>**DISCLAIMER: _U prikazanoj formi protokol nije siguran. Prikazani protokol služi isključivo za edukativnu svrhu._**

Iako prikazani protokol nije siguran, osnovni principi koji se koriste u protokolu približno prikazuju proces koji se odvija pri uspostavi npr. HTTPS/TLS i SSH sigurnih veza.

## Protokol za uspostavu zajedničkog ključa

Popis oznaka u protokolu:

| Oznaka                                 | Opis                                                            |
| -------------------------------------- | :-------------------------------------------------------------- |
| C                                      | klijent (student/ovo računalo)                                  |
| S                                      | server (_crypto oracle_)                                        |
| RSA<sub>priv</sub>, RSA<sub>pub</sub>  | privatni i javni RSA ključevi                                   |
| DH<sub>priv</sub>, DH<sub>pub</sub>    | privatni i javni DH ključevi                                    |  |
| DH<sub>params</sub>                    | javni DH parametri: _prime modulus_ (p) i _group generator_ (g) |
| **Sig**(RSA<sub>priv</sub></sub>, _m_) | RSA digitalno potpisana poruka _m_                              |
| `shared_secret`                        | dijeljena DH tajna (i.e., g<sup>xy</sup> mod p)                 |
| K                                      | Simetrični ključ izveden iz `shared_secret`                     |
| **AES-256-CBC**(K, _m_)                | enkripcija poruke _m_ ključem K u AES-CBC modu                  |
| _a_ \|\| _b_                           | konkatenacija (spajanje) poruka _a_ i _b_                       |

### Protokol <!-- omit in toc -->

| Tko šalje  | Poruka koja se šalje                                                                                                              |
| :--------: | :-------------------------------------------------------------------------------------------------------------------------------- |
| C &rarr; S | RSA<sub>pub,C</sub>                                                                                                               |
| S &rarr; C | RSA<sub>pub,S</sub>, DH<sub>params</sub>                                                                                          |
| C &rarr; S | DH<sub>pub,C</sub> \|\| **Sig**(RSA<sub>priv,C</sub></sub> , DH<sub>pub,C</sub>)                                                  |
| S &rarr; C | DH<sub>pub,S</sub> \|\| **Sig**(RSA<sub>priv,S</sub></sub> , DH<sub>params</sub> \|\| DH<sub>pub,S</sub> \|\| DH<sub>pub,C</sub>) |
| S &rarr; C | **AES-256-CBC**(K, "... Chuck Norris ...")                                                                                        |

> Primjetite da _challenge_ u posljednjoj poruci nije autenticiran; ne štitimo njegov integritet. U praksi, uz povjerljivost želite zaštititi i integritet poruke.

Klijent (C) i server (S), po uspješnoj razmjeni odgovarajućih poruka, provjeravaju digitalne potpise, zatim izvode zajedničku Diffie-Hellman tajnu `shared_secret`, te iz te tajne 256-bitni AES ključ K kojim se enkriptira studentova šala (u CBC modu). Ključ K izvodi se iz `shared_secret` vrijednosti primjenom [_hash-based key derivation function_](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/?highlight=hkdf) (HKDF) funkcije.

## Zadatak

Implementirati prikazani protokol i dekriptirati odgovarajući izazov.

Zadatak u fazama: `username & password` ⇒ `token` ⇒ `exchange_RSA_keys` ⇒ `exchange_signed_DH_keys` ⇒ `shared_secret` ⇒ `key` ⇒ `challenge`.

Prisjetite se, _password_ ste otkrili u prethodnoj vježbi.

### Izvedite `key` za dekripciju

Tekuća faza: `username & password` ⇒ `token` ⇒ `exchange_RSA_keys` ⇒ `exchange_signed_DH_keys` ⇒ `shared_secret` ⇒ **`key`** ⇒ `challenge`.

Dekripcijski ključ `key` izvodi se iz djeljene tajne `shared_secret`; [primjer iz serverskog koda](https://github.com/mcagalj/CNS-2023-24/blob/cfdd899365e6db478a88c84bd740ce81382b513f/crypto-oracle/app/routers/asymmetric.py#L146-L148).

## Implementacija u Python-u

### Okvir rješenja

```python
from base64 import b64decode, b64encode

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding as pkcs7_padding
from pydantic import BaseModel


class Ciphertext(BaseModel):
    iv: str
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def get_access_token(username, password, url):
    response = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password},
    )
    response.raise_for_status()
    return response.json().get("access_token")


def encrypt_chosen_plaintext(plaintext: str, token: str, url: str) -> str:
    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"plaintext": plaintext},
    )

    response.raise_for_status()
    return response.json()


def get_challenge(url):
    response = requests.get(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response.raise_for_status()
    return response.json()


def decrypt_challenge(key: bytes, challenge: Challenge) -> str:
    """Decrypts encrypted challenge; reveals a password that can be
    used to unlock the next task/challenge.
    """
    iv = b64decode(challenge.iv)
    ciphertext = b64decode(challenge.ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext += unpadder.finalize()
    return plaintext.decode()


def derive_key(key_seed: str, key_length=32) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b"",
        length=key_length,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key


def exchange_RSA_keys_and_DH_params( url, token, public_RSA_key):
    if isinstance(public_RSA_key, bytes):
        public_RSA_key = public_RSA_key.decode()

    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"key": public_RSA_key},
    )

    response.raise_for_status()
    key = response.json().get("key")
    dh_params = response.json().get("dh_params")
    return key, dh_params


def exchange_DH_keys(url, token, key, signature):
    if isinstance(key, bytes):
        key = key.decode()    
        
    if isinstance(signature, bytes):
        signature = b64encode(signature).decode()    

    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={
            "key": key,
            "signature": signature
        },
    )

    response.raise_for_status()
    key = response.json().get("key")
    signature = response.json().get("signature")
    return key, signature


if __name__ == "__main__":
    username = "doe_john"
    password = "rsancocily"    
    host = "10.0.15.16"


    # Step 1: Get the token
    path = "asymmetric/token"
    url = f"http://{host}/{path}"  
    token = get_access_token(username, password, url)
    print(f"Token: {token}")

    # ====================================
    #   PROTOCOL IMPLEMENTATION
    # ====================================    
    #----------------------------------------- 
    # Step 2: Generate client RSA key pair
    #----------------------------------------- 
    
    #----------------------------------------------------- 
    # Step 3: Exchnage RSA public keys and DH parameters
    #----------------------------------------------------- 

    #------------------------------------------------------------------ 
    # Step 4: Generate client DH key pair base on the DH parameters
    #------------------------------------------------------------------
    
    #------------------------------------------------------------------ 
    # Step 5: Sign client DH public key with client's RSA private key
    #------------------------------------------------------------------ 
    
    #----------------------------------------- 
    # Step 6: Exchange signed DH public keys
    #-----------------------------------------
    
    #--------------------------------------------------------------------------- 
    # Step 7: Verify authenticity of the server's DH public key, DH parameters
    #--------------------------------------------------------------------------- 
    
    #------------------------------------ 
    # Step 8: Caculate DH shared secret
    #------------------------------------ 
    
    #--------------------------------------- 
    # Step 9: Derive 256 bit decryption key
    #--------------------------------------- 
    
    #------------------------------------------------------------------ 
    # Step 10: Get the challenge and decrypt it using the derived key
    #------------------------------------------------------------------ 
    path = "asymmetric/challenge"
    url = f"http://{host}/{path}"
    response = get_challenge(url)
    challenge = Challenge(**response)
    decrypted_challenge = decrypt_challenge(key=key, challenge=challenge)
    
    print(f"\nDecrypted challenge:\n {decrypted_challenge}")
```

### Implementacija u koracima

#### Step 2: Generate client RSA key pair

```python
    client_RSA_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_RSA_public = client_RSA_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"Client RSA public:\n {client_RSA_public.decode()}")
```

#### Step 3: Exchnage RSA public keys and DH parameters

```python
    path = "asymmetric/exchange/rsa-dh-params"
    url = f"http://{host}/{path}"
    server_RSA_public, DH_parameters = exchange_RSA_keys_and_DH_params(
        url=url,
        token=token,
        public_RSA_key=client_RSA_public
    )
    
    print(f"Server RSA public:\n {server_RSA_public}")
    
    # De-serialize the RSA key and DH parameters
    server_RSA_public = serialization.load_pem_public_key(server_RSA_public.encode())
    DH_parameters = serialization.load_pem_parameters(DH_parameters.encode())
    
    print("Prime modulus p:", DH_parameters.parameter_numbers().p)
    print("The group generator g:", DH_parameters.parameter_numbers().g)
```

#### Step 4: Generate client DH key pair base on the DH parameters

```python
    client_DH_private = DH_parameters.generate_private_key()
    client_DH_public = client_DH_private.public_key()
    
    client_DH_public = client_DH_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"Client DH public:\n {client_DH_public.decode()}")    
```

#### Step 5: Sign client DH public key with client's RSA private key

```python
    signature = client_RSA_private.sign(
        client_DH_public,
        pkcs7_padding.PSS(
            mgf=pkcs7_padding.MGF1(hashes.SHA256()),
            salt_length=pkcs7_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
```

#### Step 6: Exchange signed DH public keys

```python
    path = "asymmetric/exchange/dh"
    url = f"http://{host}/{path}" 
    server_DH_public, signature = exchange_DH_keys(
        url=url, token=token, key=client_DH_public, signature=signature
    )
    
    print(f"Server DH public:\n {server_DH_public}")    
    print(f"Server DH public signature:\n{signature}")  
```

#### Step 7: Verify authenticity of the server's DH public key, DH parameters

```python
    signature = b64decode(signature)
    server_DH_public = server_DH_public.encode()
    DH_parameters = DH_parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.ParameterFormat.PKCS3
    ) 
    
    message = DH_parameters + server_DH_public + client_DH_public
    
    server_RSA_public.verify(
        signature,
        message,
        pkcs7_padding.PSS(
            mgf=pkcs7_padding.MGF1(hashes.SHA256()),
            salt_length=pkcs7_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
```

#### Step 8: Caculate DH shared secret

```python
    server_DH_public = serialization.load_pem_public_key(server_DH_public)
    shared_secret = client_DH_private.exchange(server_DH_public)
    
    print(f"Established shared secret:\n{shared_secret}")  
```

#### Step 9: Derive 256 bit decryption key

```python
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ServerClient",
        info=None
    ).derive(shared_secret)
    
    print(f"\nDecryption key:\n f{key} (length: {len(key)*8})")
```
