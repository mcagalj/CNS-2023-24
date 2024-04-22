# **Kriptografija i mrežna sigurnost** <!-- omit in toc -->

- [Lab 7: Public key cryptography (RSA, Diffie-Hellman)](#lab-7-public-key-cryptography-rsa-diffie-hellman)
  - [Protokol za uspostavu zajedničkog ključa](#protokol-za-uspostavu-zajedničkog-ključa)
  - [Zadatak](#zadatak)
    - [Izvedite `key` za dekripciju](#izvedite-key-za-dekripciju)


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
