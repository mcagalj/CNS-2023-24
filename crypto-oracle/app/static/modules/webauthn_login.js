import base64url from "./base64url.js"
import { getChallenge } from "./webauthn_register.js"
import { log, logError, config } from "./logger.js"

config.log_el = document.querySelector('#log')

class Login {
    async init(event) {
        // 1. Get challenge from server (Relying Party)
        const challenge = await this.getLoginChallenge(event)
        log({ challenge })

        // 2. Use existing public key credential to authenticate user
        const credentials = await this.signWithPrivateKey(challenge)
        log({ credentials })

        // 3. Use public key credential to authenticate and login user
        const status = await this.loginWith(credentials)
        if (status && status.verified) alert(`Welcome ${status.username}\n\nSuccessful authentication!`)
        log({ status })
    }


    async getLoginChallenge(event) {
        return await getChallenge("/passkeys/login/", event)
    }

    async signWithPrivateKey(challengeObject) {
        const options = {
            mediation: 'optional',
            publicKey: challengeObject,
            userVerification: "preferred",
        }

        options.publicKey.allowCredentials = challengeObject.allowCredentials.map(credential => ({
            type: credential.type,
            id: base64url.decode(credential.id),
            transports: credential.transports
        }))
        options.publicKey.challenge = base64url.decode(challengeObject.challenge)

        try {
            const credentials = await navigator.credentials.get(options)

            const { id, rawId, response, type, authenticatorAttachment = null } = credentials;
            return ({
                id,
                rawId: base64url.encode(rawId),
                response: {
                    clientDataJSON: base64url.encode(response.clientDataJSON),
                    authenticatorData: base64url.encode(response.authenticatorData),
                    signature: base64url.encode(response.signature),
                    userHandle: response.userHandle ? base64url.encode(response.userHandle) : null
                },
                type,
                clientExtensionResults: credentials.getClientExtensionResults(),
                authenticatorAttachment
            })
        } catch (e) {
            logError(e)
        }
    }

    async loginWith(credentials) {
        try {
            const response = await fetch("/passkeys/login/verify/", {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials),
            });

            if (response.ok) {
                return await response.json()
            } else {
                alert(`${response.status}: ${response.statusText}`)
                logError(JSON.stringify(await response.json(), null, 2))
            }
        } catch (error) {
            logError(error);
        }
    }

}

class LoginAutofill {
    async init() {
        // 1. Get challenge from server (Relying Party)
        const challenge = await this.getLoginChallenge()
        log({ challenge })

        // 2. Use existing public key credential to authenticate user 
        const credentials = await this.signWithPrivateKey(challenge)
        log({ credentials })

        // 3. Use public key credential to authenticate and login user
        const status = await this.loginWith(credentials)
        if (status && status.verified) alert(`Welcome ${status.username}\n\nSuccessful authentication!`)
        log({ status })
    }

    async getLoginChallenge() {
        return await getChallenge("/passkeys/login-autofill/")
    }

    async signWithPrivateKey(challengeObject) {
        const options = {
            mediation: 'optional',
            publicKey:
            {
                challenge: base64url.decode(challengeObject.challenge)
            },
            userVerification: challengeObject?.userVerification ?? "preferred"
        }

        try {

            const credentials = await navigator.credentials.get(options)

            const { id, rawId, response, type, authenticatorAttachment = null } = credentials;
            return ({
                id,
                rawId: base64url.encode(rawId),
                response: {
                    clientDataJSON: base64url.encode(response.clientDataJSON),
                    authenticatorData: base64url.encode(response.authenticatorData),
                    signature: base64url.encode(response.signature),
                    userHandle: response.userHandle ? base64url.encode(response.userHandle) : null
                },
                ...(authenticatorAttachment !== null ? { authenticatorAttachment } : {}),
                type,
            })
        } catch (e) {
            logError(e)
        }
    }

    async loginWith(credentials) {
        try {
            const response = await fetch("/passkeys/login-autofill/verify/", {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials),
            });

            if (response.ok) {
                return await response.json()
            } else {
                alert(`${response.status}: ${response.statusText}`)
                logError(JSON.stringify(await response.json(), null, 2))
            }
        } catch (error) {
            logError(error);
        }
    }

}

export async function initiateAuthentication(event) {
    event.preventDefault()
    const login = new Login()
    await login.init(event)
}

export async function initiateAuthenticationAutofill() {
    const login = new LoginAutofill()
    await login.init()
}