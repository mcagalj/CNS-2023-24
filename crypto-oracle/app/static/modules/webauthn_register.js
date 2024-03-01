import base64url from "./base64url.js"
import { log, logError, config } from "./logger.js"

config.log_el = document.querySelector('#log')

class Register {
    async init(event) {
        // 1. Get Challenge from server (Relying Party)
        const challenge = await this.getRegistrationChallenge(event)
        if (!challenge) {
            alert('Error: challenge not generated')
            logError("Challenge not generated")
        }
        log({ challenge })

        // 2. Use challenge to create public key credential pair
        const credentials = await this.createPublicKeyPairWith(challenge)
        log({ credentials })

        // 3. Send publicKey+challenge to server to create new user
        const status = await this.loginWith(credentials)
        if (status && status.verified) alert(`Welcome ${status.username}\n\nSuccessful registration!`)
        log({ status })
    }

    async getRegistrationChallenge(event) {
        return await getChallenge("/passkeys/register/", event)
    }

    async createPublicKeyPairWith(challengeObject) {
        const options = {
            publicKey: challengeObject
        }
        options.publicKey.user.id = base64url.decode(challengeObject.user.id)
        options.publicKey.challenge = base64url.decode(challengeObject.challenge)
        options.publicKey.authenticatorSelection = {
            userVerification: 'preferred',
        }

        const credentials = await navigator.credentials.create(options);

        const { id, rawId, response, type, authenticatorAttachment = null } = credentials;
        return ({
            id,
            rawId: base64url.encode(rawId),
            response: {
                attestationObject: base64url.encode(response.attestationObject),
                clientDataJSON: base64url.encode(response.clientDataJSON),
                publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
                publicKey: base64url.encode(response.getPublicKey()),
                authenticatorData: base64url.encode(response.getAuthenticatorData()),
            },
            type,
            transports: response.getTransports() ?? null,
            clientExtensionResults: credentials.getClientExtensionResults(),
            authenticatorAttachment
        })

    }

    async loginWith(credentials) {
        try {
            const response = await fetch("/passkeys/register/verify/", {
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

export async function getChallenge(path, event = null) {
    try {
        const response = await fetch(path, {
            method: 'POST',
            headers: {
                'Accept': 'application/json'
            },
            body: event ? new FormData(event.target) : null
        });
        if (response.ok) {
            event?.target.reset();
            const responseData = await response.json()
            try {
                return JSON.parse(responseData)
            } catch {
                return responseData
            }
        } else {
            const error = await response.json()
            switch (response.status) {
                case 422:
                    alert(`${response.status}: ${response.statusText}\n\n${error.detail[0].msg}`)
                    logError(JSON.stringify(error, null, 2))
                default:
                    alert(`${response.status}: ${response.statusText}` + (error.detail ? `\n\n${error.detail}` : ''))
                    logError(JSON.stringify(error, null, 2))
            }
        }
    } catch (error) {
        logError(error);
    }
}


export async function initiateRegistration(event) {
    event.preventDefault()
    const register = new Register()
    await register.init(event)
}