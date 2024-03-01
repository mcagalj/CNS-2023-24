import { initiateAuthenticationAutofill } from './modules/webauthn_login.js'

window.addEventListener('load', async () => {
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isConditionalMediationAvailable) {
        // Check if conditional mediation is available.  
        const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
        if (isCMA) {
            await initiateAuthenticationAutofill();
        } else {
            info_board.style.display = 'block'
        }
    }
})