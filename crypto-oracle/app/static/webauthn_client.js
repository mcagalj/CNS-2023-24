import { initiateRegistration } from './modules/webauthn_register.js'
import { initiateAuthentication } from './modules/webauthn_login.js'

document.querySelector("#registration-form").addEventListener("submit", (event) => initiateRegistration(event))
document.querySelector("#authentication-form").addEventListener("submit", (event) => initiateAuthentication(event))

window.addEventListener('load', async () => {
    if (!window.PublicKeyCredential) {
        const form_container = document.getElementById('form-container')
        const info_board = document.getElementById('info-board')
        form_container.style.display = 'none'
        log_el.style.display = 'none'
        info_board.style.display = 'block'
    }
})

