function scrollToBottom() {
    config.log_el.scrollTop = config.log_el.scrollHeight;
}

function getCurrentTimestamp() {
    const now = new Date();
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const seconds = now.getSeconds().toString().padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

export const config = {
    log_el: null
}

export function log(...messages) {
    const timestamp = getCurrentTimestamp();
    const logMessage = messages.map(m => JSON.stringify(m, null, 2)).join(' ');
    const logEntry = `${timestamp} ℹ️ -> ${logMessage}`;

    console.log(...messages);
    config.log_el.innerText += '\n\n' + logEntry;
    scrollToBottom()
}

export function logError(message) {
    const timestamp = getCurrentTimestamp();
    const logEntry = `${timestamp} ❌ -> ${message}`;

    console.error(message);
    config.log_el.innerText += '\n\n' + logEntry;
    scrollToBottom()
    throw Error('got error: ' + message);
}
