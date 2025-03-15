document.addEventListener('DOMContentLoaded', function () {
    var passwordInput = document.getElementById('password');
    passwordInput.addEventListener('input', checkPasswordStrength);
});

function calculateEntropy(password) {
    const lower_case = "abcdefghijklmnopqrstuvwxyz";
    const upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const digits = "0123456789";
    const special_characters = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~";
    
    let characterSet = "";

    if (/[a-z]/.test(password)) characterSet += lower_case;
    if (/[A-Z]/.test(password)) characterSet += upper_case;
    if (/\d/.test(password)) characterSet += digits;
    if (/[!@#$%^&*()\-_=+\[\]{}|;:',.<>?\/`~]/.test(password)) characterSet += special_characters;

    const R = characterSet.length;
    const L = password.length;
    
    const entropy = Math.log2(R) * L;
    return entropy;
}

function checkPasswordStrength() {
    var password = document.getElementById('password').value;
    var strengthLabel = document.getElementById('password-strength');
    
    var entropy = calculateEntropy(password);
    
    if (entropy < 60) {
        strengthLabel.textContent = 'Password Strength: Weak';
    } else if (entropy < 100) {
        strengthLabel.textContent = 'Password Strength: Medium';
    } else {
        strengthLabel.textContent = 'Password Strength: Strong';
    }
}
