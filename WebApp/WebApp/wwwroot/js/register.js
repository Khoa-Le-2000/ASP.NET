var password = document.getElementById("Password"),
    confirm_password = document.getElementById("PasswordConfirm");

function validatePassword() {
    if (password.value != confirm_password.value) {
        ValPasswordConfirm.value = "Passwords Don't Match";
    } else {
        ValPasswordConfirm.value = "";
    }
}

password.onchange = validatePassword;
confirm_password.onkeyup = validatePassword;