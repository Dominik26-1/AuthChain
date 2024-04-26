document.addEventListener("DOMContentLoaded", function() {
    var timeout;

    function resetTimer() {
        clearTimeout(timeout);
        // Nastaviť timeout na 15 minút (900 000 milisekúnd)
        timeout = setTimeout(function() {
            alert("Boli ste odhlásený kvôli dlhšej nečinnosti.");
            // Tu môžete pridať ďalšiu logiku pre odhlásenie alebo presmerovanie
            window.location = '/'; // Presmerovanie na stránku prihlásenia
        }, 900000); // 15 minút = 900 000 milisekúnd
    }

    // Resetovať timer pri akýchkoľvek interakciách
    window.onload = resetTimer;
    document.onmousemove = resetTimer;
    document.onkeypress = resetTimer;
});