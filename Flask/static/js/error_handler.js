function closeMessage() {
    $(".alert").fadeTo(500, 0).slideUp(500, function () {
        $(this).remove();
    });
}

$(function () {
    // When the document is ready, activate the pill functionality
    $('.nav-pills a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    });
});

$(function () {
    // Funkcia na aktualizáciu aktívneho stavu na navigačných odkazoch
    function updateActiveNavLink() {
        // Získajte aktuálnu cestu z URL
        var currentPath = window.location.pathname;

        // Odstráňte triedu 'active' zo všetkých odkazov
        $('.nav-tabs .nav-item .nav-link').removeClass('active show');

        // Pridajte triedu 'active' na odkaz, ktorý zodpovedá aktuálnej ceste
        $('.nav-tabs .nav-item .nav-link').each(function () {
            var linkPath = $(this).attr('href');
            if (linkPath === currentPath) {
                $(this).addClass('active show');
            }
        });
    }

    // Aktualizujte aktívne odkazy pri načítaní stránky
    updateActiveNavLink();
});