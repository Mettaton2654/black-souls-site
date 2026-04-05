(function () {
    const menu = document.getElementById('navMenu');
    const toggleButton = document.getElementById('mobileMenuBtn');

    if (!menu || !toggleButton) {
        return;
    }

    const updateAria = (expanded) => {
        toggleButton.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    };

    const closeMenu = () => {
        menu.classList.remove('active');
        updateAria(false);
    };

    const openMenu = () => {
        menu.classList.add('active');
        updateAria(true);
    };

    const toggleMenu = () => {
        const isOpen = menu.classList.toggle('active');
        updateAria(isOpen);
    };

    toggleButton.addEventListener('click', (event) => {
        event.preventDefault();
        toggleMenu();
    });
    document.addEventListener('click', (event) => {
        if (!menu.contains(event.target) && !toggleButton.contains(event.target)) {
            closeMenu();
        }
    });
    const onResize = () => {
        if (window.innerWidth > 768) {
            closeMenu();
        }
    };

    window.addEventListener('resize', onResize);
    onResize();
})();
