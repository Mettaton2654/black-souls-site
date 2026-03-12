// Navigation / mobile menu behavior
// This script avoids inline JS so it works with CSP and keeps behavior consistent.

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

    // Close menu when clicking outside (mobile)
    document.addEventListener('click', (event) => {
        if (!menu.contains(event.target) && !toggleButton.contains(event.target)) {
            closeMenu();
        }
    });

    // Close menu if resizing to desktop width
    const onResize = () => {
        if (window.innerWidth > 768) {
            closeMenu();
        }
    };

    window.addEventListener('resize', onResize);

    // Ensure correct initial state
    onResize();
})();
