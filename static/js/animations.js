window.addEventListener('scroll', function() {
    const scrolled = window.pageYOffset;
    document.body.style.backgroundPositionY = -(scrolled * 0.3) + 'px';
});