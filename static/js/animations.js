// Параллакс фона при скролле (лёгкий эффект)
window.addEventListener('scroll', function() {
    const scrolled = window.pageYOffset;
    document.body.style.backgroundPositionY = -(scrolled * 0.3) + 'px';
});

// Добавим класс для анимации появления карточек при скролле (если не используем AOS)
// Но наши карточки уже имеют анимацию при загрузке. Можно добавить дополнительный эффект при наведении.