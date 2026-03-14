// Ждем загрузки DOM
document.addEventListener('DOMContentLoaded', function() {
    // Находим все формы для удаления постов
    const deleteForms = document.querySelectorAll('.delete-post-form');
    
    // Для каждой формы добавляем обработчик
    deleteForms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            // Показываем подтверждение
            if (!confirm('Удалить пост?')) {
                // Если пользователь нажал "Отмена" - отменяем отправку формы
                event.preventDefault();
            }
            // Если подтвердил - форма отправится как обычно
        });
    });
});