document.addEventListener('DOMContentLoaded', function() {
    const deleteForms = document.querySelectorAll('.delete-post-form');
    deleteForms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!confirm('Удалить пост?')) {
                event.preventDefault();
            }
        });
    });
});