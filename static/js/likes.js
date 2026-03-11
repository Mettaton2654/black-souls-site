document.addEventListener('DOMContentLoaded', () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

    if (!csrfToken) return;

    document.querySelectorAll('.like-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            const postId = this.dataset.postId;
            if (!postId) return;

            fetch(`/post/${postId}/like`, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrfToken
                }
            })
            .then(response => response.json())
            .then(data => {
                this.classList.toggle('liked', data.liked);
                const count = this.querySelector('.like-count');
                if (count) count.textContent = data.count;
            })
            .catch(error => console.error('Like error:', error));
        });
    });
});
