let cropper;
const modal = document.getElementById('avatar-modal');
const img = document.getElementById('avatar-to-crop');
const input = document.getElementById('avatar-input');
const btn = document.getElementById('change-avatar-btn');
const closeBtn = document.querySelector('.close');
const cropBtn = document.getElementById('crop-avatar-btn');

btn.onclick = () => input.click();

input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        img.src = e.target.result;
        modal.style.display = 'block';
        img.onload = () => {
            if (cropper) cropper.destroy();
            try {
                cropper = new Cropper(img, {
                    aspectRatio: 1,
                    viewMode: 1,
                    autoCropArea: 1,
                    responsive: true,
                    background: false,
                });
                console.log('Cropper initialized');
            } catch (error) {
                console.error('Cropper init error:', error);
                alert('Ошибка загрузки редактора. Проверьте подключение библиотеки.');
            }
        };
    };
    reader.readAsDataURL(file);
};

closeBtn.onclick = () => {
    modal.style.display = 'none';
    if (cropper) cropper.destroy();
};

cropBtn.onclick = () => {
    if (!cropper) {
        alert('Редактор не готов');
        return;
    }

    const canvas = cropper.getCroppedCanvas({
        width: 300,
        height: 300,
        imageSmoothingEnabled: true,
        imageSmoothingQuality: 'high'
    });

    canvas.toBlob((blob) => {
        const formData = new FormData();
        formData.append('avatar', blob, 'avatar.png');

        fetch('/upload-avatar', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Ошибка при загрузке: ' + (data.error || 'Неизвестная ошибка'));
            }
        })
        .catch(error => {
            console.error('Fetch error:', error);
            alert('Ошибка сети');
        })
        .finally(() => {
            modal.style.display = 'none';
            if (cropper) cropper.destroy();
        });
    }, 'image/png');
};

window.onclick = (event) => {
    if (event.target == modal) {
        modal.style.display = 'none';
        if (cropper) cropper.destroy();
    }
};
