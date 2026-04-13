(function() {
        // Функция форматирования локальной даты и времени
        function formatDateTime(isoString, format = 'datetime') {
            if (!isoString) return '';
            try {
                const d = new Date(isoString);
                if (isNaN(d.getTime())) return isoString; // fallback
                const opts = {
                    datetime: { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' },
                    date: { day: '2-digit', month: '2-digit', year: 'numeric' },
                    time: { hour: '2-digit', minute: '2-digit' }
                };
                return d.toLocaleString('ru-RU', opts[format] || opts.datetime).replace(',', '');
            } catch(e) {
                return isoString;
            }
        }

        // Автоматически обрабатываем все элементы с атрибутом data-utc
        document.querySelectorAll('[data-utc]').forEach(el => {
            const utc = el.getAttribute('data-utc');
            const format = el.getAttribute('data-format') || 'datetime';
            el.textContent = formatDateTime(utc, format);
        });
    })();