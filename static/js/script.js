document.addEventListener('DOMContentLoaded', function() {
    const adminCheckbox = document.getElementById('is_admin');
    const adminCodeField = document.querySelector('.admin-code-field');

    if (adminCheckbox && adminCodeField) {
        adminCheckbox.addEventListener('change', function() {
            if (this.checked) {
                adminCodeField.style.display = 'block';
                setTimeout(() => adminCodeField.classList.add('visible'), 50);
            } else {
                adminCodeField.classList.remove('visible');
                setTimeout(() => adminCodeField.style.display = 'none', 300);
            }
        });
    }
});