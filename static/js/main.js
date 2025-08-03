// JavaScript principal for GradatFinal Application

document.addEventListener('DOMContentLoaded', function() {
    // Dark Mode Toggle Functionality
    const toggleButton = document.getElementById('darkModeToggle');
    const body = document.body;
    const toggleIcon = toggleButton ? toggleButton.querySelector('i') : null;

    // Function to apply theme and update icon
    function applyTheme(theme) {
        if (theme === 'dark') {
            body.classList.add('dark-mode');
            if (toggleIcon) {
                toggleIcon.classList.remove('fa-moon');
                toggleIcon.classList.add('fa-sun');
            }
            localStorage.setItem('theme', 'dark');
        } else {
            body.classList.remove('dark-mode');
            if (toggleIcon) {
                toggleIcon.classList.remove('fa-sun');
                toggleIcon.classList.add('fa-moon');
            }
            localStorage.setItem('theme', 'light');
        }
    }

    if (toggleButton && toggleIcon) { // Ensure elements exist before proceeding
        // Load saved theme from localStorage or default to light
        let currentTheme = localStorage.getItem('theme') || 'light'; // Default to light
        applyTheme(currentTheme);

        // Add event listener for the toggle button
        toggleButton.addEventListener('click', function() {
            currentTheme = body.classList.contains('dark-mode') ? 'light' : 'dark';
            applyTheme(currentTheme);
        });
    } else {
        if (!toggleButton) console.warn("Dark mode toggle button not found.");
        if (!toggleIcon && toggleButton) console.warn("Dark mode toggle icon element not found within the button.");
    }

    console.log("Main JS loaded. Dark Mode functionality initialized if elements found.");

    // You can add other global JavaScript functionalities below
});
