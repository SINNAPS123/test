// JavaScript principal for GradatFinal Application

document.addEventListener('DOMContentLoaded', function() {
    // Dark Mode Toggle Functionality for DaisyUI
    const toggleButton = document.getElementById('darkModeToggle');
    const htmlElement = document.documentElement;

    // Function to apply theme
    function applyTheme(theme) {
        htmlElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    }

    if (toggleButton) {
        // Load saved theme from localStorage or default to 'light'
        let currentTheme = localStorage.getItem('theme') || 'light';
        applyTheme(currentTheme);

        // Add event listener for the toggle button
        toggleButton.addEventListener('click', function() {
            const newTheme = htmlElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            applyTheme(newTheme);
        });
    } else {
        console.warn("Dark mode toggle button not found.");
    }

    console.log("Main JS loaded for DaisyUI themes.");

    // You can add other global JavaScript functionalities below
});
