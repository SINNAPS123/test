// JavaScript principal for GradatFinal Application

document.addEventListener('DOMContentLoaded', function() {
    // Loading Overlay Functionality
    const loadingOverlay = document.getElementById('loading-overlay');

    // Function to show the overlay
    function showLoader() {
        if (loadingOverlay) {
            loadingOverlay.classList.add('show');
        }
    }

    // Function to hide the overlay
    function hideLoader() {
        if (loadingOverlay) {
            loadingOverlay.classList.remove('show');
        }
    }

    // Show loader for navigation clicks
    document.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', function(e) {
            // Don't show loader for links opening in a new tab, or for javascript:void(0) links
            if (this.target === '_blank' || this.href.startsWith('javascript:')) {
                return;
            }
            // Also don't show for anchor links on the same page
            if (this.hash && (this.pathname === window.location.pathname)) {
                return;
            }
            showLoader();
        });
    });

    // Show loader for form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function() {
            showLoader();
        });
    });

    // Hide loader when the page is fully loaded
    window.addEventListener('load', hideLoader);

    // Hide loader if the user navigates back in history
    window.addEventListener('pageshow', function(event) {
        // The pageshow event is fired when a session history entry is traversed.
        // If the page is loaded from the cache (bfcache), we hide the loader.
        if (event.persisted) {
            hideLoader();
        }
    });


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

    // Copy to Clipboard Functionality
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', function() {
            const targetSelector = this.dataset.target;
            const targetElement = document.querySelector(targetSelector);
            if (targetElement) {
                const textToCopy = targetElement.innerText || targetElement.textContent;
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check"></i> Copiat!';
                    this.classList.remove('btn-outline-secondary');
                    this.classList.add('btn-success');
                    setTimeout(() => {
                        this.innerHTML = originalText;
                        this.classList.remove('btn-success');
                        this.classList.add('btn-outline-secondary');
                    }, 2000);
                }).catch(err => {
                    console.error('Eroare la copierea textului: ', err);
                    alert('Eroare la copierea textului. Este posibil ca browserul dvs. să nu suporte această funcționalitate.');
                });
            }
        });
    });
});
