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
            if (!targetElement) return;

            const textToCopy = targetElement.innerText || targetElement.textContent;

            const showSuccess = (btn) => {
                const originalText = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> Copiat!';
                btn.classList.remove('btn-outline-secondary');
                btn.classList.add('btn-success');
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.classList.remove('btn-success');
                    btn.classList.add('btn-outline-secondary');
                }, 2000);
            };

            if (navigator.clipboard && window.isSecureContext) {
                // Modern, secure method
                navigator.clipboard.writeText(textToCopy).then(() => {
                    showSuccess(this);
                }).catch(err => {
                    console.error('Eroare la copierea textului cu navigator.clipboard: ', err);
                    alert('Eroare la copierea textului. Contactați administratorul.');
                });
            } else {
                // Fallback for non-secure contexts (e.g., HTTP)
                const textArea = document.createElement("textarea");
                textArea.value = textToCopy;
                textArea.style.position = "fixed"; // Prevent scrolling to bottom of page in MS Edge.
                textArea.style.top = "0";
                textArea.style.left = "0";
                textArea.style.width = "2em";
                textArea.style.height = "2em";
                textArea.style.padding = "0";
                textArea.style.border = "none";
                textArea.style.outline = "none";
                textArea.style.boxShadow = "none";
                textArea.style.background = "transparent";
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                try {
                    const successful = document.execCommand('copy');
                    if (successful) {
                        showSuccess(this);
                    } else {
                        throw new Error('Fallback copy was unsuccessful');
                    }
                } catch (err) {
                    console.error('Eroare la copierea textului (fallback): ', err);
                    alert('Eroare la copierea textului. Browserul dvs. este posibil să nu suporte această funcționalitate.');
                }
                document.body.removeChild(textArea);
            }
        });
    });
});
