/**
 * Hall's Photography - Authentication JavaScript
 * Specific functionality for login and signup pages
 */

class AuthPage {
  constructor() {
    this.init();
  }

  init() {
    this.setupLoginForm();
    this.setupSignupForm();
  }

  /**
   * Setup login form functionality
   */
  setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    if (!loginForm) return;

    loginForm.addEventListener('submit', (e) => {
      e.preventDefault();

      const username = document.getElementById('username')?.value;
      const password = document.getElementById('password')?.value;
      const submitBtn = loginForm.querySelector('button[type="submit"]');
      const originalText = submitBtn.innerHTML;

      // Basic validation
      if (!username || !password) {
        window.hallPhotography?.showMessage('Please enter both username and password.', 'error');
        return;
      }

      // Show loading state
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';
      submitBtn.disabled = true;

      // Send login request
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/login/process');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      
      xhr.onload = function() {
        if (xhr.status === 200) {
          window.hallPhotography?.showMessage('Login successful! Redirecting...', 'success');
          setTimeout(() => {
            window.location.href = "/";
          }, 1000);
        } else {
          window.hallPhotography?.showMessage('Login failed. Please check your credentials.', 'error');
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        }
      };

      xhr.onerror = function() {
        window.hallPhotography?.showMessage('Network error. Please try again.', 'error');
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
      };

      xhr.send('username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
    });
  }

  /**
   * Setup signup form functionality
   */
  setupSignupForm() {
    const registerForm = document.getElementById('registerForm');
    if (!registerForm) return;

    registerForm.addEventListener('submit', (e) => {
      const password = document.getElementById('password')?.value;
      const verifyPassword = document.getElementById('verify_password')?.value;
      const submitBtn = registerForm.querySelector('button[type="submit"]');
      const originalText = submitBtn.innerHTML;

      // Validate passwords match
      if (password !== verifyPassword) {
        e.preventDefault();
        window.hallPhotography?.showMessage('Passwords do not match. Please check and try again.', 'error');
        return;
      }

      // Validate password requirements
      if (!this.validatePasswordRequirements(password)) {
        e.preventDefault();
        window.hallPhotography?.showMessage('Password does not meet requirements. Please check and try again.', 'error');
        return;
      }

      // Show loading state
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Account...';
      submitBtn.disabled = true;
    });
  }

  validatePasswordRequirements(password) {
    const passwordRequirements = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    return password.match(passwordRequirements);
  }
}

// Initialize auth page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  if (document.body.classList.contains('auth-page')) {
    new AuthPage();
  }
});
