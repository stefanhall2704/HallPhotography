/**
 * Hall Photography - Main JavaScript
 * Common functionality shared across all pages
 */

class HallPhotography {
  constructor() {
    this.init();
  }

  init() {
    this.setupThemeToggle();
    this.setupNavigation();
    this.setupSmoothScrolling();
    this.setupFormValidation();
    this.setupAnimations();
  }

  /**
   * Theme Toggle Functionality
   */
  setupThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    const body = document.body;

    if (!themeToggle || !themeIcon) return;

    // Load saved theme
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
      body.setAttribute('data-theme', savedTheme);
      this.updateThemeIcon(themeIcon, savedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      body.setAttribute('data-theme', 'dark');
      this.updateThemeIcon(themeIcon, 'dark');
    }

    // Theme toggle handler
    themeToggle.addEventListener('click', () => {
      const currentTheme = body.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      body.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      this.updateThemeIcon(themeIcon, newTheme);
    });
  }

  updateThemeIcon(icon, theme) {
    icon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
  }

  /**
   * Navigation Functionality
   */
  setupNavigation() {
    const navbar = document.getElementById('navbar');
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    const navMenu = document.querySelector('.nav-menu');

    // Navbar scroll effect
    if (navbar) {
      window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
          navbar.classList.add('scrolled');
        } else {
          navbar.classList.remove('scrolled');
        }
      });
    }

    // Mobile menu toggle
    if (mobileMenuToggle && navMenu) {
      mobileMenuToggle.addEventListener('click', () => {
        navMenu.classList.toggle('active');
      });
    }
  }

  /**
   * Smooth Scrolling for Anchor Links
   */
  setupSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
      anchor.addEventListener('click', (e) => {
        e.preventDefault();
        const target = document.querySelector(anchor.getAttribute('href'));
        if (target) {
          target.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
          });
        }
      });
    });
  }

  /**
   * Form Validation and Enhancement
   */
  setupFormValidation() {
    // Phone number formatting
    const phoneInputs = document.querySelectorAll('input[type="tel"]');
    phoneInputs.forEach(input => {
      input.addEventListener('input', (e) => {
        e.target.value = this.formatPhoneNumber(e.target.value);
      });
    });

    // Password validation
    const passwordInputs = document.querySelectorAll('input[name="password"], input[name="verify_password"]');
    passwordInputs.forEach(input => {
      input.addEventListener('input', () => {
        this.validatePasswords();
      });
    });
  }

  formatPhoneNumber(value) {
    const cleaned = value.replace(/\D/g, '');
    let formatted = '';

    if (cleaned.length > 0) {
      formatted += '(';
    }
    if (cleaned.length > 3) {
      formatted += cleaned.substring(0, 3) + ') ';
    } else {
      formatted += cleaned;
    }
    if (cleaned.length > 6) {
      formatted += cleaned.substring(3, 6) + '-';
    } else if (cleaned.length > 3) {
      formatted += cleaned.substring(3);
    }
    if (cleaned.length > 10) {
      formatted += cleaned.substring(6, 10);
    } else if (cleaned.length > 6) {
      formatted += cleaned.substring(6);
    }
    return formatted;
  }

  validatePasswords() {
    const password = document.getElementById('password')?.value;
    const verifyPassword = document.getElementById('verify_password')?.value;
    const indicator = document.getElementById('password-match-indicator');

    if (!password || !verifyPassword || !indicator) return;

    if (password === verifyPassword && this.validatePasswordRequirements(password)) {
      indicator.textContent = "✓ Passwords match and meet requirements";
      indicator.classList.remove('error');
      indicator.classList.add('success');
      indicator.style.display = "block";
    } else if (password !== verifyPassword && verifyPassword.length > 0) {
      indicator.textContent = "✗ Passwords do not match";
      indicator.classList.remove('success');
      indicator.classList.add('error');
      indicator.style.display = "block";
    } else if (!this.validatePasswordRequirements(password) && password.length > 0) {
      indicator.textContent = "✗ Password must be at least 8 characters with uppercase, lowercase, number, and special character";
      indicator.classList.remove('success');
      indicator.classList.add('error');
      indicator.style.display = "block";
    } else {
      indicator.style.display = "none";
    }
  }

  validatePasswordRequirements(password) {
    const passwordRequirements = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
    return password.match(passwordRequirements);
  }

  /**
   * Animation Setup
   */
  setupAnimations() {
    // Intersection Observer for animations
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
        }
      });
    }, observerOptions);

    // Observe elements with animation classes
    document.querySelectorAll('.fade-in, .session-card, .stat-item').forEach(element => {
      observer.observe(element);
    });
  }

  /**
   * Utility Methods
   */
  showMessage(message, type = 'info', duration = 3000) {
    // Remove existing messages
    const existingMessage = document.querySelector('.message');
    if (existingMessage) {
      existingMessage.remove();
    }

    const messageDiv = document.createElement('div');
    messageDiv.className = `message message-${type}`;
    messageDiv.style.cssText = `
      position: fixed;
      top: 20px;
      left: 50%;
      transform: translateX(-50%);
      padding: 12px 24px;
      border-radius: 25px;
      color: white;
      font-weight: 500;
      z-index: 1000;
      animation: slideDown 0.3s ease-out;
      max-width: 90%;
      text-align: center;
      ${this.getMessageColor(type)}
    `;
    messageDiv.textContent = message;

    document.body.appendChild(messageDiv);

    // Auto remove
    setTimeout(() => {
      messageDiv.style.animation = 'slideUp 0.3s ease-out forwards';
      setTimeout(() => messageDiv.remove(), 300);
    }, duration);
  }

  getMessageColor(type) {
    const colors = {
      success: 'background: var(--soft-sage);',
      error: 'background: var(--deep-rust);',
      warning: 'background: var(--golden-yellow); color: var(--charcoal);',
      info: 'background: var(--burnt-orange);'
    };
    return colors[type] || colors.info;
  }

  /**
   * Form Submission Enhancement
   */
  enhanceFormSubmission(formId, submitUrl, successCallback) {
    const form = document.getElementById(formId);
    if (!form) return;

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      
      const submitBtn = form.querySelector('button[type="submit"]');
      const originalText = submitBtn.innerHTML;

      // Show loading state
      submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
      submitBtn.disabled = true;

      // Collect form data
      const formData = new FormData(form);

      // Send request
      fetch(submitUrl, {
        method: 'POST',
        body: formData
      })
      .then(response => {
        if (response.ok) {
          this.showMessage('Success!', 'success');
          if (successCallback) successCallback();
        } else {
          throw new Error('Request failed');
        }
      })
      .catch(error => {
        this.showMessage('Something went wrong. Please try again.', 'error');
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
      });
    });
  }

  /**
   * Counter Animation
   */
  animateCounter(element, targetValue, duration = 2000) {
    const isDecimal = targetValue.toString().includes('.');
    const finalValue = isDecimal ? parseFloat(targetValue) : parseInt(targetValue);
    
    let currentValue = 0;
    const increment = finalValue / (duration / 30);
    
    const timer = setInterval(() => {
      currentValue += increment;
      if (currentValue >= finalValue) {
        currentValue = finalValue;
        clearInterval(timer);
      }
      element.textContent = isDecimal ? currentValue.toFixed(1) : Math.floor(currentValue);
    }, 30);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.hallPhotography = new HallPhotography();
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = HallPhotography;
}
