/**
 * Hall Photography - Profile JavaScript
 * Specific functionality for the user profile page
 */

class ProfilePage {
  constructor() {
    this.init();
  }

  init() {
    this.setupStatsAnimation();
    this.setupProfileInteractions();
  }

  /**
   * Setup animated statistics
   */
  setupStatsAnimation() {
    const observerOptions = {
      threshold: 0.5,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          this.animateStats(entry.target);
          observer.unobserve(entry.target);
        }
      });
    }, observerOptions);

    // Observe profile stats
    const profileStats = document.querySelector('.profile-stats');
    if (profileStats) {
      observer.observe(profileStats);
    }
  }

  /**
   * Animate statistics counters
   */
  animateStats(container) {
    const statNumbers = container.querySelectorAll('.stat-number');
    
    statNumbers.forEach(stat => {
      const finalValue = stat.textContent;
      const isDecimal = finalValue.includes('.');
      const targetValue = isDecimal ? parseFloat(finalValue) : parseInt(finalValue);
      
      if (window.hallPhotography) {
        window.hallPhotography.animateCounter(stat, targetValue);
      } else {
        // Fallback animation
        this.animateCounter(stat, targetValue);
      }
    });
  }

  /**
   * Fallback counter animation
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

  /**
   * Setup profile-specific interactions
   */
  setupProfileInteractions() {
    // Profile picture hover effect
    const profilePicture = document.querySelector('.profile-picture');
    if (profilePicture) {
      profilePicture.addEventListener('mouseenter', () => {
        profilePicture.style.transform = 'scale(1.05)';
        profilePicture.style.boxShadow = 'var(--shadow-strong)';
      });

      profilePicture.addEventListener('mouseleave', () => {
        profilePicture.style.transform = 'scale(1)';
        profilePicture.style.boxShadow = 'var(--shadow-medium)';
      });
    }

    // Stat items hover effects
    const statItems = document.querySelectorAll('.stat-item');
    statItems.forEach(item => {
      item.addEventListener('mouseenter', () => {
        item.style.transform = 'translateY(-5px)';
        item.style.boxShadow = 'var(--shadow-medium)';
      });

      item.addEventListener('mouseleave', () => {
        item.style.transform = 'translateY(0)';
        item.style.boxShadow = 'var(--shadow-soft)';
      });
    });
  }
}

// Initialize profile page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  if (document.body.classList.contains('profile-page')) {
    new ProfilePage();
  }
});
