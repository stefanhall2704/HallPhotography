/**
 * Hall's Photography - Homepage JavaScript
 * Specific functionality for the homepage
 */

class HomePage {
  constructor() {
    this.init();
  }

  init() {
    this.loadMinisSessions();
    this.setupGalleryInteractions();
  }

  /**
   * Load and display mini sessions
   */
  async loadMinisSessions() {
    try {
      const res = await fetch('/get/minis_session');
      if (!res.ok) {
        throw new Error('Failed to load sessions');
      }
      const sessions = await res.json();
      this.displaySessions(sessions);
    } catch (err) {
      console.error('Error loading sessions:', err);
      this.showErrorState();
    }
  }

  displaySessions(sessions) {
    const list = document.getElementById('minis-sessions-list');
    if (!list) return;

    const now = new Date();
    const upcoming = [];

    // Process sessions to find upcoming ones with available slots
    for (const session of sessions) {
      if (!Array.isArray(session.Days)) continue;

      for (const day of session.Days) {
        const start = new Date(day.Start);
        const end = new Date(day.End);
        if (end <= now || start <= now) continue;

        try {
          // Check for available slots
          this.checkAvailableSlots(day).then(slots => {
            if (slots && slots.length > 0) {
              upcoming.push({ session, day, slots });
              this.renderSessions(upcoming, list);
            }
          });
        } catch (err) {
          console.error('Failed to load slots', err);
        }
      }
    }

    // If no sessions found, show empty state
    if (upcoming.length === 0) {
      this.showEmptyState(list);
    }
  }

  async checkAvailableSlots(day) {
    try {
      const slotRes = await fetch(`/get/days?start=${encodeURIComponent(day.Start)}&end=${encodeURIComponent(day.End)}`);
      if (!slotRes.ok) return [];
      
      const slotData = await slotRes.json();
      const dateKey = day.Start.split('T')[0];
      return slotData[dateKey] || [];
    } catch (err) {
      console.error('Error checking slots:', err);
      return [];
    }
  }

  renderSessions(upcoming, container) {
    if (upcoming.length === 0) {
      this.showEmptyState(container);
      return;
    }

    // Clear loading spinner
    container.innerHTML = '';

    upcoming.forEach(({ session, day, slots }, index) => {
      const card = document.createElement('div');
      card.className = 'session-card';
      card.style.animationDelay = `${index * 0.2}s`;

      const startDate = new Date(day.Start);
      
      card.innerHTML = `
        <h3 class="session-title">${session.Name}</h3>
        <p class="session-description">${session.Description}</p>
        <div class="session-meta">
          <span class="session-date">
            <i class="fas fa-calendar"></i>
            ${startDate.toLocaleDateString('en-US', { 
              weekday: 'long', 
              year: 'numeric', 
              month: 'long', 
              day: 'numeric' 
            })}
          </span>
          <span class="session-slots">
            <i class="fas fa-clock"></i>
            ${slots.length} slots
          </span>
        </div>
        <a href="/book_minis" class="btn btn-primary">
          <i class="fas fa-calendar-plus"></i>
          Book Now
        </a>
      `;

      container.appendChild(card);
    });
  }

  showEmptyState(container) {
    container.innerHTML = `
      <div class="session-card" style="grid-column: 1 / -1; text-align: center;">
        <h3 class="session-title">No Upcoming Sessions</h3>
        <p class="session-description">Check back soon for new mini session opportunities!</p>
      </div>
    `;
  }

  showErrorState() {
    const list = document.getElementById('minis-sessions-list');
    if (!list) return;

    list.innerHTML = `
      <div class="session-card" style="grid-column: 1 / -1; text-align: center;">
        <h3 class="session-title">Unable to Load Sessions</h3>
        <p class="session-description">Please refresh the page or try again later.</p>
      </div>
    `;
  }

  /**
   * Setup gallery interactions
   */
  setupGalleryInteractions() {
    const galleryItems = document.querySelectorAll('.gallery-item');
    
    galleryItems.forEach(item => {
      item.addEventListener('mouseenter', () => {
        item.style.transform = 'scale(1.05) rotate(0deg)';
        item.style.zIndex = '10';
      });

      item.addEventListener('mouseleave', () => {
        // Reset to original transform based on nth-child
        const index = Array.from(item.parentNode.children).indexOf(item);
        const transforms = [
          'translateY(-20px)',
          'translateX(20px)',
          'translateX(-20px) translateY(20px)'
        ];
        item.style.transform = transforms[index] || 'none';
        item.style.zIndex = '1';
      });
    });
  }
}

// Initialize homepage when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  if (document.body.classList.contains('home-page')) {
    new HomePage();
  }
});
