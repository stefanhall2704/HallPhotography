/**
 * Hall's Photography - Homepage JavaScript
 * Specific functionality for the homepage
 */

class HomePage {
  constructor() {
    this.portfolioItems = [];
    this.currentScrollIndex = 0;
    this.itemsPerView = 3;
    this.init();
  }

  init() {
    this.loadMinisSessions();
    this.setupGalleryInteractions();
    this.loadPortfolio();
    this.setupPortfolioNavigation();
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

  /**
   * Load portfolio items from API
   */
  async loadPortfolio() {
    try {
      const response = await fetch('/api/portfolio');
      if (!response.ok) {
        throw new Error('Failed to load portfolio');
      }
      this.portfolioItems = await response.json();
      this.renderPortfolio();
    } catch (error) {
      console.error('Error loading portfolio:', error);
      this.showPortfolioError();
    }
  }

  /**
   * Render portfolio items
   */
  renderPortfolio() {
    const loadingEl = document.getElementById('portfolio-loading');
    const itemsEl = document.getElementById('portfolio-items');
    
    if (!loadingEl || !itemsEl) return;

    // Hide loading
    loadingEl.style.display = 'none';

    if (this.portfolioItems.length === 0) {
      this.showPortfolioEmpty();
      return;
    }

    // Render items
    itemsEl.innerHTML = this.portfolioItems.map(item => `
      <div class="portfolio-item" data-id="${item.ID}">
        <img src="${item.ImageURL}" alt="${item.Title}" loading="lazy">
        <div class="portfolio-item-category">${item.Category}</div>
        <div class="portfolio-item-overlay">
          <h3 class="portfolio-item-title">${item.Title}</h3>
          ${item.Description ? `<p class="portfolio-item-description">${item.Description}</p>` : ''}
        </div>
      </div>
    `).join('');

    // Update navigation state
    this.updatePortfolioNavigation();
  }

  /**
   * Show portfolio empty state
   */
  showPortfolioEmpty() {
    const itemsEl = document.getElementById('portfolio-items');
    if (!itemsEl) return;

    itemsEl.innerHTML = `
      <div class="portfolio-empty">
        <i class="fas fa-images"></i>
        <h3>No Portfolio Items Yet</h3>
        <p>Check back soon for amazing photography work!</p>
      </div>
    `;
  }

  /**
   * Show portfolio error state
   */
  showPortfolioError() {
    const loadingEl = document.getElementById('portfolio-loading');
    const itemsEl = document.getElementById('portfolio-items');
    
    if (loadingEl) loadingEl.style.display = 'none';
    if (itemsEl) {
      itemsEl.innerHTML = `
        <div class="portfolio-empty">
          <i class="fas fa-exclamation-triangle"></i>
          <h3>Unable to Load Portfolio</h3>
          <p>Please refresh the page or try again later.</p>
        </div>
      `;
    }
  }

  /**
   * Setup portfolio navigation
   */
  setupPortfolioNavigation() {
    const leftBtn = document.getElementById('portfolio-left');
    const rightBtn = document.getElementById('portfolio-right');
    const scrollEl = document.getElementById('portfolio-scroll');
    const wrapperEl = document.querySelector('.portfolio-scroll-wrapper');

    if (!leftBtn || !rightBtn || !scrollEl || !wrapperEl) return;

    // Calculate items per view based on screen size
    this.updateItemsPerView();

    // Navigation button handlers
    leftBtn.addEventListener('click', () => this.scrollPortfolio('left'));
    rightBtn.addEventListener('click', () => this.scrollPortfolio('right'));

    // Touch/swipe support
    let startX = 0;
    let isDragging = false;

    scrollEl.addEventListener('touchstart', (e) => {
      startX = e.touches[0].clientX;
      isDragging = true;
    });

    scrollEl.addEventListener('touchmove', (e) => {
      if (!isDragging) return;
      e.preventDefault();
    });

    scrollEl.addEventListener('touchend', (e) => {
      if (!isDragging) return;
      isDragging = false;
      
      const endX = e.changedTouches[0].clientX;
      const diff = startX - endX;
      
      if (Math.abs(diff) > 50) {
        if (diff > 0) {
          this.scrollPortfolio('right');
        } else {
          this.scrollPortfolio('left');
        }
      }
    });

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      if (e.target.closest('.portfolio-container')) {
        if (e.key === 'ArrowLeft') {
          e.preventDefault();
          this.scrollPortfolio('left');
        } else if (e.key === 'ArrowRight') {
          e.preventDefault();
          this.scrollPortfolio('right');
        }
      }
    });

    // Update on resize
    window.addEventListener('resize', () => {
      this.updateItemsPerView();
      this.updatePortfolioNavigation();
    });
  }

  /**
   * Update items per view based on screen size
   */
  updateItemsPerView() {
    const width = window.innerWidth;
    if (width < 768) {
      this.itemsPerView = 1;
    } else if (width < 1200) {
      this.itemsPerView = 2;
    } else {
      this.itemsPerView = 3;
    }
  }

  /**
   * Scroll portfolio in specified direction
   */
  scrollPortfolio(direction) {
    if (this.portfolioItems.length === 0) return;

    const maxIndex = Math.max(0, this.portfolioItems.length - this.itemsPerView);
    
    if (direction === 'left') {
      this.currentScrollIndex = Math.max(0, this.currentScrollIndex - 1);
    } else {
      this.currentScrollIndex = Math.min(maxIndex, this.currentScrollIndex + 1);
    }

    this.updatePortfolioScroll();
    this.updatePortfolioNavigation();
  }

  /**
   * Update portfolio scroll position
   */
  updatePortfolioScroll() {
    const scrollEl = document.getElementById('portfolio-scroll');
    const wrapperEl = document.querySelector('.portfolio-scroll-wrapper');
    
    if (!scrollEl || !wrapperEl) return;

    const itemWidth = 320 + 20; // item width + gap
    const translateX = -this.currentScrollIndex * itemWidth;
    
    scrollEl.style.transform = `translateX(${translateX}px)`;

    // Update fade effects
    wrapperEl.classList.toggle('fade-left', this.currentScrollIndex > 0);
    wrapperEl.classList.toggle('fade-right', this.currentScrollIndex < Math.max(0, this.portfolioItems.length - this.itemsPerView));
  }

  /**
   * Update portfolio navigation buttons
   */
  updatePortfolioNavigation() {
    const leftBtn = document.getElementById('portfolio-left');
    const rightBtn = document.getElementById('portfolio-right');
    
    if (!leftBtn || !rightBtn) return;

    const maxIndex = Math.max(0, this.portfolioItems.length - this.itemsPerView);
    
    leftBtn.disabled = this.currentScrollIndex <= 0;
    rightBtn.disabled = this.currentScrollIndex >= maxIndex;
  }
}

// Global admin functions for portfolio management
window.showAddPortfolioModal = function() {
  const modal = createPortfolioModal({
    title: 'Add Portfolio Item',
    onSubmit: async (data) => {
      try {
        const formData = new FormData();
        formData.append('title', data.title);
        formData.append('description', data.description);
        formData.append('category', data.category);
        formData.append('image_url', data.imageURL);
        formData.append('sort_order', data.sortOrder);

        const response = await fetch('/admin/portfolio', {
          method: 'POST',
          body: formData
        });

        if (!response.ok) {
          throw new Error('Failed to add portfolio item');
        }

        showToast('Portfolio item added successfully!', 'success');
        modal.remove();
        
        // Reload portfolio
        if (window.homePage) {
          window.homePage.loadPortfolio();
        }
      } catch (error) {
        console.error('Error adding portfolio item:', error);
        showToast('Failed to add portfolio item: ' + error.message, 'error');
      }
    }
  });
};

window.showPortfolioManagement = function() {
  const modal = createPortfolioManagementModal();
};

function createPortfolioManagementModal() {
  const modal = document.createElement('div');
  modal.className = 'portfolio-modal';
  modal.innerHTML = `
    <div class="portfolio-modal-overlay"></div>
    <div class="portfolio-modal-content" style="max-width: 800px; width: 95%;">
      <h3>Portfolio Management</h3>
      <div id="portfolio-management-content">
        <div class="portfolio-loading">
          <div class="loading-spinner"></div>
          <p>Loading portfolio items...</p>
        </div>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  setTimeout(() => modal.classList.add('show'), 10);
  
  // Load portfolio items
  loadPortfolioItems(modal);
  
  // Close on overlay click
  modal.querySelector('.portfolio-modal-overlay').addEventListener('click', () => {
    modal.classList.remove('show');
    setTimeout(() => modal.remove(), 300);
  });
  
  return modal;
}

async function loadPortfolioItems(modal) {
  try {
    const response = await fetch('/admin/portfolio');
    if (!response.ok) throw new Error('Failed to fetch portfolio items');
    
    const items = await response.json();
    renderPortfolioItems(modal, items);
  } catch (error) {
    console.error('Error loading portfolio items:', error);
    modal.querySelector('#portfolio-management-content').innerHTML = `
      <div class="portfolio-empty">
        <i class="fas fa-exclamation-triangle"></i>
        <h3>Error Loading Portfolio</h3>
        <p>Error: ${error.message}</p>
      </div>
    `;
  }
}

function renderPortfolioItems(modal, items) {
  const content = modal.querySelector('#portfolio-management-content');
  
  if (items.length === 0) {
    content.innerHTML = `
      <div class="portfolio-empty">
        <i class="fas fa-images"></i>
        <h3>No Portfolio Items</h3>
        <p>Add your first portfolio item to showcase your work!</p>
        <button class="btn btn-primary" onclick="showAddPortfolioModal()" style="margin-top: 15px;">
          <i class="fas fa-plus"></i> Add Portfolio Item
        </button>
      </div>
    `;
    return;
  }

  content.innerHTML = `
    <div style="margin-bottom: 20px;">
      <button class="btn btn-primary" onclick="showAddPortfolioModal()">
        <i class="fas fa-plus"></i> Add New Item
      </button>
    </div>
    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; max-height: 60vh; overflow-y: auto;">
      ${items.map(item => `
        <div class="portfolio-item-card" style="border: 1px solid #e9ecef; border-radius: 12px; overflow: hidden; background: white;">
          <div style="position: relative;">
            <img src="${item.ImageURL}" alt="${item.Title}" style="width: 100%; height: 200px; object-fit: cover;">
            <div style="position: absolute; top: 10px; right: 10px; background: rgba(0,0,0,0.7); color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px;">
              ${item.Category}
            </div>
            <div style="position: absolute; top: 10px; left: 10px;">
              <label style="display: flex; align-items: center; background: rgba(255,255,255,0.9); padding: 4px 8px; border-radius: 12px; font-size: 12px;">
                <input type="checkbox" ${item.IsActive ? 'checked' : ''} onchange="togglePortfolioItem(${item.ID}, this.checked)" style="margin-right: 5px;">
                Active
              </label>
            </div>
          </div>
          <div style="padding: 15px;">
            <h4 style="margin: 0 0 8px 0; color: #333;">${item.Title}</h4>
            ${item.Description ? `<p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">${item.Description}</p>` : ''}
            <div style="display: flex; gap: 8px; margin-top: 15px;">
              <button class="btn btn-outline" onclick="editPortfolioItem(${item.ID})" style="font-size: 12px; padding: 6px 12px;">
                <i class="fas fa-edit"></i> Edit
              </button>
              <button class="btn btn-outline" onclick="deletePortfolioItem(${item.ID})" style="font-size: 12px; padding: 6px 12px; color: #dc3545; border-color: #dc3545;">
                <i class="fas fa-trash"></i> Delete
              </button>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

window.togglePortfolioItem = async function(itemId, isActive) {
  try {
    const formData = new FormData();
    formData.append('is_active', isActive.toString());

    const response = await fetch(`/admin/portfolio/${itemId}`, {
      method: 'PUT',
      body: formData
    });

    if (!response.ok) throw new Error('Failed to update portfolio item');

    showToast(`Portfolio item ${isActive ? 'activated' : 'deactivated'} successfully!`, 'success');
  } catch (error) {
    console.error('Error updating portfolio item:', error);
    showToast('Failed to update portfolio item: ' + error.message, 'error');
  }
};

window.editPortfolioItem = function(itemId) {
  showToast('Edit functionality coming soon!', 'info');
};

window.deletePortfolioItem = async function(itemId) {
  if (!confirm('Are you sure you want to delete this portfolio item? This action cannot be undone.')) {
    return;
  }

  try {
    const response = await fetch(`/admin/portfolio/${itemId}`, {
      method: 'DELETE'
    });

    if (!response.ok) throw new Error('Failed to delete portfolio item');

    showToast('Portfolio item deleted successfully!', 'success');
    
    // Reload the modal content
    const modal = document.querySelector('.portfolio-modal');
    if (modal) {
      loadPortfolioItems(modal);
    }
    
    // Also reload the homepage portfolio
    if (window.homePage) {
      window.homePage.loadPortfolio();
    }
  } catch (error) {
    console.error('Error deleting portfolio item:', error);
    showToast('Failed to delete portfolio item: ' + error.message, 'error');
  }
};

function createPortfolioModal(options) {
  const modal = document.createElement('div');
  modal.className = 'portfolio-modal';
  modal.innerHTML = `
    <div class="portfolio-modal-overlay"></div>
    <div class="portfolio-modal-content">
      <h3>${options.title}</h3>
      <form id="portfolio-form">
        <div class="form-group">
          <label for="portfolio-title">Title *</label>
          <input type="text" id="portfolio-title" name="title" required>
        </div>
        <div class="form-group">
          <label for="portfolio-description">Description</label>
          <textarea id="portfolio-description" name="description" rows="3"></textarea>
        </div>
        <div class="form-group">
          <label for="portfolio-category">Category *</label>
          <select id="portfolio-category" name="category" required>
            <option value="">Select Category</option>
            <option value="portraits">Portraits</option>
            <option value="families">Families</option>
            <option value="events">Events</option>
            <option value="weddings">Weddings</option>
            <option value="maternity">Maternity</option>
            <option value="newborn">Newborn</option>
            <option value="seniors">Seniors</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="form-group">
          <label for="portfolio-image-url">Image URL *</label>
          <input type="url" id="portfolio-image-url" name="image_url" required placeholder="https://example.com/image.jpg">
        </div>
        <div class="form-group">
          <label for="portfolio-sort-order">Sort Order</label>
          <input type="number" id="portfolio-sort-order" name="sort_order" value="0" min="0">
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-outline" onclick="this.closest('.portfolio-modal').remove()">Cancel</button>
          <button type="submit" class="btn btn-primary">Add Item</button>
        </div>
      </form>
    </div>
  `;

  // Add modal styles
  const style = document.createElement('style');
  style.textContent = `
    .portfolio-modal {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 10000;
      display: flex;
      align-items: center;
      justify-content: center;
      opacity: 0;
      transition: opacity 0.3s ease;
    }
    .portfolio-modal.show {
      opacity: 1;
    }
    .portfolio-modal-overlay {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
    }
    .portfolio-modal-content {
      position: relative;
      background: white;
      border-radius: 16px;
      padding: 32px;
      max-width: 500px;
      width: 90%;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      transform: scale(0.9);
      transition: transform 0.3s ease;
    }
    .portfolio-modal.show .portfolio-modal-content {
      transform: scale(1);
    }
    .portfolio-modal-content h3 {
      margin: 0 0 24px 0;
      color: var(--charcoal);
      font-size: 24px;
    }
    .portfolio-modal .form-group {
      margin-bottom: 20px;
    }
    .portfolio-modal .form-group label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
      color: var(--charcoal);
    }
    .portfolio-modal .form-group input,
    .portfolio-modal .form-group textarea,
    .portfolio-modal .form-group select {
      width: 100%;
      padding: 12px;
      border: 2px solid #e9ecef;
      border-radius: 8px;
      font-size: 14px;
      transition: border-color 0.3s;
    }
    .portfolio-modal .form-group input:focus,
    .portfolio-modal .form-group textarea:focus,
    .portfolio-modal .form-group select:focus {
      outline: none;
      border-color: var(--burnt-orange);
    }
    .portfolio-modal .form-actions {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
      margin-top: 24px;
    }
  `;
  document.head.appendChild(style);

  document.body.appendChild(modal);
  setTimeout(() => modal.classList.add('show'), 10);

  // Handle form submission
  modal.querySelector('#portfolio-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    options.onSubmit(data);
  });

  // Close on overlay click
  modal.querySelector('.portfolio-modal-overlay').addEventListener('click', () => {
    modal.remove();
  });

  return modal;
}


function showToast(message, type = 'info') {
  // Simple toast notification
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#17a2b8'};
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 10001;
    font-size: 14px;
    font-weight: 500;
    transform: translateX(100%);
    transition: transform 0.3s ease;
  `;
  toast.textContent = message;
  
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.transform = 'translateX(0)';
  }, 10);
  
  setTimeout(() => {
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Initialize homepage when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  if (document.body.classList.contains('home-page')) {
    window.homePage = new HomePage();
  }
});
