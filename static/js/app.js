/* Nginx Site Manager - Main JavaScript */

// Global application state
const App = {
    token: localStorage.getItem('access_token'),
    tokenType: localStorage.getItem('token_type') || 'bearer',
    baseUrl: window.location.origin,
    
    // Initialize the application
    init() {
        this.setupAuth();
        this.setupToasts();
        this.setupGlobalEventListeners();
    },
    
    // Check authentication and redirect if needed
    setupAuth() {
        const currentPath = window.location.pathname;
        const isLoginPage = currentPath === '/login';
        
        // If not on login page and no token, redirect to login
        if (!isLoginPage && !this.token) {
            this.redirectToLogin();
            return;
        }
        
        // If not on login page, validate token
        if (!isLoginPage && this.token) {
            const isValid = this.validateToken();
            if (!isValid) {
                return; // validateToken will handle redirect
            }
        }
        
        // If on login page and has valid token, redirect to dashboard
        if (isLoginPage && this.token && !this.isTokenExpired()) {
            window.location.href = '/';
            return;
        }
        
        // If on login page with expired token, clear it
        if (isLoginPage && this.token && this.isTokenExpired()) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('token_type');
        }
    },
    
    // Setup toast notifications
    setupToasts() {
        // Create toast container if it doesn't exist
        if (!document.querySelector('.toast-container')) {
            const container = document.createElement('div');
            container.className = 'toast-container position-fixed top-0 end-0 p-3';
            container.innerHTML = `
                <div id="alertToast" class="toast" role="alert">
                    <div class="toast-header">
                        <strong class="me-auto" id="toastTitle">Notification</strong>
                        <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                    </div>
                    <div class="toast-body" id="toastBody">Message</div>
                </div>
            `;
            document.body.appendChild(container);
        }
    },
    
    // Setup global event listeners
    setupGlobalEventListeners() {
        // Handle authentication errors globally
        window.addEventListener('unhandledrejection', (event) => {
            if (event.reason && event.reason.status === 401) {
                this.handleAuthError();
            }
        });
        
        // Handle network errors
        window.addEventListener('offline', () => {
            showToast('Warning', 'You are now offline', 'warning');
        });
        
        window.addEventListener('online', () => {
            showToast('Info', 'Connection restored', 'info');
        });
        
        // Intercept all fetch requests to handle auth errors globally
        const originalFetch = window.fetch;
        window.fetch = async (...args) => {
            try {
                const response = await originalFetch.apply(window, args);
                
                // Check for 401 responses on any fetch request
                if (response.status === 401 && !args[0].includes('/auth/login')) {
                    // Don't interfere with login requests, but handle all others
                    this.handleAuthError();
                    throw new Error('Session expired');
                }
                
                return response;
            } catch (error) {
                throw error;
            }
        };
    },
    
    // Redirect to login page
    redirectToLogin() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('token_type');
        window.location.href = '/login';
    },
    
    // Handle authentication errors
    handleAuthError() {
        showToast('Error', 'Session expired. Please login again.', 'error');
        setTimeout(() => {
            this.redirectToLogin();
        }, 2000);
    },
    
    // Check if token is expired (basic check)
    isTokenExpired() {
        const token = localStorage.getItem('access_token');
        if (!token) return true;
        
        try {
            // Decode JWT payload (basic decode, not verification)
            const payload = JSON.parse(atob(token.split('.')[1]));
            const currentTime = Math.floor(Date.now() / 1000);
            
            // Check if token is expired
            if (payload.exp && payload.exp < currentTime) {
                return true;
            }
            
            return false;
        } catch (error) {
            console.warn('Failed to decode token:', error);
            return true; // Assume expired if we can't decode
        }
    },
    
    // Validate token on app startup
    validateToken() {
        if (!this.token || this.isTokenExpired()) {
            this.redirectToLogin();
            return false;
        }
        
        return true;
    }
};

// Authentication helper functions
function getAuthHeaders() {
    const token = localStorage.getItem('access_token');
    const tokenType = localStorage.getItem('token_type') || 'bearer';
    
    if (!token) {
        throw new Error('No authentication token found');
    }
    
    return {
        'Authorization': `${tokenType} ${token}`,
        'Content-Type': 'application/json'
    };
}

// Enhanced fetch with authentication
async function fetchWithAuth(url, options = {}) {
    try {
        const headers = {
            ...getAuthHeaders(),
            ...options.headers
        };
        
        const response = await fetch(url, {
            ...options,
            headers
        });
        
        // Handle authentication errors
        if (response.status === 401) {
            // Check if response body has specific error message
            try {
                const errorData = await response.json();
                if (errorData.detail && (
                    errorData.detail.includes('expired') || 
                    errorData.detail.includes('invalid') ||
                    errorData.detail.includes('token')
                )) {
                    App.handleAuthError();
                    throw new Error('Session expired');
                }
            } catch (parseError) {
                // If we can't parse the response, still treat as auth error
                App.handleAuthError();
                throw new Error('Authentication failed');
            }
            App.handleAuthError();
            throw new Error('Authentication failed');
        }
        
        return response;
    } catch (error) {
        if (error.message === 'No authentication token found') {
            App.redirectToLogin();
        }
        throw error;
    }
}

// Toast notification system
function showToast(title, message, type = 'info') {
    const toast = document.getElementById('alertToast');
    const toastTitle = document.getElementById('toastTitle');
    const toastBody = document.getElementById('toastBody');
    
    if (!toast || !toastTitle || !toastBody) {
        console.error('Toast elements not found');
        return;
    }
    
    // Set content
    toastTitle.textContent = title;
    toastBody.textContent = message;
    
    // Remove existing classes
    toast.classList.remove('text-bg-success', 'text-bg-danger', 'text-bg-warning', 'text-bg-info');
    
    // Add appropriate class based on type
    switch (type) {
        case 'success':
            toast.classList.add('text-bg-success');
            break;
        case 'error':
        case 'danger':
            toast.classList.add('text-bg-danger');
            break;
        case 'warning':
            toast.classList.add('text-bg-warning');
            break;
        case 'info':
        default:
            toast.classList.add('text-bg-info');
            break;
    }
    
    // Show the toast
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

// Logout function
async function logout() {
    try {
        // Optional: call logout endpoint
        const sessionId = localStorage.getItem('session_id');
        if (sessionId) {
            const formData = new FormData();
            formData.append('session_id', sessionId);
            
            await fetch('/auth/logout', {
                method: 'POST',
                body: formData
            });
        }
    } catch (error) {
        console.warn('Logout request failed:', error);
    } finally {
        // Clear local storage and redirect
        localStorage.removeItem('access_token');
        localStorage.removeItem('token_type');
        localStorage.removeItem('session_id');
        window.location.href = '/login';
    }
}

// Utility functions
function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Form validation helpers
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validateDomain(domain) {
    const re = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    return re.test(domain);
}

function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// Loading state helpers
function showLoading(element, text = 'Loading...') {
    if (typeof element === 'string') {
        element = document.getElementById(element);
    }
    
    if (element) {
        element.innerHTML = `
            <div class="d-flex justify-content-center align-items-center p-4">
                <div class="spinner-border me-2" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <span>${text}</span>
            </div>
        `;
    }
}

function hideLoading(element, content = '') {
    if (typeof element === 'string') {
        element = document.getElementById(element);
    }
    
    if (element) {
        element.innerHTML = content;
    }
}

// Button loading state
function setButtonLoading(button, loading = true, text = 'Loading...') {
    if (typeof button === 'string') {
        button = document.getElementById(button);
    }
    
    if (!button) return;
    
    if (loading) {
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = `<i class="fas fa-spinner fa-spin me-2"></i>${text}`;
        button.disabled = true;
    } else {
        button.innerHTML = button.dataset.originalText || button.innerHTML;
        button.disabled = false;
        delete button.dataset.originalText;
    }
}

// Error handling
function handleApiError(error, defaultMessage = 'An error occurred') {
    console.error('API Error:', error);
    
    let message = defaultMessage;
    
    if (error.response) {
        // Server responded with error status
        message = error.response.detail || error.response.message || defaultMessage;
    } else if (error.message) {
        // Network or other error
        message = error.message;
    }
    
    showToast('Error', message, 'error');
}

// Local storage helpers
function saveToStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
        console.warn('Failed to save to localStorage:', error);
    }
}

function loadFromStorage(key, defaultValue = null) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
        console.warn('Failed to load from localStorage:', error);
        return defaultValue;
    }
}

function removeFromStorage(key) {
    try {
        localStorage.removeItem(key);
    } catch (error) {
        console.warn('Failed to remove from localStorage:', error);
    }
}

// Copy to clipboard
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Success', 'Copied to clipboard', 'success');
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        showToast('Error', 'Failed to copy to clipboard', 'error');
    }
}

// Confirm dialog helper
function confirmAction(message, title = 'Confirm Action') {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        ${message}
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-danger" id="confirmBtn">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        const bsModal = new bootstrap.Modal(modal);
        
        modal.querySelector('#confirmBtn').addEventListener('click', () => {
            bsModal.hide();
            resolve(true);
        });
        
        modal.addEventListener('hidden.bs.modal', () => {
            document.body.removeChild(modal);
            resolve(false);
        });
        
        bsModal.show();
    });
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    App.init();
});

// Global error handler
window.addEventListener('error', function(event) {
    console.error('Global error:', event.error);
});

// Expose utilities globally
window.App = App;
window.showToast = showToast;
window.fetchWithAuth = fetchWithAuth;
window.logout = logout;