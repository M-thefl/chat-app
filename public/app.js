const CONFIG = {
    WS_RECONNECT_ATTEMPTS: 5,
    WS_RECONNECT_DELAY: 3000,
    TYPING_TIMEOUT: 1000,
    MESSAGE_HISTORY_LIMIT: 1000,
    NOTIFICATION_TIMEOUT: 4000,
    MAX_MESSAGE_LENGTH: 2000,
    AUTO_RECONNECT: true,
    HEARTBEAT_INTERVAL: 30000,
    DEBUG_MODE: false
};

class ChatState {
    constructor() {
        this.ws = null;
        this.currentUser = null;
        this.currentSession = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.typingTimeout = null;
        this.heartbeatInterval = null;
        this.onlineUsers = new Map();
        this.messageHistory = [];
        this.typingUsers = new Set();
        this.unreadMessages = 0;
        this.lastMessageTime = null;
        this.connectionState = 'disconnected';
        this.autoScroll = true;
    }

    reset() {
        this.ws = null;
        this.currentUser = null;
        this.currentSession = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.onlineUsers.clear();
        this.messageHistory = [];
        this.typingUsers.clear();
        this.unreadMessages = 0;
        this.lastMessageTime = null;
        this.connectionState = 'disconnected';
        this.autoScroll = true;
        
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
        
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
            this.typingTimeout = null;
        }
    }
}

class SecureChatApp {
    constructor() {
        this.state = new ChatState();
        this.ui = new UIHandler();
        this.network = new NetworkHandler(this);
        this.auth = new AuthHandler(this);
        this.events = new EventHandler(this);
        this.utils = new Utils();
        
        this.initialize();
    }

    initialize() {
        this.ui.initialize();
        this.events.bindEvents();        
        this.auth.checkSavedSession();        
        this.setupAutoSave();
        this.utils.debug('Application initialized');
    }

    setupAutoSave() {
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.addEventListener('input', () => {
                const draft = messageInput.value.trim();
                if (draft) {
                    localStorage.setItem('messageDraft', draft);
                } else {
                    localStorage.removeItem('messageDraft');
                }
            });

            const savedDraft = localStorage.getItem('messageDraft');
            if (savedDraft) {
                messageInput.value = savedDraft;
                this.ui.updateCharCount(savedDraft.length);
            }
        }
    }

    sendMessage(text) {
        if (!this.validateMessage(text)) return false;
        
        this.network.send({
            type: 'message',
            text: text,
            timestamp: Date.now()
        });
        
        return true;
    }

    validateMessage(text) {
        if (!text || !text.trim()) {
            this.ui.showNotification('Message cannot be empty', 'warning');
            return false;
        }

        if (text.length > CONFIG.MAX_MESSAGE_LENGTH) {
            this.ui.showNotification(`Message too long (max ${CONFIG.MAX_MESSAGE_LENGTH} characters)`, 'error');
            return false;
        }

        if (this.utils.detectSuspiciousContent(text)) {
            this.ui.showNotification('Message contains suspicious content', 'warning');
            return false;
        }

        return true;
    }

    editMessage(messageId, newText) {
        if (!this.validateMessage(newText)) return false;
        
        this.network.send({
            type: 'edit',
            messageId: messageId,
            text: newText
        });
        
        return true;
    }

    updateTypingStatus(isTyping) {
        if (!this.state.isConnected) return;
        
        this.network.send({
            type: 'typing',
            isTyping: isTyping
        });
    }

    updateUserStatus(status) {
        if (!this.state.isConnected) return;
        
        this.network.send({
            type: 'status',
            status: status
        });
    }

    onMessageReceived(message) {
        this.messageHistory.push(message);        
        if (this.messageHistory.length > CONFIG.MESSAGE_HISTORY_LIMIT) {
            this.messageHistory.shift();
        }        
        this.ui.addMessage(message);        
        if (!document.hasFocus()) {
            this.state.unreadMessages++;
            this.ui.updateUnreadCount(this.state.unreadMessages);
        }
        
        if (localStorage.getItem('soundEnabled') !== 'false') {
            this.utils.playNotificationSound();
        }
    }

    onUsersUpdated(users) {
        this.state.onlineUsers.clear();
        users.forEach(user => {
            this.state.onlineUsers.set(user.id, user);
        });
        
        this.ui.updateOnlineUsers(users);
    }

    onTyping(user) {
        this.state.typingUsers.add(user);
        this.ui.showTypingIndicator(user);
        
        setTimeout(() => {
            this.state.typingUsers.delete(user);
            if (this.state.typingUsers.size === 0) {
                this.ui.hideTypingIndicator();
            }
        }, 3000);
    }

    onConnectionStateChange(state) {
        this.state.connectionState = state;
        this.ui.updateConnectionStatus(state);
        
        if (state === 'connected') {
            this.startHeartbeat();
        } else {
            this.stopHeartbeat();
        }
    }

    startHeartbeat() {
        this.stopHeartbeat();
        
        this.state.heartbeatInterval = setInterval(() => {
            if (this.state.isConnected && this.state.ws) {
                this.network.send({ type: 'ping' });
            }
        }, CONFIG.HEARTBEAT_INTERVAL);
    }

    stopHeartbeat() {
        if (this.state.heartbeatInterval) {
            clearInterval(this.state.heartbeatInterval);
            this.state.heartbeatInterval = null;
        }
    }

    // Cleanup
    cleanup() {
        this.state.reset();
        this.ui.cleanup();
        this.network.disconnect();
        this.events.unbindEvents();
    }
}

class UIHandler {
    constructor() {
        this.elements = {};
        this.notificationQueue = [];
        this.isNotificationShowing = false;
    }

    initialize() {
        this.cacheElements();
        this.loadTheme();
        this.initializeAnimations();
    }

    cacheElements() {
        this.elements = {
            // Login screen
            loginScreen: document.getElementById('loginScreen'),
            chatInterface: document.getElementById('chatInterface'),
            usernameInput: document.getElementById('usernameInput'),
            passwordInput: document.getElementById('passwordInput'),
            displayNameInput: document.getElementById('displayNameInput'),
            loginBtn: document.getElementById('loginBtn'),
            registerBtn: document.getElementById('registerBtn'),            
            statusDot: document.getElementById('statusDot'),
            statusText: document.getElementById('statusText'),
            userDisplayName: document.getElementById('userDisplayName'),
            userStatusIndicator: document.getElementById('userStatusIndicator'),
            userStatusText: document.getElementById('userStatusText'),
            userAvatar: document.getElementById('userAvatar'),
            onlineCount: document.getElementById('onlineCount'),
            usersList: document.getElementById('usersList'),
            userCount: document.getElementById('userCount'),            
            messagesContainer: document.getElementById('messagesContainer'),
            messages: document.getElementById('messages'),
            messageInput: document.getElementById('messageInput'),
            charCount: document.getElementById('charCount'),
            sendButton: document.getElementById('sendButton'),
            
            // Typing
            typingIndicator: document.getElementById('typingIndicator'),
            typingText: document.getElementById('typingText'),            
            themeToggle: document.getElementById('themeToggle'),
            logoutBtn: document.getElementById('logoutBtn'),
            settingsBtn: document.getElementById('settingsBtn'),
            emojiBtn: document.getElementById('emojiBtn'),
            attachBtn: document.getElementById('attachBtn'),            
            settingsModal: document.getElementById('settingsModal'),
            closeSettings: document.getElementById('closeSettings'),
            
            notificationContainer: document.getElementById('notificationContainer')
        };
    }

    showLoginScreen() {
        this.elements.chatInterface.classList.add('hidden');
        this.elements.loginScreen.classList.remove('hidden');
        this.elements.usernameInput?.focus();
    }

    showChatInterface() {
        this.elements.loginScreen.classList.add('hidden');
        this.elements.chatInterface.classList.remove('hidden');
        this.elements.messageInput?.focus();
    }

    updateUserProfile(user) {
        if (!user) return;
        
        const { userDisplayName, userAvatar, userStatusText, userStatusIndicator } = this.elements;
        
        if (userDisplayName) {
            userDisplayName.textContent = user.displayName || user.username;
        }
        
        if (userAvatar) {
            const initials = this.getInitials(user.displayName || user.username);
            userAvatar.innerHTML = initials;
            userAvatar.style.background = user.avatarColor || '#00d4aa';
        }
        
        if (userStatusText) {
            userStatusText.textContent = user.isOnline ? 'Online' : 'Offline';
        }
        
        if (userStatusIndicator) {
            userStatusIndicator.className = user.isOnline ? 'status-indicator' : 'status-indicator offline';
        }
    }

    addMessage(message) {
        const messagesDiv = this.elements.messages;
        if (!messagesDiv) return;
        
        const isOwnMessage = message.userId === window.chatApp?.state.currentUser?.id;
        const isSystem = message.type === 'system';
        
        const welcomeMsg = messagesDiv.querySelector('.welcome-message');
        if (welcomeMsg) {
            welcomeMsg.remove();
        }
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isSystem ? 'system' : isOwnMessage ? 'own' : 'other'}`;
        messageDiv.dataset.messageId = message.id;
        messageDiv.dataset.timestamp = message.timestamp;
        
        const time = new Date(message.time || Date.now()).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
        });
        
        let messageHTML = `
            <div class="message-bubble">
                <div class="message-header">
                    <span class="message-sender">
                        ${this.escapeHtml(message.username || 'Unknown')}
                        ${isOwnMessage ? '<span style="font-size: 11px; opacity: 0.8;">(You)</span>' : ''}
                    </span>
                    <span class="message-time">${time}</span>
                </div>
                <div class="message-text">${this.escapeHtml(message.text)}</div>
        `;
        
        if (message.edited) {
            messageHTML += `
                <div class="message-edited">
                    <i class="fas fa-pen" style="font-size: 9px;"></i>
                    edited
                </div>
            `;
        }
        
        if (isOwnMessage && !isSystem) {
            messageHTML += `
                <div class="message-actions">
                    <button class="btn-icon edit-btn" data-message-id="${message.id}" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn-icon delete-btn" data-message-id="${message.id}" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `;
        }
        
        messageHTML += `</div>`;
        messageDiv.innerHTML = messageHTML;
        
        messageDiv.style.animation = 'slideIn 0.3s ease-out';
        
        messagesDiv.appendChild(messageDiv);
        
        if (window.chatApp?.state.autoScroll) {
            this.scrollToBottom();
        }
        
        this.bindMessageActions(messageDiv);
    }

    bindMessageActions(messageElement) {
        const editBtn = messageElement.querySelector('.edit-btn');
        const deleteBtn = messageElement.querySelector('.delete-btn');
        
        if (editBtn) {
            editBtn.addEventListener('click', (e) => {
                const messageId = e.currentTarget.dataset.messageId;
                this.showEditModal(messageId);
            });
        }
        
        if (deleteBtn) {
            deleteBtn.addEventListener('click', (e) => {
                const messageId = e.currentTarget.dataset.messageId;
                if (confirm('Are you sure you want to delete this message?')) {
                    window.chatApp?.network.send({
                        type: 'delete',
                        messageId: messageId
                    });
                }
            });
        }
    }

    showEditModal(messageId) {
        const message = window.chatApp?.messageHistory.find(m => m.id === messageId);
        if (!message) return;
        
        const newText = prompt('Edit your message:', message.text);
        if (newText !== null && newText !== message.text) {
            window.chatApp?.editMessage(messageId, newText);
        }
    }

    updateMessage(messageId, newText) {
        const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (!messageElement) return;
        
        const textElement = messageElement.querySelector('.message-text');
        if (textElement) {
            textElement.innerHTML = this.escapeHtml(newText);
            
            if (!messageElement.querySelector('.message-edited')) {
                const editedDiv = document.createElement('div');
                editedDiv.className = 'message-edited';
                editedDiv.innerHTML = '<i class="fas fa-pen" style="font-size: 9px;"></i> edited';
                messageElement.querySelector('.message-bubble').appendChild(editedDiv);
            }
        }
    }

    updateOnlineUsers(users) {
        const { usersList, onlineCount, userCount } = this.elements;
        if (!usersList || !onlineCount || !userCount) return;
        
        onlineCount.textContent = users.length;
        userCount.textContent = `${users.length} user${users.length !== 1 ? 's' : ''} online`;
        
        usersList.innerHTML = '';
        
        users.forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            userItem.dataset.userId = user.id;
            
            const initials = this.getInitials(user.displayName || user.username);
            const isCurrentUser = user.id === window.chatApp?.state.currentUser?.id;
            
            userItem.innerHTML = `
                <div class="user-avatar small" style="background: ${user.avatarColor || '#00d4aa'}">
                    ${initials}
                </div>
                <div class="user-details">
                    <div class="user-display-name">
                        ${this.escapeHtml(user.displayName || user.username)}
                        ${isCurrentUser ? '<span style="font-size: 11px; color: var(--accent);">(You)</span>' : ''}
                    </div>
                    <div class="user-username">@${this.escapeHtml(user.username)}</div>
                    <div class="user-status">${user.status || 'Online'}</div>
                </div>
            `;
            
            usersList.appendChild(userItem);
        });
    }

    showTypingIndicator(username) {
        const { typingIndicator, typingText } = this.elements;
        if (!typingIndicator || !typingText) return;
        
        typingText.textContent = `${username} is typing...`;
        typingIndicator.classList.remove('hidden');
    }

    hideTypingIndicator() {
        const { typingIndicator } = this.elements;
        if (typingIndicator) {
            typingIndicator.classList.add('hidden');
        }
    }

    updateConnectionStatus(state) {
        const { statusDot, statusText } = this.elements;
        if (!statusDot || !statusText) return;
        
        const states = {
            connecting: { text: 'Connecting...', class: 'connecting' },
            connected: { text: 'Connected', class: 'connected' },
            disconnected: { text: 'Disconnected', class: 'disconnected' },
            error: { text: 'Connection Error', class: 'error' }
        };
        
        const status = states[state] || states.disconnected;
        
        statusText.textContent = status.text;
        statusDot.className = 'status-dot';
        statusDot.classList.add(status.class);
    }

    updateCharCount(count) {
        const { charCount } = this.elements;
        if (charCount) {
            charCount.textContent = `${count}/${CONFIG.MAX_MESSAGE_LENGTH}`;
            
            if (count > CONFIG.MAX_MESSAGE_LENGTH * 0.9) {
                charCount.style.color = 'var(--warning)';
            } else if (count > CONFIG.MAX_MESSAGE_LENGTH * 0.75) {
                charCount.style.color = 'var(--accent)';
            } else {
                charCount.style.color = '';
            }
        }
    }

    autoResizeTextarea() {
        const { messageInput } = this.elements;
        if (!messageInput) return;
        
        messageInput.style.height = 'auto';
        messageInput.style.height = Math.min(messageInput.scrollHeight, 120) + 'px';
    }

    showNotification(message, type = 'info', duration = CONFIG.NOTIFICATION_TIMEOUT) {
        const container = this.elements.notificationContainer;
        if (!container) return;
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const icons = {
            success: 'check-circle',
            error: 'exclamation-triangle',
            warning: 'exclamation-circle',
            info: 'info-circle'
        };
        
        notification.innerHTML = `
            <div class="notification-icon">
                <i class="fas fa-${icons[type] || 'info-circle'}"></i>
            </div>
            <div class="notification-content">
                <div class="notification-message">${this.escapeHtml(message)}</div>
            </div>
        `;
        
        container.appendChild(notification);
        
        setTimeout(() => {
            notification.style.opacity = '1';
            notification.style.transform = 'translateX(0)';
        }, 10);
        
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100px)';
            setTimeout(() => notification.remove(), 300);
        }, duration);
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        const icon = this.elements.themeToggle?.querySelector('i');
        if (icon) {
            icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    toggleTheme() {
        const html = document.documentElement;
        const currentTheme = html.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        html.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const icon = this.elements.themeToggle?.querySelector('i');
        if (icon) {
            icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    showSettings() {
        this.elements.settingsModal?.classList.remove('hidden');
        this.populateSettings();
    }

    hideSettings() {
        this.elements.settingsModal?.classList.add('hidden');
    }

    populateSettings() {
        const settings = {
            soundEnabled: localStorage.getItem('soundEnabled') !== 'false',
            autoScroll: localStorage.getItem('autoScroll') !== 'false',
            showTimestamps: localStorage.getItem('showTimestamps') !== 'false',
            compactMode: localStorage.getItem('compactMode') === 'true'
        };
        
    }

    scrollToBottom() {
        const { messagesContainer } = this.elements;
        if (messagesContainer) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    getInitials(name) {
        return name.split(' ')
            .map(word => word[0])
            .join('')
            .toUpperCase()
            .substring(0, 2);
    }

    updateUnreadCount(count) {
        // Update tab title
        if (count > 0) {
            document.title = `(${count}) Secure Chat`;
        } else {
            document.title = 'Secure Chat';
        }
        
    }

    initializeAnimations() {
        const style = document.createElement('style');
        style.textContent = `
            .status-dot.connecting {
                background: var(--warning);
                animation: pulse 1.5s infinite;
            }
            
            .message-actions {
                display: flex;
                gap: 4px;
                margin-top: 8px;
                opacity: 0;
                transition: opacity 0.2s;
            }
            
            .message:hover .message-actions {
                opacity: 1;
            }
            
            .btn-icon {
                width: 24px;
                height: 24px;
                padding: 0;
                border-radius: 4px;
                font-size: 12px;
            }
        `;
        document.head.appendChild(style);
    }

    cleanup() {
        if (this.notificationTimeout) {
            clearTimeout(this.notificationTimeout);
        }
    }
}

class NetworkHandler {
    constructor(app) {
        this.app = app;
        this.state = app.state;
    }

    connect() {
        if (this.state.isConnected) return;
        
        const sessionId = this.state.currentSession?.sessionId;
        if (!sessionId) {
            this.app.ui.showNotification('No active session', 'error');
            return false;
        }
        
        this.app.ui.updateConnectionStatus('connecting');
        
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws?session=${encodeURIComponent(sessionId)}`;
        
        try {
            this.state.ws = new WebSocket(wsUrl);
            this.setupWebSocket();
            return true;
        } catch (error) {
            console.error('WebSocket creation error:', error);
            this.app.ui.showNotification('Connection failed', 'error');
            return false;
        }
    }

    setupWebSocket() {
        const ws = this.state.ws;
        
        ws.onopen = () => {
            this.state.isConnected = true;
            this.state.reconnectAttempts = 0;
            this.app.onConnectionStateChange('connected');
            this.app.ui.showNotification('Connected to secure chat', 'success');
            
            this.send({ type: 'init' });
        };
        
        ws.onclose = (event) => {
            this.state.isConnected = false;
            this.app.onConnectionStateChange('disconnected');
            
            console.log('WebSocket closed:', event.code, event.reason);
            
            if (event.code !== 1000) { // Normal closure
                this.app.ui.showNotification('Disconnected from server', 'warning');
                this.handleReconnection();
            }
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.app.onConnectionStateChange('error');
            this.app.ui.showNotification('Connection error', 'error');
        };
        
        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (error) {
                console.error('Message parse error:', error);
            }
        };
    }

    handleMessage(data) {
        switch(data.type) {
            case 'message':
                this.app.onMessageReceived(data);
                break;
                
            case 'users':
                this.app.onUsersUpdated(data.users || []);
                break;
                
            case 'typing':
                if (data.user && data.user !== this.state.currentUser?.username) {
                    this.app.onTyping(data.user);
                }
                break;
                
            case 'edit':
                this.app.ui.updateMessage(data.messageId, data.text);
                break;
                
            case 'system':
                this.app.ui.addMessage(data);
                break;
                
            case 'error':
                this.app.ui.showNotification(data.message || 'An error occurred', 'error');
                break;
                
            case 'pong':
                break;
                
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    send(data) {
        if (!this.state.ws || this.state.ws.readyState !== WebSocket.OPEN) {
            console.warn('WebSocket not ready for sending');
            return false;
        }
        
        try {
            this.state.ws.send(JSON.stringify(data));
            return true;
        } catch (error) {
            console.error('Send error:', error);
            return false;
        }
    }

    handleReconnection() {
        if (!CONFIG.AUTO_RECONNECT || !this.state.currentSession) {
            return;
        }
        
        if (this.state.reconnectAttempts >= CONFIG.WS_RECONNECT_ATTEMPTS) {
            this.app.ui.showNotification('Max reconnection attempts reached', 'error');
            return;
        }
        
        this.state.reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, this.state.reconnectAttempts), 30000);
        
        console.log(`Reconnecting in ${delay}ms (Attempt ${this.state.reconnectAttempts})`);
        
        setTimeout(() => {
            if (!this.state.isConnected && this.state.currentSession) {
                this.connect();
            }
        }, delay);
    }

    disconnect() {
        if (this.state.ws) {
            this.state.ws.close(1000, 'User disconnected');
            this.state.ws = null;
        }
        this.state.isConnected = false;
    }
}

class AuthHandler {
    constructor(app) {
        this.app = app;
    }

    async login(username, password) {
        if (!username || !password) {
            this.app.ui.showNotification('Please enter username and password', 'warning');
            return false;
        }

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                const error = await response.text();
                throw new Error(error || 'Login failed');
            }

            const data = await response.json();
            
            if (data.success) {
                this.app.state.currentUser = data.user;
                this.app.state.currentSession = {
                    sessionId: data.sessionId,
                    expiresAt: data.expiresAt
                };

                localStorage.setItem('secureChatSession', JSON.stringify(this.app.state.currentSession));
                localStorage.setItem('userData', JSON.stringify(data.user));

                // Update UI
                this.app.ui.updateUserProfile(data.user);
                this.app.ui.showChatInterface();
                this.app.ui.showNotification('Login successful!', 'success');

                this.app.network.connect();

                return true;
            }
        } catch (error) {
            this.app.ui.showNotification(error.message, 'error');
            console.error('Login error:', error);
        }

        return false;
    }

    async register(username, password, displayName) {
        if (!username || !password) {
            this.app.ui.showNotification('Please enter username and password', 'warning');
            return false;
        }

        if (username.length < 3) {
            this.app.ui.showNotification('Username must be at least 3 characters', 'warning');
            return false;
        }

        if (password.length < 8) {
            this.app.ui.showNotification('Password must be at least 8 characters', 'warning');
            return false;
        }

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username, 
                    password, 
                    displayName: displayName || username 
                })
            });

            if (!response.ok) {
                if (response.status === 409) {
                    throw new Error('Username already exists');
                }
                throw new Error('Registration failed');
            }

            const data = await response.json();
            
            if (data.success) {
                this.app.ui.showNotification('Registration successful! Please login.', 'success');
                this.app.ui.elements.passwordInput.value = '';
                return true;
            }
        } catch (error) {
            this.app.ui.showNotification(error.message, 'error');
            console.error('Registration error:', error);
        }

        return false;
    }

    checkSavedSession() {
        const savedSession = localStorage.getItem('secureChatSession');
        const savedUser = localStorage.getItem('userData');
        
        if (!savedSession || !savedUser) {
            return;
        }

        try {
            const session = JSON.parse(savedSession);
            const user = JSON.parse(savedUser);
            
            if (session.expiresAt && new Date(session.expiresAt) > new Date()) {
                this.app.state.currentUser = user;
                this.app.state.currentSession = session;
                
                this.validateSession(session.sessionId);
            } else {
                this.clearSavedData();
            }
        } catch (error) {
            console.error('Session parse error:', error);
            this.clearSavedData();
        }
    }

    async validateSession(sessionId) {
        try {
            const response = await fetch('/api/session', {
                headers: { 'X-Session-ID': sessionId }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    this.app.state.currentUser = data.user;
                    this.app.state.currentSession = data.session;
                    
                    this.app.ui.updateUserProfile(data.user);
                    this.app.ui.showChatInterface();
                    this.app.network.connect();
                    
                    this.app.ui.showNotification(`Welcome back, ${data.user.displayName}!`, 'success');
                    return true;
                }
            }
        } catch (error) {
            console.error('Session validation error:', error);
        }

        this.clearSavedData();
        return false;
    }

    async logout() {
        if (!confirm('Are you sure you want to logout?')) {
            return;
        }

        const sessionId = this.app.state.currentSession?.sessionId;
        
        if (sessionId) {
            try {
                await fetch('/api/logout', {
                    headers: { 'X-Session-ID': sessionId }
                });
            } catch (error) {
                console.error('Logout API error:', error);
            }
        }

        this.clearSavedData();
        this.app.cleanup();
        
        this.app.ui.showLoginScreen();
        this.app.ui.showNotification('Logged out successfully', 'success');
    }

    clearSavedData() {
        localStorage.removeItem('secureChatSession');
        localStorage.removeItem('userData');
        localStorage.removeItem('messageDraft');
        
        this.app.state.reset();
    }
}

class EventHandler {
    constructor(app) {
        this.app = app;
        this.ui = app.ui;
        this.auth = app.auth;
    }

    bindEvents() {
        this.bindLoginEvents();
        this.bindChatEvents();
        this.bindMessageEvents();
        this.bindWindowEvents();
    }

    bindLoginEvents() {
        const { usernameInput, passwordInput, loginBtn, registerBtn } = this.ui.elements;
        
        [usernameInput, passwordInput].forEach(input => {
            if (input) {
                input.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        this.auth.login(usernameInput.value, passwordInput.value);
                    }
                });
            }
        });
        
        if (loginBtn) {
            loginBtn.addEventListener('click', () => {
                this.auth.login(usernameInput.value, passwordInput.value);
            });
        }
        
        if (registerBtn) {
            registerBtn.addEventListener('click', () => {
                const displayName = this.ui.elements.displayNameInput?.value;
                this.auth.register(usernameInput.value, passwordInput.value, displayName);
            });
        }
    }

    bindChatEvents() {
        const { 
            logoutBtn, themeToggle, settingsBtn, closeSettings,
            emojiBtn, attachBtn, sendButton, messageInput 
        } = this.ui.elements;
        
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.auth.logout());
        }
        
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.ui.toggleTheme());
        }
        
        // Settings
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => this.ui.showSettings());
        }
        
        if (closeSettings) {
            closeSettings.addEventListener('click', () => this.ui.hideSettings());
        }
        
        document.addEventListener('click', (e) => {
            if (e.target === this.ui.elements.settingsModal) {
                this.ui.hideSettings();
            }
        });
        
        if (emojiBtn) {
            emojiBtn.addEventListener('click', () => {
                this.ui.showNotification('Emoji picker coming soon!', 'info');
            });
        }
        
        if (attachBtn) {
            attachBtn.addEventListener('click', () => {
                this.ui.showNotification('File attachment coming soon!', 'info');
            });
        }
        
        if (sendButton) {
            sendButton.addEventListener('click', () => {
                const text = messageInput?.value.trim();
                if (text) {
                    this.app.sendMessage(text);
                    messageInput.value = '';
                    this.ui.autoResizeTextarea();
                    this.ui.updateCharCount(0);
                }
            });
        }
        
        if (messageInput) {
            messageInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendButton?.click();
                }
            });
            
            messageInput.addEventListener('input', () => {
                this.ui.autoResizeTextarea();
                const count = messageInput.value.length;
                this.ui.updateCharCount(count);
                
                clearTimeout(this.app.state.typingTimeout);
                if (count > 0) {
                    this.app.updateTypingStatus(true);
                    this.app.state.typingTimeout = setTimeout(() => {
                        this.app.updateTypingStatus(false);
                    }, CONFIG.TYPING_TIMEOUT);
                } else {
                    this.app.updateTypingStatus(false);
                }
            });
            
            messageInput.addEventListener('focus', () => {
                this.app.state.autoScroll = true;
                this.app.state.unreadMessages = 0;
                this.ui.updateUnreadCount(0);
            });
        }
    }

    bindMessageEvents() {
        const messagesContainer = this.ui.elements.messagesContainer;
        if (messagesContainer) {
            messagesContainer.addEventListener('scroll', () => {
                const { scrollTop, scrollHeight, clientHeight } = messagesContainer;
                const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
                this.app.state.autoScroll = isAtBottom;
            });
        }
    }

    bindWindowEvents() {
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.app.state.unreadMessages = 0;
                this.ui.updateUnreadCount(0);
            }
        });
        
        window.addEventListener('focus', () => {
            this.app.state.unreadMessages = 0;
            this.ui.updateUnreadCount(0);
        });
        
        window.addEventListener('beforeunload', (e) => {
            if (this.app.state.isConnected) {
                this.app.network.send({ type: 'status', status: 'away' });
            }
        });
        
        window.addEventListener('online', () => {
            this.ui.showNotification('You are back online', 'success');
            if (this.app.state.currentSession && !this.app.state.isConnected) {
                this.app.network.connect();
            }
        });
        
        window.addEventListener('offline', () => {
            this.ui.showNotification('You are offline', 'warning');
        });
    }

    unbindEvents() {
    }
}

class Utils {
    constructor() {
        this.audioContext = null;
        this.notificationSound = null;
    }

    debug(...args) {
        if (CONFIG.DEBUG_MODE) {
            console.log('[DEBUG]', ...args);
        }
    }

    formatTime(date) {
        return new Date(date).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    formatDate(date) {
        return new Date(date).toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });
    }

    timeAgo(timestamp) {
        const seconds = Math.floor((Date.now() - timestamp) / 1000);
        
        const intervals = {
            year: 31536000,
            month: 2592000,
            week: 604800,
            day: 86400,
            hour: 3600,
            minute: 60,
            second: 1
        };
        
        for (const [unit, secondsInUnit] of Object.entries(intervals)) {
            const interval = Math.floor(seconds / secondsInUnit);
            if (interval >= 1) {
                return `${interval} ${unit}${interval === 1 ? '' : 's'} ago`;
            }
        }
        
        return 'just now';
    }

    detectSuspiciousContent(text) {
        const suspiciousPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /data:/gi,
            /vbscript:/gi,
            /expression\s*\(/gi
        ];
        
        return suspiciousPatterns.some(pattern => pattern.test(text));
    }

    sanitizeInput(text) {
        if (!text) return '';
        
        text = text.trim().replace(/\s+/g, ' ');
        
        const escapeMap = {
            '&': '&amp;',
            // '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;'
        };
        
        return text.replace(/[&<>"'\/]/g, char => escapeMap[char] || char);
    }

    generateAvatarColor(name) {
        const colors = [
            '#00d4aa', '#ff6b6b', '#4ecdc4', '#ffd166',
            '#06d6a0', '#118ab2', '#ef476f', '#ffd166',
            '#073b4c', '#118ab2', '#06d6a0', '#ffd166'
        ];
        
        let hash = 0;
        for (let i = 0; i < name.length; i++) {
            hash = name.charCodeAt(i) + ((hash << 5) - hash);
        }
        
        const index = Math.abs(hash) % colors.length;
        return colors[index];
    }

    getInitials(name) {
        if (!name) return '??';
        
        return name
            .split(' ')
            .map(part => part[0])
            .join('')
            .toUpperCase()
            .substring(0, 2);
    }

    async playNotificationSound() {
        try {
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }
            
            const oscillator = this.audioContext.createOscillator();
            const gainNode = this.audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(this.audioContext.destination);
            
            oscillator.frequency.value = 800;
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0.3, this.audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.1);
            
            oscillator.start(this.audioContext.currentTime);
            oscillator.stop(this.audioContext.currentTime + 0.1);
        } catch (error) {
            console.error('Audio error:', error);
        }
    }

    debounce(func, wait) {
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

    throttle(func, limit) {
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

    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(
            () => this.debug('Copied to clipboard'),
            (err) => console.error('Copy failed:', err)
        );
    }

    downloadFile(filename, content, type = 'text/plain') {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.chatApp = new SecureChatApp();
    
    if (CONFIG.DEBUG_MODE) {
        window.debugApp = window.chatApp;
    }
    
    console.log('🔒 Secure Chat v2.0 initialized');
});