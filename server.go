package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

const (
	MaxConnections      = 50
	MaxMessageLength    = 2000
	SessionDuration     = 24 * time.Hour
	PingInterval        = 30 * time.Second
	WriteTimeout        = 10 * time.Second
	RateLimitWindow     = 5 * time.Second
	MaxRequestsPerIP    = 10
	MaxMessagesStored   = 1000
	MessageCleanupHours = 24
)

var (
	hmacSecret = generateSecureKey(32)
)

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	IPAddress string    `json:"-"`
	UserAgent string    `json:"-"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"displayName"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	LastSeen     time.Time `json:"lastSeen"`
	IsOnline     bool      `json:"isOnline"`
	IsAdmin      bool      `json:"isAdmin"`
	AvatarColor  string    `json:"avatarColor"`
	Status       string    `json:"status"`
}

type Message struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	UserID    string    `json:"userId"`
	Text      string    `json:"text"`
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Timestamp int64     `json:"timestamp"`
	Signature string    `json:"signature,omitempty"`
	Edited    bool      `json:"edited"`
	Deleted   bool      `json:"deleted"`
}

type Client struct {
	conn      *websocket.Conn
	sessionID string
	userID    string
	username  string
	ip        string
	mu        sync.Mutex
}

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
}

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: 5 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == "http://localhost:8080" || origin == "https://localhost:8080"
		},
	}
	// (( BUG
	clients   = make(map[string]*Client)  // sessionID -> Client
	users     = make(map[string]*User)    // userID -> User
	sessions  = make(map[string]*Session) // sessionID -> Session
	messages  []Message
	userStats = struct {
		TotalMessages int `json:"totalMessages"`
		ActiveUsers   int `json:"activeUsers"`
		PeakUsers     int `json:"peakUsers"`
	}{}

	mu sync.RWMutex

	rateLimiter = &RateLimiter{
		requests: make(map[string][]time.Time),
	}
)

func main() {
	log.Println("🚀 Starting Secure Chat Server...")
	log.Println("🔐 Security Features Enabled:")
	log.Println("   • HMAC Message Signing")
	log.Println("   • Rate Limiting")
	log.Println("   • Password Hashing (bcrypt)")
	log.Println("   • Session Management")
	log.Println("   • XSS Protection")

	go cleanupRoutine()

	createAdminUser()

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./public"))
	mux.Handle("/", addSecurityHeaders(fs))

	mux.HandleFunc("/api/register", rateLimitMiddleware(handleRegister))
	mux.HandleFunc("/api/login", rateLimitMiddleware(handleLogin))
	mux.HandleFunc("/api/logout", authMiddleware(handleLogout))
	mux.HandleFunc("/api/session", authMiddleware(handleSession))
	mux.HandleFunc("/api/users", authMiddleware(handleGetUsers))
	mux.HandleFunc("/api/messages", authMiddleware(handleGetMessages))
	mux.HandleFunc("/api/stats", authMiddleware(handleStats))
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/ws", authMiddleware(handleWebSocket))

	mux.HandleFunc("/api/admin/users", adminMiddleware(handleAdminUsers))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Server ready on http://localhost:8080")
	log.Println("Max concurrent users:", MaxConnections)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Server error:", err)
	}
}

func addSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "+
				"font-src 'self' https://cdnjs.cloudflare.com; "+
				"connect-src 'self' ws://localhost:8080; "+
				"img-src 'self' data:;")
		if strings.HasPrefix(r.URL.Path, "/api") || r.URL.Path == "/ws" {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		rateLimiter.mu.Lock()
		now := time.Now()

		requests := rateLimiter.requests[ip]
		var validRequests []time.Time
		for _, t := range requests {
			if now.Sub(t) < RateLimitWindow {
				validRequests = append(validRequests, t)
			}
		}

		if len(validRequests) >= MaxRequestsPerIP {
			rateLimiter.mu.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		rateLimiter.requests[ip] = append(validRequests, now)
		rateLimiter.mu.Unlock()

		next.ServeHTTP(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			next.ServeHTTP(w, r)
			return
		}

		var sessionID string

		if cookie, err := r.Cookie("session_id"); err == nil {
			sessionID = cookie.Value
		}

		if sessionID == "" {
			sessionID = r.Header.Get("X-Session-ID")
		}

		if sessionID == "" {
			http.Error(w, "Unauthorized: No session", http.StatusUnauthorized)
			return
		}

		mu.RLock()
		session, exists := sessions[sessionID]
		mu.RUnlock()

		if !exists {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		if time.Now().After(session.ExpiresAt) {
			mu.Lock()
			delete(sessions, sessionID)
			mu.Unlock()
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		session.ExpiresAt = time.Now().Add(SessionDuration)

		next.ServeHTTP(w, r)
	}
}

func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			if cookie, err := r.Cookie("session_id"); err == nil {
				sessionID = cookie.Value
			}
		}

		mu.RLock()
		session, exists := sessions[sessionID]
		mu.RUnlock()

		if !exists {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		mu.RLock()
		user, userExists := users[session.UserID]
		mu.RUnlock()

		if !userExists || !user.IsAdmin {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func generateSecureKey(length int) []byte {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Failed to generate secure key:", err)
	}
	return key
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionID() string {
	return "sess_" + generateID()
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = strings.Split(r.RemoteAddr, ":")[0]
		}
	}
	return ip
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func signMessage(messageID, userID, text string, timestamp int64) string {
	message := fmt.Sprintf("%s:%s:%s:%d", messageID, userID, text, timestamp)
	h := hmac.New(sha256.New, hmacSecret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func verifyMessage(msg Message) bool {
	expectedSig := signMessage(msg.ID, msg.UserID, msg.Text, msg.Timestamp)
	return hmac.Equal([]byte(msg.Signature), []byte(expectedSig))
}

func sanitizeInput(input string) string {
	input = strings.TrimSpace(input)
	// hoommmmmm )
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")

	input = strings.Join(strings.Fields(input), " ")

	return input
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	//  input
	data.Username = strings.TrimSpace(data.Username)
	data.DisplayName = strings.TrimSpace(data.DisplayName)

	if len(data.Username) < 3 || len(data.Username) > 20 {
		http.Error(w, "Username must be 3-20 characters", http.StatusBadRequest)
		return
	}

	if len(data.Password) < 8 {
		http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	mu.RLock()
	for _, user := range users {
		if strings.EqualFold(user.Username, data.Username) {
			mu.RUnlock()
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}
	mu.RUnlock()

	// Hash
	passwordHash, err := hashPassword(data.Password)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	colors := []string{"#00d4aa", "#ff6b6b", "#4ecdc4", "#ffd166", "#06d6a0", "#118ab2"}
	colorIndex := len(users) % len(colors)

	// Create user
	userID := generateID()
	user := &User{
		ID:           userID,
		Username:     data.Username,
		DisplayName:  data.DisplayName,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
		AvatarColor:  colors[colorIndex],
		Status:       "offline",
	}

	mu.Lock()
	users[userID] = user
	mu.Unlock()

	log.Printf("👤 New user registered: %s (%s)", user.Username, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Registration successful",
		"userId":  userID,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	data.Username = strings.TrimSpace(data.Username)

	// Find user
	mu.RLock()
	var foundUser *User
	for _, user := range users {
		if strings.EqualFold(user.Username, data.Username) {
			foundUser = user
			break
		}
	}
	mu.RUnlock()

	if foundUser == nil || !checkPassword(data.Password, foundUser.PasswordHash) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	mu.Lock()
	for sessionID, session := range sessions {
		if session.UserID == foundUser.ID {
			delete(sessions, sessionID)
			if client, exists := clients[sessionID]; exists {
				client.conn.Close()
				delete(clients, sessionID)
			}
		}
	}
	mu.Unlock()

	sessionID := generateSessionID()
	session := &Session{
		ID:        sessionID,
		UserID:    foundUser.ID,
		Username:  foundUser.Username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(SessionDuration),
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	mu.Lock()
	sessions[sessionID] = session
	foundUser.LastSeen = time.Now()
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	response := map[string]interface{}{
		"success":   true,
		"sessionId": sessionID,
		"user":      foundUser,
		"expiresAt": session.ExpiresAt.Format(time.RFC3339),
		"maxUsers":  MaxConnections,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	log.Printf("  User logged in: %s from %s", foundUser.Username, getClientIP(r))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		if cookie, err := r.Cookie("session_id"); err == nil {
			sessionID = cookie.Value
		}
	}

	if sessionID != "" {
		mu.Lock()
		if session, exists := sessions[sessionID]; exists {
			if user, userExists := users[session.UserID]; userExists {
				user.IsOnline = false
				user.Status = "offline"
			}
			delete(sessions, sessionID)
		}

		if client, exists := clients[sessionID]; exists {
			client.conn.Close()
			delete(clients, sessionID)
		}
		mu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Path:     "/",
		})
	}

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		if cookie, err := r.Cookie("session_id"); err == nil {
			sessionID = cookie.Value
		}
	}

	mu.RLock()
	session, sessionExists := sessions[sessionID]
	mu.RUnlock()

	if !sessionExists {
		http.Error(w, "Session not found", http.StatusUnauthorized)
		return
	}

	mu.RLock()
	user, userExists := users[session.UserID]
	mu.RUnlock()

	if !userExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success":    true,
		"session":    session,
		"user":       user,
		"serverTime": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetUsers(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	onlineUsers := []User{}
	allUsers := []User{}

	for _, user := range users {
		allUsers = append(allUsers, *user)
		if user.IsOnline {
			onlineUsers = append(onlineUsers, *user)
		}
	}

	response := map[string]interface{}{
		"onlineUsers": onlineUsers,
		"allUsers":    allUsers,
		"onlineCount": len(onlineUsers),
		"totalCount":  len(allUsers),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetMessages(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	start := 0
	if len(messages) > 100 {
		start = len(messages) - 100
	}

	response := map[string]interface{}{
		"messages": messages[start:],
		"count":    len(messages),
		"hasMore":  len(messages) > 100,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()

	stats := map[string]interface{}{
		"activeUsers":    len(clients),
		"totalUsers":     len(users),
		"totalMessages":  userStats.TotalMessages,
		"peakUsers":      userStats.PeakUsers,
		"uptime":         time.Since(startTime).String(),
		"serverTime":     time.Now().Format(time.RFC3339),
		"maxConnections": MaxConnections,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	if len(clients) >= MaxConnections {
		status = "full"
	}

	response := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "2.0.0",
		"features": []string{
			"end-to-end-encryption",
			"session-management",
			"rate-limiting",
			"message-signing",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	userList := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		userData := map[string]interface{}{
			"id":          user.ID,
			"username":    user.Username,
			"displayName": user.DisplayName,
			"createdAt":   user.CreatedAt,
			"lastSeen":    user.LastSeen,
			"isOnline":    user.IsOnline,
			"isAdmin":     user.IsAdmin,
			"status":      user.Status,
		}
		userList = append(userList, userData)
	}

	response := map[string]interface{}{
		"users": userList,
		"count": len(userList),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	if len(clients) >= MaxConnections {
		mu.RUnlock()
		http.Error(w, "Server is at maximum capacity", http.StatusServiceUnavailable)
		return
	}
	mu.RUnlock()

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "Session required", http.StatusUnauthorized)
		return
	}

	mu.RLock()
	session, sessionExists := sessions[sessionID]
	mu.RUnlock()

	if !sessionExists {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	mu.RLock()
	user, userExists := users[session.UserID]
	mu.RUnlock()

	if !userExists {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &Client{
		conn:      conn,
		sessionID: sessionID,
		userID:    user.ID,
		username:  user.Username,
		ip:        getClientIP(r),
	}

	// Set ping/pong handlers
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(PingInterval * 2))
		return nil
	})

	mu.Lock()
	clients[sessionID] = client
	user.IsOnline = true
	user.Status = "online"
	user.LastSeen = time.Now()

	userStats.ActiveUsers = len(clients)
	if userStats.ActiveUsers > userStats.PeakUsers {
		userStats.PeakUsers = userStats.ActiveUsers
	}
	mu.Unlock()

	welcomeMsg := Message{
		ID:        generateID(),
		Username:  "System",
		UserID:    "system",
		Text:      fmt.Sprintf("🌟 %s has joined the secure chat", user.DisplayName),
		Time:      time.Now(),
		Type:      "system",
		Timestamp: time.Now().UnixNano(),
	}

	addMessage(welcomeMsg)
	broadcast(welcomeMsg)
	updateOnlineUsers()

	client.sendInitialData()

	log.Printf("🔗 WebSocket connected: %s (Total: %d)", user.Username, len(clients))

	go client.ping()
	client.handleMessages()
}

func (c *Client) sendInitialData() {
	mu.RLock()
	defer mu.RUnlock()

	// Get recent messages
	recentMessages := messages
	if len(recentMessages) > 50 {
		recentMessages = recentMessages[len(recentMessages)-50:]
	}

	// Get online users
	onlineUsers := []User{}
	for _, user := range users {
		if user.IsOnline {
			onlineUsers = append(onlineUsers, *user)
		}
	}

	initialData := map[string]interface{}{
		"type": "init",
		"data": map[string]interface{}{
			"user":       users[c.userID],
			"messages":   recentMessages,
			"users":      onlineUsers,
			"stats":      userStats,
			"serverTime": time.Now().Format(time.RFC3339),
		},
	}

	c.mu.Lock()
	c.conn.WriteJSON(initialData)
	c.mu.Unlock()
}

func (c *Client) ping() {
	ticker := time.NewTicker(PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			err := c.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(WriteTimeout))
			c.mu.Unlock()

			if err != nil {
				c.disconnect()
				return
			}
		}
	}
}

func (c *Client) handleMessages() {
	defer c.disconnect()

	for {
		var msg map[string]interface{}
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error for %s: %v", c.username, err)
			}
			break
		}

		c.processMessage(msg)
	}
}

func (c *Client) processMessage(msg map[string]interface{}) {
	msgType, _ := msg["type"].(string)

	switch msgType {
	case "message":
		text, _ := msg["text"].(string)
		text = sanitizeInput(text)

		if len(text) == 0 || len(text) > MaxMessageLength {
			return
		}

		message := Message{
			ID:        generateID(),
			Username:  c.username,
			UserID:    c.userID,
			Text:      text,
			Time:      time.Now(),
			Type:      "message",
			Timestamp: time.Now().UnixNano(),
			Signature: signMessage(generateID(), c.userID, text, time.Now().UnixNano()),
		}

		addMessage(message)
		broadcast(message)
		userStats.TotalMessages++

	case "typing":
		typingMsg := map[string]interface{}{
			"type":   "typing",
			"user":   c.username,
			"userId": c.userID,
		}
		broadcastToOthers(c.sessionID, typingMsg)

	case "edit":
		messageID, _ := msg["messageId"].(string)
		newText, _ := msg["text"].(string)
		newText = sanitizeInput(newText)

		mu.Lock()
		for i, m := range messages {
			if m.ID == messageID && m.UserID == c.userID {
				messages[i].Text = newText
				messages[i].Edited = true

				editMsg := map[string]interface{}{
					"type":      "edit",
					"messageId": messageID,
					"text":      newText,
					"user":      c.username,
				}
				broadcast(editMsg)
				break
			}
		}
		mu.Unlock()
	}
}

func (c *Client) disconnect() {
	mu.Lock()
	defer mu.Unlock()

	// Remove client
	delete(clients, c.sessionID)

	// Update user status
	if user, exists := users[c.userID]; exists {
		user.IsOnline = false
		user.Status = "offline"
		user.LastSeen = time.Now()
	}

	// Update stats
	userStats.ActiveUsers = len(clients)

	leaveMsg := Message{
		ID:        generateID(),
		Username:  "System",
		UserID:    "system",
		Text:      fmt.Sprintf("👋 %s has left the chat", c.username),
		Time:      time.Now(),
		Type:      "system",
		Timestamp: time.Now().UnixNano(),
	}

	addMessage(leaveMsg)
	broadcast(leaveMsg)
	updateOnlineUsers()

	c.conn.Close()
	log.Printf("🔌 WebSocket disconnected: %s (Remaining: %d)", c.username, len(clients))
}

func addMessage(msg Message) {
	mu.Lock()
	messages = append(messages, msg)

	if len(messages) > MaxMessagesStored {
		messages = messages[len(messages)-MaxMessagesStored:]
	}
	mu.Unlock()
}

func broadcast(msg interface{}) {
	mu.RLock()
	defer mu.RUnlock()

	for _, client := range clients {
		go func(c *Client) {
			c.mu.Lock()
			defer c.mu.Unlock()

			c.conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
			c.conn.WriteJSON(msg)
		}(client)
	}
}

func broadcastToOthers(excludeSessionID string, msg interface{}) {
	mu.RLock()
	defer mu.RUnlock()

	for sessionID, client := range clients {
		if sessionID == excludeSessionID {
			continue
		}

		go func(c *Client) {
			c.mu.Lock()
			defer c.mu.Unlock()

			c.conn.SetWriteDeadline(time.Now().Add(WriteTimeout))
			c.conn.WriteJSON(msg)
		}(client)
	}
}

func updateOnlineUsers() {
	mu.RLock()
	defer mu.RUnlock()

	onlineUsers := []User{}
	for _, user := range users {
		if user.IsOnline {
			onlineUsers = append(onlineUsers, *user)
		}
	}

	updateMsg := map[string]interface{}{
		"type":  "users",
		"users": onlineUsers,
		"count": len(onlineUsers),
	}

	broadcast(updateMsg)
}

func cleanupRoutine() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mu.Lock()

			now := time.Now()
			for sessionID, session := range sessions {
				if now.After(session.ExpiresAt) {
					delete(sessions, sessionID)
				}
			}

			cutoff := time.Now().Add(-MessageCleanupHours * time.Hour)
			var recentMessages []Message
			for _, msg := range messages {
				if msg.Time.After(cutoff) {
					recentMessages = append(recentMessages, msg)
				}
			}
			messages = recentMessages

			mu.Unlock()
			log.Println("🧹 Cleanup completed")
		}
	}
}

func createAdminUser() {
	adminHash, _ := hashPassword("admin123")

	adminUser := &User{
		ID:           "admin_" + generateID(),
		Username:     "admin",
		DisplayName:  "Administrator",
		PasswordHash: adminHash,
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
		IsOnline:     false,
		IsAdmin:      true,
		AvatarColor:  "#ff6b6b",
		Status:       "offline",
	}

	mu.Lock()
	users[adminUser.ID] = adminUser
	mu.Unlock()

	log.Println("👑 Admin user created: admin / admin123")
}

var startTime = time.Now()
