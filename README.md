# chat-app
Simple real-time chat backend server. (: 

# 🌟 Features
- Real-time messaging with WebSocket

- Beautiful dark theme with animations

- User presence (online/offline)

- Message history with auto-scroll

- Responsive design for all devices

- Easy to deploy - single binary


# Quick Start
1. Install Go

2. Install dependency: go mod download

3. Run server: go run server.go

4. Connect to: ws: //localhost:8080/







## APi
-  ``GET /ws`` - WebSocket endpoint

-  ``GET /api/users`` - Get online users

-  ``GET /api/stats`` - Server stats


## How It Works 
```
Client → WebSocket → Handler → Broadcast → All Clients
```


## Deployment
  ```bash
  # Development
  go run server.go
  
  # Production
  go build -o chat-app server.go
  ./chat-app
  
  # Docker
  docker build -t chat-server .
  docker run -p 8080:8080 chat-server
  ```
