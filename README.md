## Requirements

- Python 3.11+

## Setup

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Start the WebSocket server** (terminal 1)
```bash
python server.py
```

**3. Start the HTTP server** (terminal 2)
```bash
python file_server.py
```

**4. Open the app**

Go to `http://localhost:8080` in two separate browser windows.

- Register or log in with a username (3–32 chars) and password (8+ chars)
- Once both users are logged in, click a username in the sidebar to open a chat
- Type a message and press Enter to send
