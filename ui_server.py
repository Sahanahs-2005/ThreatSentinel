from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re

from security import inspect_message, inspect_response
from local_ai import get_ai_response


HOST = "127.0.0.1"
PORT = 8080


# Extra checks for common dangerous wording that existing rules may miss.
# These supplement security.py; they do not guarantee detection of every threat.
EXTRA_BLOCK_PATTERNS = [
    (
        r"\b(ignore|disregard|bypass|override)\b.{0,60}"
        r"\b(previous|prior|system|security|safety)\b.{0,40}"
        r"\b(instructions?|rules?|checks?|filters?)\b",
        "Possible attempt to bypass security instructions."
    ),
    (
        r"\b(reveal|show|print|display|expose|leak)\b.{0,60}"
        r"\b(system prompt|api key|secret key|password)\b",
        "Possible attempt to reveal confidential system information."
    ),
    (
        r"\b(shall i|should i|can i|could i|"
        r"how can i|how do i|help me|tell me how to)\b"
        r".{0,50}\b(murder|kill|shoot|stab|attack)\b",
        "The message may express violent intent or request assistance with violence."
    ),
    (
        r"\b(how can i|how do i|how to|help me|"
        r"tell me how to|teach me how to|steps to|"
        r"instructions to|ways to|plan to)\b"
        r".{0,80}\b(rob|robbery|steal|stealing|theft|"
        r"burglarize|burglary|shoplift|loot)\b",
        "The message may request assistance with theft or another crime."
    ),
    (
        r"\b(how can i|how do i|how to|help me|"
        r"tell me how to|teach me how to|steps to|ways to)\b"
        r".{0,80}\b(break into|rob a bank|rob a store|"
        r"steal money|commit robbery|commit theft)\b",
        "The message may request assistance with a crime."
    ),
]


def inspect_input_safely(message):
    """
    Inspect a message using the existing security module and extra checks.
    If inspection fails, do not allow the message through.
    """
    try:
        result = inspect_message(message)

        if not isinstance(result, dict):
            raise ValueError("Invalid security result.")

        action = result.get("action")
        reason = result.get("reason")

        if action not in ("ALLOW", "BLOCK", "QUARANTINE"):
            raise ValueError("Invalid security action.")

        if not isinstance(reason, str):
            raise ValueError("Invalid security reason.")

        # Existing rules take priority when they already block a message.
        if action != "ALLOW":
            return result

        # Supplement existing rules with common missed patterns.
        for pattern, explanation in EXTRA_BLOCK_PATTERNS:
            if re.search(pattern, message, re.IGNORECASE):
                return {
                    "action": "BLOCK",
                    "reason": explanation
                }

        return result

    except Exception:
        # Fail closed: never send a message to AI if inspection fails.
        return {
            "action": "QUARANTINE",
            "reason": "Security inspection failed. The message was not sent to the AI."
        }


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatSentinel AI</title>

<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #080d1b;
    color: #f2f5ff;
}

.layout {
    display: flex;
    min-height: 100vh;
}

.sidebar {
    width: 260px;
    padding: 28px 20px;
    background: #0d1427;
    border-right: 1px solid #26314b;
}

.logo {
    font-size: 23px;
    font-weight: bold;
    color: #45e6d0;
}

.logo span {
    color: #ff4fa3;
}

.subtitle, .sidebar-note {
    color: #8995b1;
    font-size: 13px;
    line-height: 1.7;
}

.status-card {
    margin-top: 35px;
    background: #141e34;
    border: 1px solid #293956;
    border-radius: 12px;
    padding: 16px;
}

.status-card h3 {
    font-size: 13px;
    color: #aab7d2;
}

.status {
    color: #45e6a8;
    font-size: 13px;
    margin: 12px 0;
}

.dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    background: #45e6a8;
    border-radius: 50%;
    margin-right: 8px;
}

.sidebar-note {
    margin-top: 28px;
}

.main {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
}

.topbar {
    padding: 22px 30px;
    border-bottom: 1px solid #26314b;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
}

.topbar h2 {
    margin: 0;
    font-size: 20px;
}

.badge {
    font-size: 12px;
    padding: 8px 12px;
    border: 1px solid #245d59;
    border-radius: 20px;
    color: #45e6d0;
    background: #102b30;
}

.chat {
    flex: 1;
    width: 100%;
    max-width: 950px;
    margin: 0 auto;
    padding: 30px 24px;
}

.welcome {
    text-align: center;
    padding: 50px 10px 28px;
}

.shield {
    font-size: 48px;
}

.welcome h1 {
    font-size: 30px;
    margin-bottom: 10px;
}

.welcome h1 span {
    color: #45e6d0;
}

.welcome p {
    color: #9ba8c3;
    line-height: 1.7;
}

.message {
    margin: 20px 0;
    padding: 17px 19px;
    border-radius: 14px;
    line-height: 1.7;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
}

.user {
    background: #192742;
    border: 1px solid #304466;
    margin-left: 12%;
}

.assistant {
    background: #111b30;
    border: 1px solid #263653;
    margin-right: 5%;
}

.security {
    display: inline-block;
    margin-top: 10px;
    font-size: 12px;
    padding: 5px 9px;
    border-radius: 6px;
    background: #173c31;
    color: #66f0b4;
}

.security.BLOCK {
    color: #ff7b91;
    background: #421c2b;
}

.security.QUARANTINE {
    color: #ffd477;
    background: #42351b;
}

.reason {
    color: #aab7d2;
    font-size: 12px;
    margin-top: 8px;
}

.composer {
    position: sticky;
    bottom: 0;
    padding: 18px 24px 24px;
    background: #080d1b;
    border-top: 1px solid #26314b;
}

.input-row {
    max-width: 900px;
    margin: auto;
    display: flex;
    gap: 12px;
}

textarea {
    flex: 1;
    resize: vertical;
    min-height: 55px;
    max-height: 180px;
    background: #111b30;
    color: white;
    border: 1px solid #354363;
    border-radius: 12px;
    padding: 17px;
    font-size: 15px;
    font-family: inherit;
    outline: none;
}

textarea:focus {
    border-color: #45e6d0;
}

button {
    border: 0;
    border-radius: 12px;
    padding: 0 24px;
    background: linear-gradient(135deg, #45e6d0, #3ab5d7);
    color: #07111f;
    font-weight: bold;
    cursor: pointer;
}

button:disabled {
    opacity: 0.5;
    cursor: wait;
}

.hint {
    text-align: center;
    color: #71809f;
    font-size: 11px;
    margin-top: 12px;
}

@media(max-width: 700px) {
    .sidebar {
        display: none;
    }

    .topbar {
        padding: 18px;
    }

    .chat {
        padding: 15px;
    }

    .welcome h1 {
        font-size: 24px;
    }

    .user, .assistant {
        margin-left: 0;
        margin-right: 0;
    }

    .composer {
        padding: 12px;
    }

    button {
        padding: 0 15px;
    }
}
</style>
</head>

<body>
<div class="layout">
    <aside class="sidebar">
        <div class="logo">THREAT<span>SENTINEL</span></div>

        <p class="subtitle">
            AI Security Gateway<br>
            Intelligent conversations with security inspection.
        </p>

        <div class="status-card">
            <h3>SYSTEM STATUS</h3>
            <div class="status"><span class="dot"></span>Security rules active</div>
            <div class="status"><span class="dot"></span>Local AI configured</div>
            <div class="status"><span class="dot"></span>Response inspection active</div>
        </div>

        <p class="sidebar-note">
            HOW IT WORKS<br><br>
            01 — Inspect the user message<br><br>
            02 — Allow or block the request<br><br>
            03 — Generate an AI response<br><br>
            04 — Inspect the AI response
        </p>
    </aside>

    <main class="main">
        <header class="topbar">
            <h2>Secure AI Chat</h2>
            <div class="badge">● LOCAL AI · LLAMA 3.2</div>
        </header>

        <section class="chat" id="chat">
            <div class="welcome" id="welcome">
                <div class="shield">🛡️</div>
                <h1>Welcome to <span>ThreatSentinel</span></h1>
                <p>
                    Your message is inspected before reaching the AI.
                    AI responses are inspected before display.
                </p>
            </div>
        </section>

        <footer class="composer">
            <div class="input-row">
                <textarea id="message"
                    placeholder="Ask something... (Enter to send, Shift+Enter for a new line)"></textarea>
                <button id="send" type="button">Send ↗</button>
            </div>
            <div class="hint">
                Local model · Input inspection · Output inspection
            </div>
        </footer>
    </main>
</div>

<script>
const chat = document.getElementById("chat");
const input = document.getElementById("message");
const sendButton = document.getElementById("send");

function addMessage(role, text, security, reason) {
    const welcome = document.getElementById("welcome");
    if (welcome) welcome.remove();

    const box = document.createElement("div");
    box.className = "message " + role;

    const title = document.createElement("strong");
    title.textContent = role === "user" ? "You" : "ThreatSentinel AI";

    const content = document.createElement("div");
    content.textContent = text;

    box.appendChild(title);
    box.appendChild(content);

    if (security) {
        const badge = document.createElement("div");
        badge.className = "security " + security;
        badge.textContent = "Security: " + security;
        box.appendChild(badge);
    }

    if (reason) {
        const detail = document.createElement("div");
        detail.className = "reason";
        detail.textContent = reason;
        box.appendChild(detail);
    }

    chat.appendChild(box);
    box.scrollIntoView({behavior: "smooth", block: "end"});
    return box;
}

async function sendMessage() {
    const message = input.value.trim();
    if (!message || sendButton.disabled) return;

    input.value = "";
    sendButton.disabled = true;
    input.disabled = true;

    addMessage("user", message);

    const loading = addMessage(
        "assistant",
        "Inspecting your message..."
    );

    try {
        const response = await fetch("/chat", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({message: message})
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "The request failed.");
        }

        loading.remove();

        // For blocked input, show BLOCK as the main security status.
        // For allowed input, show the AI output security decision.
        const displayAction =
            data.input_action !== "ALLOW"
                ? data.input_action
                : data.output_action;

        let reason = "Input: " + data.input_action +
                     " — " + data.input_reason;

        if (data.output_action) {
            reason += "\nOutput: " + data.output_action +
                      " — " + data.output_reason;
        }

        addMessage(
            "assistant",
            data.response || "No response was returned.",
            displayAction || "QUARANTINE",
            reason
        );

    } catch (error) {
        loading.remove();
        addMessage(
            "assistant",
            "The request could not be completed.",
            "QUARANTINE",
            error.message
        );
    } finally {
        sendButton.disabled = false;
        input.disabled = false;
        input.focus();
    }
}

sendButton.addEventListener("click", sendMessage);

input.addEventListener("keydown", function(event) {
    if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
});
</script>
</body>
</html>
"""


class ThreatSentinelHandler(BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return

        body = HTML.encode("utf-8")

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/chat":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length <= 0 or length > 20000:
                self.send_json(
                    400,
                    {"error": "Invalid message size."}
                )
                return

            raw_body = self.rfile.read(length)
            data = json.loads(raw_body.decode("utf-8"))

            if not isinstance(data, dict):
                self.send_json(
                    400,
                    {"error": "The request must be a JSON object."}
                )
                return

            message = data.get("message", "")

            if not isinstance(message, str) or not message.strip():
                self.send_json(
                    400,
                    {"error": "Please enter a valid message."}
                )
                return

            message = message.strip()

            # STEP 1: Inspect input before calling the AI.
            input_result = inspect_input_safely(message)
            input_action = input_result["action"]
            input_reason = input_result["reason"]

            # STEP 2: Stop blocked or quarantined messages.
            if input_action != "ALLOW":
                self.send_json(200, {
                    "response": (
                        "Your message was stopped by ThreatSentinel. "
                        "It was not sent to the AI."
                    ),
                    "input_action": input_action,
                    "input_reason": input_reason,
                    "output_action": None,
                    "output_reason": None
                })
                return

            # STEP 3: Generate a response for allowed input only.
            ai_response = get_ai_response(message)

            if not isinstance(ai_response, str):
                self.send_json(502, {
                    "error": "The AI returned an invalid response."
                })
                return

            if ai_response.startswith((
                "AI connection error:",
                "Unexpected AI response:"
            )):
                self.send_json(502, {
                    "error": ai_response
                })
                return

            # STEP 4: Inspect AI output.
            try:
                output_result = inspect_response(ai_response)

                if not isinstance(output_result, dict):
                    raise ValueError("Invalid output security result.")

                output_action = output_result.get("action")
                output_reason = output_result.get("reason")

                if output_action not in ("ALLOW", "BLOCK", "QUARANTINE"):
                    raise ValueError("Invalid output security action.")

                if not isinstance(output_reason, str):
                    raise ValueError("Invalid output security reason.")

            except Exception:
                self.send_json(200, {
                    "response": (
                        "The AI response was hidden because "
                        "output security inspection failed."
                    ),
                    "input_action": input_action,
                    "input_reason": input_reason,
                    "output_action": "QUARANTINE",
                    "output_reason": (
                        "Output security inspection failed."
                    )
                })
                return

            # STEP 5: Display only an approved response.
            if output_action == "ALLOW":
                safe_response = output_result.get("response")

                if not isinstance(safe_response, str):
                    safe_response = (
                        "The AI response was hidden because "
                        "its format was invalid."
                    )
                    output_action = "QUARANTINE"
                    output_reason = "Invalid response format."
            else:
                safe_response = (
                    "The AI response was hidden by output security."
                )

            self.send_json(200, {
                "response": safe_response,
                "input_action": input_action,
                "input_reason": input_reason,
                "output_action": output_action,
                "output_reason": output_reason
            })

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {
                "error": "Invalid request data."
            })

        except Exception:
            self.send_json(500, {
                "error": (
                    "An internal server error occurred. "
                    "Check the server terminal."
                )
            })

    def log_message(self, format, *args):
        print("[ThreatSentinel Server]", format % args)


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        (HOST, PORT),
        ThreatSentinelHandler
    )

    print("=" * 50)
    print("       THREATSENTINEL WEB INTERFACE")
    print("=" * 50)
    print(f"Open: http://{HOST}:{PORT}")
    print("Keep this terminal open while using the interface.")
    print("Press Ctrl+C to stop the server.")
    print("=" * 50)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nThreatSentinel server stopped.")
    finally:
        server.server_close()