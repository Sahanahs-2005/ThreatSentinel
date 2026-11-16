import os
import re
import csv
import joblib
import difflib
import threading


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "threat_model.joblib")
CUSTOM_PATH = os.path.join(BASE_DIR, "dataset", "custom_prompts.csv")

AUTO_RETRAIN = True        # retrain in the background when the CSV changes
SIMILARITY_LIMIT = 0.88    # how close a message must be to a CSV sentence


# --------------------------------------------------
# 0. TRAINED MODEL (loaded now, reloaded after retraining)
# --------------------------------------------------

_model_lock = threading.Lock()
_ml_model = None


def load_model():
    """Load the trained model. If it is missing, rules still work."""
    global _ml_model
    try:
        model = joblib.load(MODEL_PATH)
    except Exception:
        model = None
    with _model_lock:
        _ml_model = model


def ml_malicious_score(text):
    """Return the model's probability that the text is malicious, or None."""
    with _model_lock:
        model = _ml_model
    if model is None:
        return None
    try:
        classes = list(model.classes_)
        return float(model.predict_proba([text])[0][classes.index(1)])
    except Exception:
        return None


load_model()


# --------------------------------------------------
# 0b. YOUR OWN SENTENCES (dataset/custom_prompts.csv)
# --------------------------------------------------

MALICIOUS_LABELS = {
    "1", "true", "yes", "malicious", "unsafe",
    "attack", "injection", "harmful"
}
SAFE_LABELS = {
    "0", "false", "no", "benign", "safe",
    "normal", "legitimate", "clean"
}

_custom_lock = threading.Lock()
_custom_entries = []        # list of (normalized text, "malicious" / "safe")
_custom_mtime = None


def simplify(text):
    """Lowercase and collapse spaces and punctuation for comparing."""
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", str(text))
    text = re.sub(r"[^\w\s']", " ", text.lower())
    return re.sub(r"\s+", " ", text).strip()


def reload_custom_if_changed():
    """Re-read the CSV only when the file has been saved again."""
    global _custom_entries, _custom_mtime

    try:
        mtime = os.path.getmtime(CUSTOM_PATH)
    except OSError:
        with _custom_lock:
            _custom_entries = []
            _custom_mtime = None
        return

    if mtime == _custom_mtime:
        return

    entries = []
    try:
        with open(CUSTOM_PATH, newline="", encoding="utf-8-sig") as file:
            for row in csv.DictReader(file):
                text = simplify(row.get("text", ""))
                label = str(row.get("label", "")).strip().lower()
                if not text:
                    continue
                if label in MALICIOUS_LABELS:
                    entries.append((text, "malicious"))
                elif label in SAFE_LABELS:
                    entries.append((text, "safe"))
    except Exception:
        return  # keep the old list if the file is half-saved

    with _custom_lock:
        _custom_entries = entries
        _custom_mtime = mtime


def custom_lookup(message):
    """Return 'malicious', 'safe' or None based on your own sentences."""
    reload_custom_if_changed()
    text = simplify(message)

    with _custom_lock:
        entries = list(_custom_entries)

    if not text or not entries:
        return None

    best_label, best_ratio = None, 0.0

    for known, label in entries:
        if known == text:
            return label
        if abs(len(known) - len(text)) > max(len(text), len(known)) * 0.3:
            continue
        ratio = difflib.SequenceMatcher(None, text, known).ratio()
        if ratio > best_ratio:
            best_ratio, best_label = ratio, label

    if best_ratio >= SIMILARITY_LIMIT:
        return best_label

    return None


# --------------------------------------------------
# 0c. AUTOMATIC RETRAINING IN THE BACKGROUND
# --------------------------------------------------

_retrain_lock = threading.Lock()
_retraining = False
_failed_for_mtime = None


def _retrain_worker(csv_mtime):
    global _retraining, _failed_for_mtime
    try:
        import train_model
        train_model.main()
        load_model()
        print("[ThreatSentinel] Model retrained and reloaded.")
    except Exception as error:
        _failed_for_mtime = csv_mtime
        print("[ThreatSentinel] Automatic retraining failed:", error)
    finally:
        with _retrain_lock:
            _retraining = False


def retrain_if_needed():
    """Start background retraining when the CSV is newer than the model."""
    global _retraining

    if not AUTO_RETRAIN:
        return

    try:
        csv_mtime = os.path.getmtime(CUSTOM_PATH)
    except OSError:
        return

    try:
        model_mtime = os.path.getmtime(MODEL_PATH)
    except OSError:
        model_mtime = 0

    if csv_mtime <= model_mtime or csv_mtime == _failed_for_mtime:
        return

    with _retrain_lock:
        if _retraining:
            return
        _retraining = True

    threading.Thread(
        target=_retrain_worker, args=(csv_mtime,), daemon=True
    ).start()


# --------------------------------------------------
# 1. PROMPT INJECTION AND SECURITY BYPASS
# --------------------------------------------------

INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+instructions?\b",
    r"\b(disregard|bypass|override)\s+(all\s+)?(the\s+)?(previous|prior|existing|system|security)\s+instructions?\b",
    r"\breveal\s+(the\s+)?(hidden\s+)?system\s+prompt\b",
    r"\b(show|print|display|reveal|leak|expose)\s+(me\s+)?(your|the)\s+(hidden\s+)?(system\s+prompt|secret key|api key|passwords?)\b",
    r"\bignore\s+(your\s+)?safety\s+(rules|filters|guidelines)\b",
    r"\bdisable\s+(all\s+)?(security|safety)\s+(checks|filters|rules)\b",
    r"\b(ignore|disregard|bypass|override)\b.{0,60}"
    r"\b(previous|prior|system|security|safety)\b.{0,40}"
    r"\b(instructions?|rules?|checks?|filters?)\b",
    r"\b(reveal|show|print|display|expose|leak)\b.{0,60}"
    r"\b(system prompt|api key|secret key)\b",
]


# --------------------------------------------------
# 2. PRIVATE INFORMATION AND CREDENTIALS
# --------------------------------------------------

PRIVATE_DATA_PATTERNS = [
    r"\b(bank|banking)\s+account\s+(number|details|credentials)\b",
    r"\b(account|atm|debit|credit)\s+card\s+(number|details|credentials)\b",
    r"\b(password|passcode|pin|otp|one.time.password)\b",
    r"\b(social security|aadhaar|aadhar|passport|tax identification)\s+(number|details)\b",
    r"\b(private|personal|confidential)\s+(medical|financial|account|identity)\s+(information|data|details|records)\b",
    r"\b(account|bank|card|login|banking)\s+(details|info|information|balance|statement|credentials)\b",
]


THIRD_PARTY_PATTERNS = [
    r"\bmy\s+(friend|friends|classmate|classmates|colleague|colleagues|"
    r"teacher|teachers|neighbour|neighbor|partner|relative|family member)\b",
    r"\bsomeone\s+else(?:'s)?\b",
    r"\banother\s+person(?:'s)?\b",
    r"\btheir\s+(bank|account|card|password|private|personal|financial)\b",
    r"\b(?:his|her)\s+(bank|account|card|password|private|personal|financial)\b",
]


OBTAIN_PATTERNS = [
    r"\b(give|provide|tell|show|find|get|reveal|retrieve|look\s+up|"
    r"send|share|disclose|steal|access|fetch|obtain|expose|list|dump|export)\b",
]


PRIVATE_REQUEST_PATTERNS = [
    r"\b(get|find|steal|reveal|retrieve|look\s+up|obtain|expose|"
    r"give|provide|tell|show|send|share)\b.{0,100}\b"
    r"(someone else's|another person's|my friend's|their|his|her)\b.{0,100}\b"
    r"(bank account|account number|card number|password|passcode|pin|otp|"
    r"private information|personal information|financial details)\b",

    r"\b(my friend's|someone else's|another person's|their|his|her)\b.{0,100}\b"
    r"(bank account number|account number|card number|password|passcode|pin|"
    r"otp|private information|personal information|financial details)\b",

    r"\b(give|provide|tell|show|find|get|retrieve|reveal|look up|"
    r"obtain|steal|access)\b.{0,60}\b"
    r"(bank account number|atm number|card number|password|passcode|"
    r"pin|otp)\b",

    r"\b(all|every|everyone's|customers'?|users'?)\b.{0,30}"
    r"\b(account|bank|card|password|credentials|personal)\b.{0,30}"
    r"\b(details|info|information|data|records|numbers?)\b",

    r"\b(list|dump|export|show|give|fetch|get|extract)\b.{0,40}"
    r"\b(all|every)\b.{0,40}"
    r"\b(customers?|users?|clients?|employees|students)\b.{0,40}"
    r"\b(emails?|e-mail|phone|mobile|contact|addresses|details|data|records|passwords?)\b",
]


# --------------------------------------------------
# 3. DIRECT THREATS OF VIOLENCE
# --------------------------------------------------

VIOLENCE_PATTERNS = [
    r"\b(i want to|i will|i am going to|i'm going to)\s+"
    r"(kill|murder|shoot|stab|hurt|attack)\b",

    r"\b(i want to|i will|i am going to|i'm going to)\s+"
    r"(kill|murder|hurt|attack)\s+(my|the|a)\s+"
    r"(teacher|classmate|friend|student|colleague|person|boss)\b",

    r"\b(i am going to|i'm going to|i will)\s+"
    r"(beat up|physically harm|assault)\s+(my|the|a)\s+"
    r"(teacher|classmate|friend|student|colleague|person|boss)\b",

    r"\b(shall i|should i|can i|could i|how can i|how do i|help me|"
    r"tell me how to)\b.{0,50}\b(murder|kill|shoot|stab|attack)\b",
]


# --------------------------------------------------
# 4. SUICIDE AND SELF-HARM
# --------------------------------------------------

SELF_HARM_PATTERNS = [
    r"\b(i want to|i will|i am going to|i'm going to)\s+"
    r"(kill myself|end my life|commit suicide|hurt myself)\b",

    r"\b(i want to die|i wish i were dead|i don't want to live anymore)\b",

    r"\b(i am going to|i'm going to|i will)\s+"
    r"(self.harm|harm myself)\b",
]


# --------------------------------------------------
# 5. ROBBERY, THEFT, AND BREAK-IN REQUESTS
# --------------------------------------------------

CRIME_INTENT_PATTERNS = [
    r"\b(how\s+(can|do|to)|tell me how to|teach me how to|"
    r"help me|steps to|instructions to|plan to|ways to)\b"
    r".{0,100}\b(rob|robbery|steal|stealing|theft|burglarize|"
    r"burglary|loot|snatch|shoplift)\b",

    r"\b(how\s+(can|do|to)|tell me how to|teach me how to|"
    r"help me|steps to|instructions to|plan to|ways to)\b"
    r".{0,100}\b(rob|robbery|steal|burglarize|break into)\b"
    r".{0,60}\b(bank|store|shop|house|home|building|atm)\b",

    r"\b(how\s+(can|do|to)|tell me how to|teach me how to|"
    r"help me|steps to|instructions to|plan to|ways to)\b"
    r".{0,100}\b(bank robbery|rob a bank|rob a store|"
    r"rob a shop|steal money|commit robbery|commit theft)\b",

    r"\b(how\s+to|how\s+can\s+i|help me|teach me|"
    r"tell me how to|ways to|plan to)\b.{0,100}\b"
    r"(steal|rob|take|snatch|loot|burglarize)\b.{0,100}\b"
    r"(my friend|my friends|my friend's|friends|"
    r"someone else's|another person's|their|his|her)\b",

    r"\b(rob|steal|take|snatch|loot)\b.{0,80}\b"
    r"(my friend|my friend's|my friends|friends|"
    r"someone else's|another person's|their|his|her)\b.{0,80}\b"
    r"(things|belongings|money|property|possessions|items)\b",

    r"\b(robbery|stealing|theft|rob|steal)\b.{0,80}\b"
    r"(my friend|my friend's|my friends|friends|"
    r"someone else's|another person's)\b.{0,80}\b"
    r"(things|belongings|money|property|possessions|items)\b",

    r"\b(how\s+(can|do|to)|tell me how to|help me|ways to)\b"
    r".{0,100}\b(get away with|avoid getting caught|evade police|"
    r"escape the police)\b"
    r".{0,60}\b(robbery|rob|steal|theft|burglary|crime)\b",

    r"\b(help me|teach me|tell me how to|give me instructions to|"
    r"plan how to)\b.{0,100}\b(steal|rob|burglarize|break into)\b"
    r".{0,60}\b(money|bank|shop|store|house|home|car|property)\b",
]


# --------------------------------------------------
# 6. BASIC SENSITIVE-DATA DETECTION
# --------------------------------------------------

SENSITIVE_DATA_PATTERNS = [
    r"\b\d{12}\b",
    r"\b\d{16}\b",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
]


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def matches_any(patterns, message):
    """Return True when one or more security patterns match."""
    return any(
        re.search(pattern, message, re.IGNORECASE)
        for pattern in patterns
    )


def normalize(text):
    """Remove zero-width characters and collapse extra spaces."""
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)
    return re.sub(r"\s+", " ", text).strip()


# --------------------------------------------------
# INPUT SECURITY CHECK
# --------------------------------------------------

def inspect_message(message):
    """Inspect the user's message before sending it to the AI."""

    if not isinstance(message, str) or not message.strip():
        return {
            "action": "BLOCK",
            "reason": "The message is empty or invalid."
        }

    text = normalize(message)

    # Start background retraining if you changed the CSV.
    retrain_if_needed()

    # Step A: Your own sentences.
    custom = custom_lookup(text)

    if custom == "malicious":
        return {
            "action": "BLOCK",
            "reason": "The message matches a sentence you added as malicious in custom_prompts.csv."
        }

    # Step B: Hard rules. These always apply, even to "safe" sentences.
    if matches_any(INJECTION_PATTERNS, text):
        return {
            "action": "BLOCK",
            "reason": "The message attempts to bypass security instructions or expose hidden system information."
        }

    if matches_any(VIOLENCE_PATTERNS, text):
        return {
            "action": "BLOCK",
            "reason": "The message contains a possible direct threat of violence or a request for help with violence."
        }

    if matches_any(CRIME_INTENT_PATTERNS, text):
        return {
            "action": "BLOCK",
            "reason": "The message requests assistance with robbery, theft, burglary, or evading law enforcement."
        }

    if matches_any(SELF_HARM_PATTERNS, text):
        return {
            "action": "QUARANTINE",
            "reason": "The message may indicate suicidal intent or self-harm and needs a supportive response."
        }

    if matches_any(PRIVATE_REQUEST_PATTERNS, text):
        return {
            "action": "BLOCK",
            "reason": "The request seeks private personal or financial information or credentials."
        }

    has_third_party = matches_any(THIRD_PARTY_PATTERNS, text)
    has_private_data = matches_any(PRIVATE_DATA_PATTERNS, text)
    has_obtain_action = matches_any(OBTAIN_PATTERNS, text)

    if has_third_party and has_private_data and has_obtain_action:
        return {
            "action": "BLOCK",
            "reason": "The request may expose another person's private information."
        }

    # Step C: A sentence you marked safe overrides the softer checks below.
    if custom == "safe":
        return {
            "action": "ALLOW",
            "reason": "The message matches a sentence you added as safe in custom_prompts.csv."
        }

    # Step D: Softer checks.
    if has_private_data and has_obtain_action:
        return {
            "action": "QUARANTINE",
            "reason": "The request may involve sensitive financial or credential information."
        }

    if matches_any(SENSITIVE_DATA_PATTERNS, text):
        return {
            "action": "QUARANTINE",
            "reason": "The message may contain a personal identifier, email address, or other sensitive data."
        }

    # Step E: Trained classifier as a second opinion.
    score = ml_malicious_score(text)

    if score is not None:
        if score >= 0.85:
            return {
                "action": "BLOCK",
                "reason": f"The trained classifier flagged this message as likely malicious ({score:.0%})."
            }
        if score >= 0.60:
            return {
                "action": "QUARANTINE",
                "reason": f"The trained classifier found this message suspicious ({score:.0%})."
            }

    return {
        "action": "ALLOW",
        "reason": "No matching security rule was found."
    }


# --------------------------------------------------
# OUTPUT SECURITY CHECK
# --------------------------------------------------

def inspect_response(response):
    """Inspect an AI response for basic sensitive-data patterns."""

    if not isinstance(response, str):
        return {
            "action": "QUARANTINE",
            "reason": "The AI response has an unexpected format.",
            "response": "[Response hidden because the output format was invalid.]"
        }

    if matches_any(SENSITIVE_DATA_PATTERNS, response):
        return {
            "action": "QUARANTINE",
            "reason": "The response may contain sensitive information.",
            "response": "[Response hidden because a sensitive-data pattern was detected.]"
        }

    return {
        "action": "ALLOW",
        "reason": "No matching sensitive-data rule was found.",
        "response": response
    }