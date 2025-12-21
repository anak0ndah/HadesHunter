#!/usr/bin/env python3
import re
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import html


class SecretType(Enum):
    AWS_ACCESS_KEY = "AWS Access Key"
    AWS_SECRET_KEY = "AWS Secret Key"
    AZURE_CLIENT_SECRET = "Azure Client Secret"
    AZURE_CONNECTION_STRING = "Azure Connection String"
    GITHUB_TOKEN = "GitHub Token"
    GITHUB_PAT = "GitHub Personal Access Token"
    SLACK_TOKEN = "Slack Token"
    SLACK_WEBHOOK = "Slack Webhook"
    GOOGLE_API_KEY = "Google API Key"
    GOOGLE_OAUTH = "Google OAuth Token"
    PRIVATE_KEY = "Private Key"
    JWT_TOKEN = "JWT Token"
    GENERIC_API_KEY = "Generic API Key"
    GENERIC_SECRET = "Generic Secret"
    PASSWORD_PATTERN = "Password Pattern"
    CREDENTIAL_EXCHANGE = "Credential Exchange"
    CONNECTION_STRING = "Connection String"
    BEARER_TOKEN = "Bearer Token"
    BASIC_AUTH = "Basic Auth"
    SSH_KEY = "SSH Key"
    DATABASE_URL = "Database URL"
    WEBHOOK_URL = "Webhook URL"
    DISCORD_TOKEN = "Discord Token"
    STRIPE_KEY = "Stripe API Key"
    SENDGRID_KEY = "SendGrid API Key"
    TWILIO_KEY = "Twilio API Key"
    OPENAI_KEY = "OpenAI API Key"


@dataclass
class SecretMatch:
    secret_type: SecretType
    raw_value: str
    redacted_value: str
    confidence: float
    entropy: float
    context_before: str
    context_after: str
    message_id: str
    conversation_id: str
    sender: str
    timestamp: str
    message_content: str
    verified: bool = False
    extra_data: Dict = field(default_factory=dict)


class SecretDetector:
    MIN_ENTROPY_HEX = 3.0
    MIN_ENTROPY_BASE64 = 4.0
    MIN_ENTROPY_GENERIC = 3.5
    
    KEYWORDS = [
        'password', 'passwd', 'pwd', 'pass', 'secret', 'token', 'api_key', 
        'apikey', 'api-key', 'auth', 'credential', 'cred', 'key', 'private',
        'access_token', 'refresh_token', 'bearer', 'authorization',
        'connection_string', 'conn_str', 'database_url', 'db_url',
        'client_secret', 'client_id', 'tenant', 'subscription',
        'mot de passe', 'mdp', 'identifiant', 'login', 'compte'
    ]
    
    PATTERNS: Dict[SecretType, List[Tuple[str, float]]] = {
        SecretType.AWS_ACCESS_KEY: [
            (r'\b((?:AKIA|ABIA|ACCA)[A-Z0-9]{16})\b', 0.95),
        ],
        SecretType.AWS_SECRET_KEY: [
            (r'(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 0.9),
        ],
        SecretType.AZURE_CLIENT_SECRET: [
            (r'(?i)(?:client[_-]?secret|azure[_-]?secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9~._-]{34,40})["\']?', 0.85),
            (r'(?i)(?:AZURE_CLIENT_SECRET|ClientSecret)\s*[:=]\s*["\']?([A-Za-z0-9~._-]{34,40})["\']?', 0.9),
        ],
        SecretType.AZURE_CONNECTION_STRING: [
            (r'(?i)(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};EndpointSuffix=[^;\s]+)', 0.95),
            (r'(?i)(Server=tcp:[^;]+;Database=[^;]+;User ID=[^;]+;Password=[^;]+;)', 0.9),
        ],
        SecretType.GITHUB_TOKEN: [
            (r'\b(ghp_[A-Za-z0-9]{36})\b', 0.95),
            (r'\b(gho_[A-Za-z0-9]{36})\b', 0.95),
            (r'\b(ghu_[A-Za-z0-9]{36})\b', 0.95),
            (r'\b(ghs_[A-Za-z0-9]{36})\b', 0.95),
            (r'\b(ghr_[A-Za-z0-9]{36})\b', 0.95),
        ],
        SecretType.GITHUB_PAT: [
            (r'(?i)(?:github|gh)[_-]?(?:token|pat|api[_-]?key)["\']?\s*[:=]\s*["\']?([a-f0-9]{40})["\']?', 0.85),
        ],
        SecretType.SLACK_TOKEN: [
            (r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b', 0.95),
        ],
        SecretType.SLACK_WEBHOOK: [
            (r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)', 0.95),
        ],
        SecretType.GOOGLE_API_KEY: [
            (r'\b(AIza[A-Za-z0-9_-]{35})\b', 0.95),
        ],
        SecretType.PRIVATE_KEY: [
            (r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)', 0.99),
        ],
        SecretType.SSH_KEY: [
            (r'(ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{50,})', 0.9),
        ],
        SecretType.JWT_TOKEN: [
            (r'\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b', 0.9),
        ],
        SecretType.BEARER_TOKEN: [
            (r'(?i)bearer\s+([A-Za-z0-9_-]{20,})', 0.8),
        ],
        SecretType.BASIC_AUTH: [
            (r'(?i)basic\s+([A-Za-z0-9+/=]{20,})', 0.8),
        ],
        SecretType.DATABASE_URL: [
            (r'(?i)((?:postgres|mysql|mongodb|redis|mssql)(?:ql)?://[^\s<>"\']+:[^\s<>"\']+@[^\s<>"\']+)', 0.9),
        ],
        SecretType.WEBHOOK_URL: [
            (r'(https://(?:discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)', 0.95),
            (r'(https://outlook\.office\.com/webhook/[A-Za-z0-9-]+)', 0.9),
        ],
        SecretType.DISCORD_TOKEN: [
            (r'\b([MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b', 0.9),
        ],
        SecretType.STRIPE_KEY: [
            (r'\b(sk_live_[A-Za-z0-9]{24,})\b', 0.95),
            (r'\b(sk_test_[A-Za-z0-9]{24,})\b', 0.9),
            (r'\b(rk_live_[A-Za-z0-9]{24,})\b', 0.95),
        ],
        SecretType.SENDGRID_KEY: [
            (r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b', 0.95),
        ],
        SecretType.TWILIO_KEY: [
            (r'\b(SK[a-f0-9]{32})\b', 0.9),
        ],
        SecretType.OPENAI_KEY: [
            (r'\b(sk-[A-Za-z0-9]{48})\b', 0.95),
        ],
        SecretType.GENERIC_API_KEY: [
            (r'(?i)(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,64})["\']?', 0.7),
        ],
        SecretType.CONNECTION_STRING: [
            (r'(?i)(?:connection[_-]?string|conn[_-]?str)["\']?\s*[:=]\s*["\']?([^\s"\']{20,})["\']?', 0.75),
        ],
    }
    
    CONVERSATION_PATTERNS: Dict[SecretType, List[Tuple[str, float]]] = {
        SecretType.PASSWORD_PATTERN: [
            # English patterns
            (r'(?i)(?:the\s+)?password\s+is\s*:?\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:here\s+is|here\'s)\s+(?:the\s+)?(?:password|pwd|pass)\s*[:=]?\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:my|your|the)\s+password\s*(?:is\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # French patterns
            (r'(?i)(?:le\s+)?mot\s+de\s+passe\s*(?:est\s*:?|:|\=)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:voici|c\'est)\s+(?:le\s+)?(?:mot\s+de\s+passe|mdp|password)\s*[:=]?\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:mon|ton|le)\s+(?:mdp|pwd|pass)\s*(?:est\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.8),
            # Spanish patterns
            (r'(?i)(?:la\s+)?contrase[ñn]a\s*(?:es\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:mi|tu|la)\s+(?:clave|contrase[ñn]a)\s*(?:es\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # German patterns
            (r'(?i)(?:das\s+)?(?:passwort|kennwort)\s*(?:ist\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:mein|dein)\s+(?:passwort|kennwort)\s*(?:ist\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # Polish patterns
            (r'(?i)has[łl]o\s*(?:to\s*:?|:|\=)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:moje|twoje)\s+has[łl]o\s*(?:to\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # Portuguese patterns
            (r'(?i)(?:a\s+)?senha\s*(?:[ée]\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            (r'(?i)(?:minha|sua)\s+senha\s*(?:[ée]\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # Italian patterns
            (r'(?i)(?:la\s+)?password\s*(?:[èe]\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # Dutch patterns
            (r'(?i)(?:het\s+)?wachtwoord\s*(?:is\s*:?|:)\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.85),
            # Generic key=value patterns
            (r'(?i)(?:password|passwd|pwd|mdp|haslo|senha|contrasena)\s*[:=]\s*["\']?([^\s"\'<>]{4,64})["\']?', 0.75),
            (r'(?i)(?:pass|pwd)\s*[:=]\s*["\']?([^\s"\'<>]{6,64})["\']?', 0.7),
        ],
        SecretType.CREDENTIAL_EXCHANGE: [
            (r'(?i)(?:user(?:name)?|login|identifiant|usuario|benutzer|uzytkownik)\s*[:=]\s*["\']?([^\s"\'<>]+)["\']?\s*[/\-,;]\s*(?:password|passwd|pwd|mdp|haslo|senha|contrasena)\s*[:=]\s*["\']?([^\s"\'<>]+)["\']?', 0.9),
            (r'(?i)(?:login|user)\s*[:=]\s*([^\s,;]+)\s*[,;]\s*(?:pass|pwd)\s*[:=]\s*([^\s,;]+)', 0.85),
            (r'(?i)(?:compte|account|konto|cuenta)\s*[:=]?\s*([^\s,;]+)\s*[,;/\-]?\s*(?:mot de passe|password|mdp|haslo|senha)\s*[:=]?\s*([^\s,;]+)', 0.85),
            # Email:password - require explicit colon separator (not dash which is valid in domains)
            (r'(?i)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*:\s*([^\s<>"\']{6,})', 0.75),
        ],
        SecretType.GENERIC_SECRET: [
            (r'(?i)(?:secret|password|passwd|pwd|mdp|haslo|senha)["\']?\s*[:=]\s*["\']?([^\s"\'<>]{6,64})["\']?', 0.65),
            (r'(?i)(?:cl[ée]|key|klucz|clave|chave)\s*[:=]\s*["\']?([^\s"\'<>]{8,64})["\']?', 0.6),
        ],
    }
    
    EXCLUDE_PATTERNS = [
        r'^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$',  # UUIDs
        r'^#[a-fA-F0-9]{6}$',  # Hex colors
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # IPs
        r'^v?\d+\.\d+\.\d+$',  # Versions
        r'^\d{4}[-/]\d{2}[-/]\d{2}$',  # Dates
        r'^(true|false|null|none|undefined)$',
        r'^[a-zA-Z]+$',  # Pure letters
        r'^\d+$',  # Pure numbers
        r'^(example|test|demo|sample|placeholder|xxx+|yyy+|zzz+)$',
    ]
    
    TEAMS_SYSTEM_PATTERNS = [
        r'https?://[^\s]*\.teams\.microsoft\.com',  # Teams URLs
        r'https?://[^\s]*\.skype\.com',  # Skype URLs
        r'https?://[^\s]*msg\.teams',  # Teams message URLs
        r'8:orgid:[a-f0-9-]+',  # Teams org IDs
        r'8:teamsvisitor:[a-f0-9]+',  # Teams visitor IDs
        r'19:meeting_[A-Za-z0-9-]+@thread',  # Meeting thread IDs
        r'19:[a-f0-9]+@thread\.v2',  # Thread IDs
        r'AAMkA[A-Za-z0-9+/=]+',  # Outlook calendar IDs
        r'"eventtime":\d+',  # Event JSON
        r'"initiator":"8:',  # System JSON
        r'"members":\[',  # Members JSON
        r'callEnded',  # Call metadata
        r'Scheduled\d{2}/\d{2}/\d{4}',  # Scheduled meetings
        r'api\.flightproxy',  # Flight proxy URLs
        r'conv\.skype\.com',  # Skype conv URLs
    ]
    
    COMMON_FALSE_POSITIVES = [
        'password', 'secret', 'token', 'apikey', 'api_key', 'changeme',
        'your_password', 'your_secret', 'your_token', 'your_api_key',
        'password123', 'admin', 'root', 'test', 'demo', 'example',
        'placeholder', 'redacted', 'hidden', 'masked', '********',
        'xxxxxxxx', 'yyyyyyyy', 'zzzzzzzz', 'undefined', 'null', 'none',
    ]
    
    def __init__(self):
        self.compiled_patterns: Dict[SecretType, List[Tuple[re.Pattern, float]]] = {}
        for secret_type, patterns in self.PATTERNS.items():
            self.compiled_patterns[secret_type] = [
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), confidence)
                for pattern, confidence in patterns
            ]
        
        self.compiled_conversation_patterns: Dict[SecretType, List[Tuple[re.Pattern, float]]] = {}
        for secret_type, patterns in self.CONVERSATION_PATTERNS.items():
            self.compiled_conversation_patterns[secret_type] = [
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), confidence)
                for pattern, confidence in patterns
            ]
        
        self.exclude_patterns = [re.compile(p, re.IGNORECASE) for p in self.EXCLUDE_PATTERNS]
    
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        char_count: Dict[str, int] = {}
        
        for char in data:
            char_count[char] = char_count.get(char, 0) + 1
        
        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def redact_secret(secret: str, show_chars: int = 4) -> str:
        if len(secret) <= show_chars * 2:
            return '*' * len(secret)
        return secret[:show_chars] + '*' * (len(secret) - show_chars * 2) + secret[-show_chars:]
    
    def is_false_positive(self, value: str) -> bool:
        value_lower = value.lower().strip()
        
        if value_lower in self.COMMON_FALSE_POSITIVES:
            return True
        
        for pattern in self.exclude_patterns:
            if pattern.fullmatch(value):
                return True
        
        if len(set(value_lower)) <= 2:
            return True
        
        # Filter out email addresses
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return True
        
        # Filter out values that look like email:password but email part is dominant
        if '@' in value and ':' in value:
            parts = value.split(':')
            if len(parts) == 2 and '@' in parts[0] and re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parts[0]):
                # Check if password part is too simple
                pwd = parts[1]
                if len(pwd) < 6 or pwd.isalpha() or pwd.isdigit():
                    return True
        
        # Filter out domain names
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value) and '@' not in value:
            return True
        
        # Filter out URLs without credentials
        if re.match(r'^https?://[a-zA-Z0-9.-]+', value) and ':' not in value.split('//')[1].split('/')[0]:
            return True
        
        return False
    
    def is_teams_system_message(self, text: str) -> bool:
        if not text:
            return True
        
        for pattern in self.TEAMS_SYSTEM_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        # Check if it looks like JSON metadata
        if text.strip().startswith('{') and ('eventtime' in text or 'initiator' in text or 'members' in text):
            return True
        
        # Check if it's mostly URLs or IDs (not conversational)
        url_count = len(re.findall(r'https?://[^\s]+', text))
        word_count = len(text.split())
        if word_count > 0 and url_count / word_count > 0.5:
            return True
        
        return False
    
    def has_keyword_nearby(self, text: str, match_start: int, radius: int = 50) -> bool:
        """Vérifie si un keyword est présent à proximité du match."""
        start = max(0, match_start - radius)
        end = min(len(text), match_start + radius)
        context = text[start:end].lower()
        
        return any(keyword in context for keyword in self.KEYWORDS)
    
    def clean_html(self, text: str) -> str:
        """Nettoie le HTML d'un message Teams."""
        if not text:
            return ""
        text = html.unescape(text)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def extract_user_content(self, text: str) -> str:
        """Extrait uniquement le contenu utilisateur d'un message Teams."""
        if not text:
            return ""
        
        clean = self.clean_html(text)
        
        # Remove Teams system URLs
        clean = re.sub(r'https?://[^\s]*(?:teams\.microsoft\.com|skype\.com|msg\.teams)[^\s]*', '', clean)
        
        # Remove Teams IDs
        clean = re.sub(r'8:(?:orgid|teamsvisitor):[a-f0-9-]+', '', clean)
        clean = re.sub(r'19:(?:meeting_)?[A-Za-z0-9_-]+@thread(?:\.v2)?', '', clean)
        
        # Remove calendar/meeting IDs
        clean = re.sub(r'AAMkA[A-Za-z0-9+/=]+', '', clean)
        
        # Remove JSON-like metadata
        clean = re.sub(r'\{[^}]*"(?:eventtime|initiator|members)"[^}]*\}', '', clean)
        
        # Remove call metadata patterns
        clean = re.sub(r'callEnded\s*\d{2}/\d{2}/\d{4}\s*\d{2}:\d{2}:\d{2}', '', clean)
        clean = re.sub(r'Scheduled\d{2}/\d{2}/\d{4}\s*\d{2}:\d{2}:\d{2}', '', clean)
        
        # Remove flight proxy URLs
        clean = re.sub(r'https?://api\.flightproxy[^\s]*', '', clean)
        
        # Clean up extra whitespace
        clean = re.sub(r'\s+', ' ', clean).strip()
        
        return clean
    
    def get_context(self, text: str, match_start: int, match_end: int, context_chars: int = 100) -> Tuple[str, str]:
        """Extrait le contexte avant et après un match."""
        before_start = max(0, match_start - context_chars)
        after_end = min(len(text), match_end + context_chars)
        
        context_before = text[before_start:match_start]
        context_after = text[match_end:after_end]
        
        return context_before.strip(), context_after.strip()
    
    def scan_text(self, text: str, message_id: str = "", conversation_id: str = "",
                  sender: str = "", timestamp: str = "") -> List[SecretMatch]:
        """Scanne un texte pour détecter des secrets."""
        results: List[SecretMatch] = []
        
        # Skip system messages entirely
        if self.is_teams_system_message(text):
            return results
        
        # Extract only user content
        clean_text = self.extract_user_content(text)
        
        if not clean_text or len(clean_text) < 5:
            return results
        
        seen_secrets = set()
        
        for secret_type, patterns in self.compiled_patterns.items():
            for pattern, base_confidence in patterns:
                for match in pattern.finditer(clean_text):
                    secret_value = match.group(1) if match.lastindex else match.group(0)
                    
                    if secret_value in seen_secrets:
                        continue
                    
                    if self.is_false_positive(secret_value):
                        continue
                    
                    entropy = self.calculate_shannon_entropy(secret_value)
                    
                    confidence = base_confidence
                    if entropy < self.MIN_ENTROPY_GENERIC:
                        confidence *= 0.6
                    elif entropy > 4.5:
                        confidence = min(1.0, confidence * 1.15)
                    
                    if self.has_keyword_nearby(clean_text, match.start()):
                        confidence = min(1.0, confidence * 1.1)
                    
                    if confidence < 0.5:
                        continue
                    
                    context_before, context_after = self.get_context(clean_text, match.start(), match.end())
                    
                    seen_secrets.add(secret_value)
                    results.append(SecretMatch(
                        secret_type=secret_type,
                        raw_value=secret_value,
                        redacted_value=self.redact_secret(secret_value),
                        confidence=round(confidence, 2),
                        entropy=round(entropy, 2),
                        context_before=context_before,
                        context_after=context_after,
                        message_id=message_id,
                        conversation_id=conversation_id,
                        sender=sender,
                        timestamp=timestamp,
                        message_content=clean_text,
                    ))
        
        for secret_type, patterns in self.compiled_conversation_patterns.items():
            for pattern, base_confidence in patterns:
                for match in pattern.finditer(clean_text):
                    if secret_type == SecretType.CREDENTIAL_EXCHANGE and match.lastindex and match.lastindex >= 2:
                        username = match.group(1)
                        password = match.group(2)
                        combined = f"{username}:{password}"
                        
                        if combined in seen_secrets:
                            continue
                        
                        if self.is_false_positive(password):
                            continue
                        
                        entropy = self.calculate_shannon_entropy(password)
                        confidence = base_confidence
                        
                        if entropy < 2.5:
                            confidence *= 0.5
                        
                        if confidence < 0.5:
                            continue
                        
                        context_before, context_after = self.get_context(clean_text, match.start(), match.end())
                        
                        seen_secrets.add(combined)
                        results.append(SecretMatch(
                            secret_type=secret_type,
                            raw_value=combined,
                            redacted_value=f"{username}:{self.redact_secret(password)}",
                            confidence=round(confidence, 2),
                            entropy=round(entropy, 2),
                            context_before=context_before,
                            context_after=context_after,
                            message_id=message_id,
                            conversation_id=conversation_id,
                            sender=sender,
                            timestamp=timestamp,
                            message_content=clean_text,
                            extra_data={"username": username, "password_redacted": self.redact_secret(password)},
                        ))
                    else:
                        secret_value = match.group(1) if match.lastindex else match.group(0)
                        
                        if secret_value in seen_secrets:
                            continue
                        
                        if self.is_false_positive(secret_value):
                            continue
                        
                        entropy = self.calculate_shannon_entropy(secret_value)
                        confidence = base_confidence
                        
                        if entropy < 2.5:
                            confidence *= 0.5
                        
                        if confidence < 0.5:
                            continue
                        
                        context_before, context_after = self.get_context(clean_text, match.start(), match.end())
                        
                        seen_secrets.add(secret_value)
                        results.append(SecretMatch(
                            secret_type=secret_type,
                            raw_value=secret_value,
                            redacted_value=self.redact_secret(secret_value),
                            confidence=round(confidence, 2),
                            entropy=round(entropy, 2),
                            context_before=context_before,
                            context_after=context_after,
                            message_id=message_id,
                            conversation_id=conversation_id,
                            sender=sender,
                            timestamp=timestamp,
                            message_content=clean_text,
                        ))
        
        return results
    
    def scan_messages(self, messages: List[Dict], conversation_id: str = "") -> List[SecretMatch]:
        """Scanne une liste de messages Teams."""
        all_results: List[SecretMatch] = []
        
        for msg in messages:
            content = msg.get('content', '')
            message_id = msg.get('id', msg.get('clientmessageid', ''))
            sender = msg.get('imdisplayname', msg.get('from', 'Unknown'))
            timestamp = msg.get('composetime', msg.get('originalarrivaltime', ''))
            
            results = self.scan_text(
                text=content,
                message_id=message_id,
                conversation_id=conversation_id,
                sender=sender,
                timestamp=timestamp
            )
            all_results.extend(results)
        
        return all_results
    
    def scan_email_text(self, text: str, message_id: str = "", conversation_id: str = "",
                        sender: str = "", timestamp: str = "") -> List[SecretMatch]:
        """Scanne un email pour détecter des secrets - sans filtrage Teams."""
        results: List[SecretMatch] = []
        
        if not text or len(text.strip()) < 5:
            return results
        
        # Clean HTML but don't filter as Teams system message
        clean_text = self.clean_html(text)
        
        if not clean_text or len(clean_text) < 5:
            return results
        
        seen_secrets = set()
        
        # Scan with all patterns
        for secret_type, patterns in self.compiled_patterns.items():
            for pattern, base_confidence in patterns:
                for match in pattern.finditer(clean_text):
                    secret_value = match.group(1) if match.lastindex else match.group(0)
                    
                    if secret_value in seen_secrets:
                        continue
                    
                    if self.is_false_positive(secret_value):
                        continue
                    
                    entropy = self.calculate_shannon_entropy(secret_value)
                    
                    confidence = base_confidence
                    if entropy < self.MIN_ENTROPY_GENERIC:
                        confidence *= 0.6
                    elif entropy > 4.5:
                        confidence = min(1.0, confidence * 1.15)
                    
                    if self.has_keyword_nearby(clean_text, match.start()):
                        confidence = min(1.0, confidence * 1.1)
                    
                    if confidence < 0.5:
                        continue
                    
                    context_before, context_after = self.get_context(clean_text, match.start(), match.end())
                    
                    seen_secrets.add(secret_value)
                    results.append(SecretMatch(
                        secret_type=secret_type,
                        raw_value=secret_value,
                        redacted_value=self.redact_secret(secret_value),
                        confidence=round(confidence, 2),
                        entropy=round(entropy, 2),
                        context_before=context_before,
                        context_after=context_after,
                        message_id=message_id,
                        conversation_id=conversation_id,
                        sender=sender,
                        timestamp=timestamp,
                        message_content=clean_text[:500],
                    ))
        
        # Also scan conversation patterns
        for secret_type, patterns in self.compiled_conversation_patterns.items():
            for pattern, base_confidence in patterns:
                for match in pattern.finditer(clean_text):
                    if secret_type == SecretType.CREDENTIAL_EXCHANGE and match.lastindex and match.lastindex >= 2:
                        username = match.group(1)
                        password = match.group(2)
                        combined = f"{username}:{password}"
                        
                        if combined in seen_secrets:
                            continue
                        
                        if self.is_false_positive(password):
                            continue
                        
                        entropy = self.calculate_shannon_entropy(password)
                        confidence = base_confidence
                        
                        if entropy < 2.5:
                            confidence *= 0.5
                        
                        if confidence < 0.5:
                            continue
                        
                        context_before, context_after = self.get_context(clean_text, match.start(), match.end())
                        
                        seen_secrets.add(combined)
                        results.append(SecretMatch(
                            secret_type=secret_type,
                            raw_value=combined,
                            redacted_value=f"{username}:{self.redact_secret(password)}",
                            confidence=round(confidence, 2),
                            entropy=round(entropy, 2),
                            context_before=context_before,
                            context_after=context_after,
                            message_id=message_id,
                            conversation_id=conversation_id,
                            sender=sender,
                            timestamp=timestamp,
                            message_content=clean_text[:500],
                        ))
                    else:
                        secret_value = match.group(1) if match.lastindex else match.group(0)
                        
                        if secret_value in seen_secrets:
                            continue
                        
                        if self.is_false_positive(secret_value):
                            continue
                        
                        entropy = self.calculate_shannon_entropy(secret_value)
                        confidence = base_confidence
                        
                        if entropy < 2.5:
                            confidence *= 0.5
                        
                        if confidence < 0.5:
                            continue
                        
                        context_before, context_after = self.get_context(clean_text, match.start(), match.end())
                        
                        seen_secrets.add(secret_value)
                        results.append(SecretMatch(
                            secret_type=secret_type,
                            raw_value=secret_value,
                            redacted_value=self.redact_secret(secret_value),
                            confidence=round(confidence, 2),
                            entropy=round(entropy, 2),
                            context_before=context_before,
                            context_after=context_after,
                            message_id=message_id,
                            conversation_id=conversation_id,
                            sender=sender,
                            timestamp=timestamp,
                            message_content=clean_text[:500],
                        ))
        
        return results


def get_detector() -> SecretDetector:
    """Factory function pour obtenir une instance du détecteur."""
    return SecretDetector()
