#!/usr/bin/env python3
import sqlite3
import json
import os
import re
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'teams_scanner.db')


def get_db_path() -> str:
    return DATABASE_PATH


@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                user_email TEXT,
                tenant_id TEXT,
                conversations_scanned INTEGER DEFAULT 0,
                messages_scanned INTEGER DEFAULT 0,
                secrets_found INTEGER DEFAULT 0,
                status TEXT DEFAULT 'in_progress',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                secret_type TEXT NOT NULL,
                raw_value TEXT,
                redacted_value TEXT NOT NULL,
                secret_hash TEXT,
                confidence REAL,
                entropy REAL,
                sender TEXT,
                timestamp TEXT,
                context_before TEXT,
                context_after TEXT,
                message_id TEXT,
                conversation_id TEXT,
                conversation_name TEXT,
                message_content TEXT,
                extra_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                scan_id INTEGER,
                name TEXT,
                type TEXT,
                messages_link TEXT,
                last_message_time TEXT,
                messages_count INTEGER DEFAULT 0,
                scanned INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT,
                conversation_id TEXT,
                scan_id INTEGER,
                sender TEXT,
                content TEXT,
                timestamp TEXT,
                is_from_me INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, conversation_id, scan_id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_secrets_scan ON secrets(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_secrets_conv ON secrets(conversation_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, scan_id)')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id TEXT PRIMARY KEY,
                scan_id INTEGER,
                subject TEXT,
                sender TEXT,
                sender_name TEXT,
                recipients TEXT,
                date TEXT,
                preview TEXT,
                body_content TEXT,
                body_type TEXT,
                has_attachments INTEGER DEFAULT 0,
                web_link TEXT,
                importance TEXT,
                is_read INTEGER DEFAULT 0,
                secrets_found INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT,
                scan_id INTEGER,
                attachment_id TEXT,
                name TEXT,
                content_type TEXT,
                size INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT,
                drive_id TEXT,
                scan_id INTEGER,
                name TEXT,
                size INTEGER,
                size_formatted TEXT,
                web_url TEXT,
                created_date TEXT,
                modified_date TEXT,
                preview TEXT,
                mime_type TEXT,
                parent_path TEXT,
                source TEXT,
                secrets_found INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id, drive_id, scan_id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_emails_scan ON emails(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_scan ON files(scan_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attachments_email ON email_attachments(email_id)')
        
        conn.commit()


def create_scan(user_email: str = None, tenant_id: str = None) -> int:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scans (scan_time, user_email, tenant_id, status)
            VALUES (?, ?, ?, 'in_progress')
        ''', (datetime.now().isoformat(), user_email, tenant_id))
        return cursor.lastrowid


def update_scan(scan_id: int, **kwargs):
    allowed_fields = ['conversations_scanned', 'messages_scanned', 'secrets_found', 'status']
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    
    if not updates:
        return
    
    set_clause = ', '.join(f'{k} = ?' for k in updates.keys())
    values = list(updates.values()) + [scan_id]
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f'UPDATE scans SET {set_clause} WHERE id = ?', values)


def get_scan(scan_id: int) -> Optional[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_latest_scan() -> Optional[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_scans(limit: int = 50) -> List[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
        return [dict(row) for row in cursor.fetchall()]


def is_similar_secret(val1: str, val2: str, threshold: float = 0.85) -> bool:
    if not val1 or not val2:
        return False
    if val1 == val2:
        return True
    if val1 in val2 or val2 in val1:
        return True
    shorter = min(len(val1), len(val2))
    if shorter < 10:
        return False
    match_len = int(shorter * threshold)
    if val1[:match_len] == val2[:match_len]:
        return True
    return False


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def get_secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def save_secret(scan_id: int, secret_data: Dict) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        
        raw_value = secret_data.get('raw_value', '')
        secret_hash = hash_secret(raw_value)
        new_confidence = secret_data.get('confidence', 0)
        
        cursor.execute('''
            SELECT id, confidence, secret_hash FROM secrets 
            WHERE scan_id = ? AND secret_hash = ?
        ''', (scan_id, secret_hash))
        
        existing = cursor.fetchone()
        if existing:
            if new_confidence > existing['confidence']:
                cursor.execute('''
                    UPDATE secrets SET 
                        secret_type = ?, confidence = ?, entropy = ?
                    WHERE id = ?
                ''', (
                    secret_data.get('type', ''),
                    new_confidence,
                    secret_data.get('entropy', 0),
                    existing['id']
                ))
                return True
            return False
        
        cursor.execute('''
            SELECT id, confidence, secret_hash FROM secrets 
            WHERE scan_id = ?
        ''', (scan_id,))
        
        for row in cursor.fetchall():
            if is_similar_secret(secret_hash, row['secret_hash']):
                if new_confidence > row['confidence']:
                    cursor.execute('''
                        UPDATE secrets SET 
                            secret_type = ?, raw_value = ?, redacted_value = ?,
                            secret_hash = ?, confidence = ?, entropy = ?
                        WHERE id = ?
                    ''', (
                        secret_data.get('type', ''),
                        raw_value,
                        secret_data.get('redacted_value', ''),
                        secret_hash,
                        new_confidence,
                        secret_data.get('entropy', 0),
                        row['id']
                    ))
                    return True
                return False
        
        cursor.execute('''
            INSERT INTO secrets (
                scan_id, secret_type, raw_value, redacted_value, secret_hash, confidence, entropy,
                sender, timestamp, context_before, context_after, message_id,
                conversation_id, conversation_name, message_content, extra_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            secret_data.get('type', ''),
            raw_value,
            secret_data.get('redacted_value', ''),
            secret_hash,
            secret_data.get('confidence', 0),
            secret_data.get('entropy', 0),
            secret_data.get('sender', ''),
            secret_data.get('timestamp', ''),
            secret_data.get('context_before', ''),
            secret_data.get('context_after', ''),
            secret_data.get('message_id', ''),
            secret_data.get('conversation_id', ''),
            secret_data.get('conversation_name', ''),
            secret_data.get('message_content', ''),
            json.dumps(secret_data.get('extra_data', {}))
        ))
        return True


def get_secrets(scan_id: int = None, limit: int = 500) -> List[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        if scan_id:
            cursor.execute('''
                SELECT * FROM secrets WHERE scan_id = ? ORDER BY id DESC LIMIT ?
            ''', (scan_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM secrets ORDER BY id DESC LIMIT ?
            ''', (limit,))
        
        results = []
        for row in cursor.fetchall():
            secret = dict(row)
            secret['extra_data'] = json.loads(secret.get('extra_data') or '{}')
            results.append(secret)
        return results


def save_conversation(scan_id: int, conv_data: Dict):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO conversations (
                id, scan_id, name, type, messages_link, last_message_time, messages_count, scanned
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            conv_data.get('id', ''),
            scan_id,
            conv_data.get('name', ''),
            conv_data.get('type', ''),
            conv_data.get('messages_link', ''),
            conv_data.get('last_message_time', ''),
            conv_data.get('messages_count', 0),
            conv_data.get('scanned', 0)
        ))


def get_conversations(scan_id: int) -> List[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM conversations WHERE scan_id = ? ORDER BY last_message_time DESC
        ''', (scan_id,))
        return [dict(row) for row in cursor.fetchall()]


def mark_conversation_scanned(scan_id: int, conv_id: str, messages_count: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE conversations SET scanned = 1, messages_count = ?
            WHERE scan_id = ? AND id = ?
        ''', (messages_count, scan_id, conv_id))


def is_user_message(msg: Dict) -> bool:
    content = msg.get('content', '') or ''
    sender = msg.get('imdisplayname', '') or msg.get('from', '') or ''
    msg_type = msg.get('messagetype', '') or ''
    
    if not content.strip():
        return False
    
    system_types = [
        'ThreadActivity/AddMember', 'ThreadActivity/DeleteMember',
        'ThreadActivity/TopicUpdate', 'ThreadActivity/HistoryDisclosedUpdate',
        'Event/Call', 'ThreadActivity/MemberJoined', 'ThreadActivity/MemberLeft',
        'RichText/Media_CallRecording', 'RichText/Media_Card'
    ]
    if msg_type in system_types:
        return False
    
    system_patterns = [
        'https://emea.ng.msg.teams.microsoft.com',
        'https://teams.microsoft.com',
        '8:orgid:',
        '8:teamsvisitor:',
        '19:meeting_',
        '@thread.v2',
        '@unq.gbl.spaces',
        '"eventtime"',
        '"initiator"',
        '"members"',
    ]
    for pattern in system_patterns:
        if pattern in content:
            return False
    
    if not sender or sender.startswith('8:') or sender.startswith('orgid:'):
        return False
    
    if re.match(r'^[\d:a-f\-]+$', content.replace('orgid:', '').replace('8:', ''), re.IGNORECASE):
        return False
    
    return True


def save_messages(scan_id: int, conversation_id: str, messages: List[Dict]):
    with get_db() as conn:
        cursor = conn.cursor()
        for msg in messages:
            if not is_user_message(msg):
                continue
            
            cursor.execute('''
                INSERT OR REPLACE INTO messages (
                    id, conversation_id, scan_id, sender, content, timestamp, is_from_me
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                msg.get('id', msg.get('clientmessageid', '')),
                conversation_id,
                scan_id,
                msg.get('imdisplayname', msg.get('from', '')),
                msg.get('content', ''),
                msg.get('composetime', msg.get('originalarrivaltime', '')),
                1 if msg.get('isFromMe') else 0
            ))


def get_message_context(scan_id: int, conversation_id: str, message_id: str, context_size: int = 5) -> Dict:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM messages 
            WHERE scan_id = ? AND conversation_id = ?
            ORDER BY timestamp ASC
        ''', (scan_id, conversation_id))
        
        messages = [dict(row) for row in cursor.fetchall()]
        target_idx = None
        for idx, msg in enumerate(messages):
            if msg['id'] == message_id:
                target_idx = idx
                break
        
        if target_idx is None:
            return {'messages': [], 'target_index': -1}
        
        start_idx = max(0, target_idx - context_size)
        end_idx = min(len(messages), target_idx + context_size + 1)
        
        context_messages = messages[start_idx:end_idx]
        cursor.execute('SELECT name FROM conversations WHERE id = ? AND scan_id = ?', 
                      (conversation_id, scan_id))
        conv_row = cursor.fetchone()
        conv_name = conv_row['name'] if conv_row else 'Unknown'
        
        return {
            'conversation_name': conv_name,
            'conversation_id': conversation_id,
            'target_message_id': message_id,
            'target_index': target_idx - start_idx,
            'messages': [
                {
                    'id': m['id'],
                    'sender': m['sender'],
                    'content': m['content'],
                    'timestamp': m['timestamp'],
                    'is_from_me': bool(m['is_from_me']),
                    'is_target': m['id'] == message_id
                }
                for m in context_messages
            ]
        }


def save_email(scan_id: int, email_data: Dict) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO emails (
                id, scan_id, subject, sender, sender_name, recipients, date,
                preview, body_content, body_type, has_attachments, web_link,
                importance, is_read, secrets_found
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            email_data.get('id', ''),
            scan_id,
            email_data.get('subject', ''),
            email_data.get('sender', ''),
            email_data.get('sender_name', ''),
            json.dumps(email_data.get('recipients', [])),
            email_data.get('date', ''),
            email_data.get('preview', ''),
            email_data.get('body_content', ''),
            email_data.get('body_type', ''),
            1 if email_data.get('has_attachments') else 0,
            email_data.get('web_link', ''),
            email_data.get('importance', 'normal'),
            1 if email_data.get('is_read') else 0,
            email_data.get('secrets_found', 0)
        ))
        return True


def save_email_attachment(scan_id: int, email_id: str, attachment_data: Dict):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO email_attachments (
                email_id, scan_id, attachment_id, name, content_type, size
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            email_id,
            scan_id,
            attachment_data.get('id', ''),
            attachment_data.get('name', ''),
            attachment_data.get('contentType', ''),
            attachment_data.get('size', 0)
        ))


def get_emails(scan_id: int, limit: int = 500) -> List[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM emails WHERE scan_id = ? ORDER BY date DESC LIMIT ?
        ''', (scan_id, limit))
        
        results = []
        for row in cursor.fetchall():
            email = dict(row)
            email['recipients'] = json.loads(email.get('recipients') or '[]')
            email['has_attachments'] = bool(email.get('has_attachments'))
            email['is_read'] = bool(email.get('is_read'))
            results.append(email)
        return results


def get_email(scan_id: int, email_id: str) -> Optional[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM emails WHERE scan_id = ? AND id = ?', (scan_id, email_id))
        row = cursor.fetchone()
        if row:
            email = dict(row)
            email['recipients'] = json.loads(email.get('recipients') or '[]')
            email['has_attachments'] = bool(email.get('has_attachments'))
            email['is_read'] = bool(email.get('is_read'))
            return email
        return None


def get_email_attachments(scan_id: int, email_id: str) -> List[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM email_attachments WHERE scan_id = ? AND email_id = ?
        ''', (scan_id, email_id))
        return [dict(row) for row in cursor.fetchall()]


def save_file(scan_id: int, file_data: Dict, source: str = "search") -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO files (
                id, drive_id, scan_id, name, size, size_formatted, web_url,
                created_date, modified_date, preview, mime_type, parent_path,
                source, secrets_found
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_data.get('id', ''),
            file_data.get('drive_id', ''),
            scan_id,
            file_data.get('name', ''),
            file_data.get('size', 0),
            file_data.get('size_formatted', ''),
            file_data.get('web_url', ''),
            file_data.get('created_date', ''),
            file_data.get('modified_date', ''),
            file_data.get('preview', ''),
            file_data.get('mime_type', ''),
            file_data.get('parent_path', ''),
            source,
            file_data.get('secrets_found', 0)
        ))
        return True


def get_files(scan_id: int, source: str = None, limit: int = 500) -> List[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        if source:
            cursor.execute('''
                SELECT * FROM files WHERE scan_id = ? AND source = ? 
                ORDER BY modified_date DESC LIMIT ?
            ''', (scan_id, source, limit))
        else:
            cursor.execute('''
                SELECT * FROM files WHERE scan_id = ? ORDER BY modified_date DESC LIMIT ?
            ''', (scan_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def get_file(scan_id: int, drive_id: str, item_id: str) -> Optional[Dict]:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM files WHERE scan_id = ? AND drive_id = ? AND id = ?
        ''', (scan_id, drive_id, item_id))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_scan_counts(scan_id: int, emails_scanned: int = 0, files_scanned: int = 0):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE scans SET 
                messages_scanned = messages_scanned + ?,
                conversations_scanned = conversations_scanned + ?
            WHERE id = ?
        ''', (emails_scanned, files_scanned, scan_id))


def delete_scan(scan_id: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM email_attachments WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM emails WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM files WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM messages WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM secrets WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM conversations WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))


def get_stats() -> Dict:
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) as count FROM scans')
        total_scans = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) as count FROM secrets')
        total_secrets = cursor.fetchone()['count']
        
        cursor.execute('SELECT SUM(messages_scanned) as count FROM scans')
        row = cursor.fetchone()
        total_messages = row['count'] or 0
        
        return {
            'total_scans': total_scans,
            'total_secrets': total_secrets,
            'total_messages': total_messages
        }


def delete_secret(secret_id: int):
    """Delete a single secret by ID."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM secrets WHERE id = ?', (secret_id,))


def clear_secrets(scan_id: int):
    """Delete all secrets for a scan."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM secrets WHERE scan_id = ?', (scan_id,))


def delete_scan(scan_id: int):
    """Delete a scan and all its related data."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM secrets WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM messages WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM conversations WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM emails WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM files WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))


init_db()
