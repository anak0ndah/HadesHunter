#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session, send_file, Response, redirect
import json
import os
import io
from datetime import datetime
from typing import Dict, List, Any
import time

from secret_detector import SecretDetector, SecretMatch, get_detector
from teams_api import TeamsAPI, TeamsAPIError, refresh_to_access_token, get_tenant_id
from graph_api import GraphAPI, GraphAPIError, refresh_to_graph_token
import database as db

app = Flask(__name__)


def get_conversation_name(conv: Dict, resolve_members: bool = False) -> str:
    topic = conv.get("threadProperties", {}).get("topic")
    if topic and topic.strip():
        return topic.strip()
    
    space_topic = conv.get("threadProperties", {}).get("spaceThreadTopic")
    if space_topic and space_topic.strip():
        return space_topic.strip()
    
    if conv.get("_resolved_name"):
        return conv["_resolved_name"]
    
    conv_id = conv.get("id", "")
    if resolve_members and conv_id:
        try:
            member_name = teams_api.get_conversation_name_from_members(conv_id)
            if member_name:
                conv["_resolved_name"] = member_name
                return member_name
        except:
            pass
    
    last_msg = conv.get("lastMessage", {})
    sender_name = last_msg.get("imdisplayname", "")
    if sender_name and sender_name.strip():
        if not sender_name.startswith("8:") and not sender_name.startswith("orgid:"):
            return sender_name.strip()
    
    thread_type = conv.get("threadProperties", {}).get("threadType", "")
    
    if "meeting_" in conv_id:
        return "Meeting Chat"
    elif thread_type == "chat":
        return "Private Chat"
    elif thread_type == "topic":
        return "Group Chat"
    elif conv_id.startswith("19:") and "@thread" in conv_id:
        return "Teams Chat"
    
    return "Chat"


app.secret_key = os.urandom(24)

detector = get_detector()
teams_api = TeamsAPI()
graph_api = GraphAPI()

current_scan = {
    "id": None,
    "start_time": None,
    "user_email": None,
    "tenant_id": None
}

PAGE_SIZE = 20
DETECTORS_FILE = os.path.join(os.path.dirname(__file__), 'GraphRunner-main 2', 'default_detectors.json')

def load_detectors() -> List[Dict]:
    """Load secret detectors from GraphRunner's default_detectors.json"""
    try:
        if os.path.exists(DETECTORS_FILE):
            with open(DETECTORS_FILE, 'r') as f:
                data = json.load(f)
                return data.get('Detectors', [])
    except:
        pass
    return []


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/set_token", methods=["POST"])
def api_set_token():
    try:
        data = request.get_json() or request.form
        access_token = data.get("access_token", "").strip()
        refresh_token = data.get("refresh_token", "").strip()
        
        if refresh_token:
            return api_refresh_token_internal(refresh_token)
        
        if not access_token:
            return jsonify({"error": "No access token or refresh token provided"}), 400
        
        try:
            import jwt
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            resource = decoded.get("aud", "")
            tenant_id = decoded.get("tid", "")
            
            if "api.spaces.skype.com" not in resource:
                return jsonify({
                    "error": f"Token is for '{resource}', not Teams API. Please provide a refresh token to auto-convert.",
                    "needs_refresh_token": True,
                    "tenant_id": tenant_id
                }), 400
        except Exception:
            pass
        
        token_info = teams_api.set_access_token(access_token)
        session["token_configured"] = True
        session["user_email"] = token_info.get("user", "")
        session["tenant_id"] = token_info.get("tenant_id", "")
        
        return jsonify({
            "success": True,
            "token_info": token_info
        })
    except TeamsAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


def api_refresh_token_internal(refresh_token: str, tenant: str = None):
    try:
        if not tenant:
            tenant = "common"
        
        try:
            tenant_id = get_tenant_id(tenant) if "." in tenant else tenant
        except:
            tenant_id = tenant
        
        tokens = refresh_to_access_token(refresh_token, tenant_id)
        
        token_info = teams_api.set_access_token(tokens["access_token"])
        session["token_configured"] = True
        session["user_email"] = token_info.get("user", "")
        session["tenant_id"] = token_info.get("tenant_id", "")
        session["refresh_token"] = tokens.get("refresh_token", refresh_token)
        
        return jsonify({
            "success": True,
            "access_token": tokens["access_token"],
            "new_refresh_token": tokens.get("refresh_token", ""),
            "token_info": token_info,
            "message": "Token Teams généré automatiquement"
        })
    except TeamsAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/refresh_token", methods=["POST"])
def api_refresh_token():
    try:
        data = request.get_json() or request.form
        refresh_token = data.get("refresh_token", "").strip()
        tenant = data.get("tenant", "").strip()
        
        if not refresh_token:
            return jsonify({"error": "No refresh token provided"}), 400
        
        return api_refresh_token_internal(refresh_token, tenant)
    except TeamsAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_conversations", methods=["GET"])
def api_get_conversations():
    try:
        resolve_names = request.args.get("resolve_names", "true").lower() == "true"
        conversations = teams_api.get_conversations()
        
        filtered = []
        for conv in conversations:
            if conv.get("threadProperties", {}).get("threadType") == "streamofnotifications":
                continue
            
            conv_name = get_conversation_name(conv, resolve_members=resolve_names)
            
            filtered.append({
                "id": conv.get("id", ""),
                "name": conv_name,
                "type": conv.get("threadProperties", {}).get("threadType", "unknown"),
                "messages_link": conv.get("messages", ""),
                "last_message_time": conv.get("lastMessage", {}).get("originalarrivaltime", ""),
                "is_empty": conv.get("properties", {}).get("isemptyconversation") == "True"
            })
        
        return jsonify({
            "conversations": filtered,
            "total": len(filtered)
        })
    except TeamsAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/scan_conversation", methods=["POST"])
def api_scan_conversation():
    try:
        data = request.get_json() or request.form
        messages_link = data.get("messages_link", "").strip()
        conversation_id = data.get("conversation_id", "").strip()
        conversation_name = data.get("conversation_name", "Unknown")
        
        if not messages_link:
            return jsonify({"error": "No messages link provided"}), 400
        
        scan_id = current_scan.get("id")
        if not scan_id:
            scan_id = db.create_scan(
                user_email=session.get("user_email"),
                tenant_id=session.get("tenant_id")
            )
            current_scan["id"] = scan_id
            current_scan["start_time"] = time.time()
        
        messages = teams_api.get_conversation_messages(messages_link)
        db.save_messages(scan_id, conversation_id, messages)
        secrets = detector.scan_messages(messages, conversation_id)
        
        for s in secrets:
            db.save_secret(scan_id, {
                "type": s.secret_type.value,
                "raw_value": s.raw_value,
                "redacted_value": s.redacted_value,
                "confidence": s.confidence,
                "entropy": s.entropy,
                "sender": s.sender,
                "timestamp": s.timestamp,
                "context_before": s.context_before,
                "context_after": s.context_after,
                "message_id": s.message_id,
                "conversation_id": conversation_id,
                "conversation_name": conversation_name,
                "message_content": s.message_content,
                "extra_data": s.extra_data
            })
        
        return jsonify({
            "secrets_found": len(secrets),
            "messages_scanned": len(messages),
            "scan_id": scan_id
        })
    except TeamsAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/scan_all", methods=["POST"])
def api_scan_all():
    global current_scan
    
    try:
        data = request.get_json() or {}
        page = data.get("page", 0)
        
        if page == 0:
            scan_id = db.create_scan(
                user_email=session.get("user_email"),
                tenant_id=session.get("tenant_id")
            )
            current_scan = {
                "id": scan_id,
                "start_time": time.time(),
                "user_email": session.get("user_email"),
                "tenant_id": session.get("tenant_id")
            }
        else:
            scan_id = current_scan.get("id")
            if not scan_id:
                return jsonify({"error": "No active scan. Start from page 0."}), 400
        
        conversations = teams_api.get_conversations()
        valid_convs = []
        for conv in conversations:
            if conv.get("threadProperties", {}).get("threadType") == "streamofnotifications":
                continue
            if conv.get("properties", {}).get("isemptyconversation") == "True":
                continue
            valid_convs.append(conv)
        
        total_convs = len(valid_convs)
        total_pages = (total_convs + PAGE_SIZE - 1) // PAGE_SIZE
        start_idx = page * PAGE_SIZE
        end_idx = min(start_idx + PAGE_SIZE, total_convs)
        page_convs = valid_convs[start_idx:end_idx]
        
        total_messages = 0
        total_secrets = 0
        
        for conv in page_convs:
            conv_id = conv.get("id", "")
            conv_name = get_conversation_name(conv)
            messages_link = conv.get("messages", "")
            
            if not messages_link:
                continue
            
            try:
                messages = teams_api.get_conversation_messages(messages_link)
                total_messages += len(messages)
                db.save_messages(scan_id, conv_id, messages)
                db.save_conversation(scan_id, {
                    "id": conv_id,
                    "name": conv_name,
                    "type": conv.get("threadProperties", {}).get("threadType", ""),
                    "messages_link": messages_link,
                    "last_message_time": conv.get("lastMessage", {}).get("originalarrivaltime", ""),
                    "messages_count": len(messages),
                    "scanned": 1
                })
                
                secrets = detector.scan_messages(messages, conv_id)
                total_secrets += len(secrets)
                
                for s in secrets:
                    db.save_secret(scan_id, {
                        "type": s.secret_type.value,
                        "raw_value": s.raw_value,
                        "redacted_value": s.redacted_value,
                        "confidence": s.confidence,
                        "entropy": s.entropy,
                        "sender": s.sender,
                        "timestamp": s.timestamp,
                        "context_before": s.context_before,
                        "context_after": s.context_after,
                        "message_id": s.message_id,
                        "conversation_id": conv_id,
                        "conversation_name": conv_name,
                        "message_content": s.message_content,
                        "extra_data": s.extra_data
                    })
                
            except TeamsAPIError:
                continue
        
        scan = db.get_scan(scan_id)
        new_convs = (scan.get("conversations_scanned") or 0) + len(page_convs)
        new_msgs = (scan.get("messages_scanned") or 0) + total_messages
        new_secrets = (scan.get("secrets_found") or 0) + total_secrets
        
        is_complete = (page + 1) >= total_pages
        
        db.update_scan(
            scan_id,
            conversations_scanned=new_convs,
            messages_scanned=new_msgs,
            secrets_found=new_secrets,
            status="completed" if is_complete else "in_progress"
        )
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "page": page,
            "total_pages": total_pages,
            "conversations_in_page": len(page_convs),
            "messages_in_page": total_messages,
            "secrets_in_page": total_secrets,
            "total_conversations": total_convs,
            "is_complete": is_complete,
            "progress_percent": round(((page + 1) / total_pages) * 100) if total_pages > 0 else 100
        })
    except TeamsAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_results", methods=["GET"])
def api_get_results():
    scan_id = request.args.get("scan_id")
    
    if scan_id:
        scan = db.get_scan(int(scan_id))
    else:
        scan = db.get_latest_scan()
    
    if not scan:
        return jsonify({
            "secrets": [],
            "conversations_scanned": 0,
            "messages_scanned": 0,
            "scan_time": None
        })
    
    secrets = db.get_secrets(scan["id"])
    
    # Format secrets for frontend
    formatted_secrets = []
    for s in secrets:
        formatted_secrets.append({
            "id": s["id"],
            "type": s["secret_type"],
            "raw_value": s["raw_value"],
            "redacted_value": s["redacted_value"],
            "confidence": s["confidence"],
            "entropy": s["entropy"],
            "sender": s["sender"],
            "timestamp": s["timestamp"],
            "context_before": s["context_before"],
            "context_after": s["context_after"],
            "message_id": s["message_id"],
            "conversation_id": s["conversation_id"],
            "conversation_name": s["conversation_name"],
            "message_content": s.get("message_content", ""),
            "extra_data": s["extra_data"]
        })
    
    return jsonify({
        "scan_id": scan["id"],
        "secrets": formatted_secrets,
        "conversations_scanned": scan["conversations_scanned"] or 0,
        "messages_scanned": scan["messages_scanned"] or 0,
        "scan_time": scan["scan_time"],
        "status": scan["status"]
    })


@app.route("/api/get_context/<conversation_id>/<message_id>", methods=["GET"])
def api_get_context(conversation_id: str, message_id: str):
    try:
        scan_id = request.args.get("scan_id")
        if scan_id:
            scan_id = int(scan_id)
        else:
            scan = db.get_latest_scan()
            scan_id = scan["id"] if scan else None
        
        if not scan_id:
            return jsonify({"error": "No scan found"}), 404
        
        context = db.get_message_context(scan_id, conversation_id, message_id)
        
        if not context["messages"]:
            return jsonify({"error": "Message not found"}), 404
        
        return jsonify(context)
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_scans", methods=["GET"])
def api_get_scans():
    scans = db.get_all_scans()
    return jsonify({"scans": scans})


@app.route("/api/delete_scan/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: int):
    try:
        db.delete_scan(scan_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify(db.get_stats())


@app.route("/results")
def results_page():
    # Redirect to history with scan_id if provided
    scan_id = request.args.get("scan_id")
    if scan_id:
        return render_template("scan_results.html")
    return redirect("/history")


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/teams")
def teams_page():
    return render_template("teams.html")


@app.route("/conversation/<conversation_id>/<message_id>")
def conversation_view(conversation_id: str, message_id: str):
    return render_template("conversation_view.html", 
                         conversation_id=conversation_id, 
                         message_id=message_id)


@app.route("/api/export_results", methods=["GET"])
def api_export_results():
    scan_id = request.args.get("scan_id")
    
    if scan_id:
        scan = db.get_scan(int(scan_id))
    else:
        scan = db.get_latest_scan()
    
    if not scan:
        return jsonify({"error": "No scan found"}), 404
    
    secrets = db.get_secrets(scan["id"])
    
    export_data = {
        "scan_info": {
            "scan_id": scan["id"],
            "scan_time": scan["scan_time"],
            "user_email": scan["user_email"],
            "conversations_scanned": scan["conversations_scanned"],
            "messages_scanned": scan["messages_scanned"],
            "secrets_found": len(secrets)
        },
        "results": []
    }
    
    for secret in secrets:
        export_data["results"].append({
            "DetectorType": secret["secret_type"],
            "Verified": False,
            "Raw": secret["raw_value"],
            "Redacted": secret["redacted_value"],
            "ExtraData": {
                "confidence": secret["confidence"],
                "entropy": secret["entropy"],
                "sender": secret["sender"],
                "conversation_id": secret["conversation_id"],
                "conversation_name": secret["conversation_name"],
                **secret.get("extra_data", {})
            },
            "SourceMetadata": {
                "Data": {
                    "Teams": {
                        "message_id": secret["message_id"],
                        "timestamp": secret["timestamp"],
                        "context_before": secret["context_before"],
                        "context_after": secret["context_after"]
                    }
                }
            }
        })
    
    return jsonify(export_data)


@app.route("/about")
def about_page():
    return render_template("about.html")


# ==================== GRAPH API ROUTES (Email, OneDrive, SharePoint) ====================

@app.route("/api/set_graph_token", methods=["POST"])
def api_set_graph_token():
    """Set Microsoft Graph API token (for Email, OneDrive, SharePoint)."""
    try:
        data = request.get_json() or request.form
        access_token = data.get("access_token", "").strip()
        refresh_token = data.get("refresh_token", "").strip()
        
        if refresh_token:
            tenant = data.get("tenant", "common")
            tokens = refresh_to_graph_token(refresh_token, tenant)
            token_info = graph_api.set_access_token(tokens["access_token"])
            graph_api.set_refresh_token(tokens.get("refresh_token", refresh_token))
            session["graph_token_configured"] = True
            session["graph_user_email"] = token_info.get("user", "")
            
            return jsonify({
                "success": True,
                "token_info": token_info,
                "message": "Graph API token configured"
            })
        
        if not access_token:
            return jsonify({"error": "No access token or refresh token provided"}), 400
        
        token_info = graph_api.set_access_token(access_token)
        session["graph_token_configured"] = True
        session["graph_user_email"] = token_info.get("user", "")
        
        return jsonify({
            "success": True,
            "token_info": token_info
        })
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/search_emails", methods=["POST"])
def api_search_emails():
    """Search emails using Microsoft Graph API."""
    try:
        data = request.get_json() or {}
        search_term = data.get("search_term", "").strip()
        max_results = int(data.get("max_results", 25))
        page_from = int(data.get("page_from", 0))
        scan_secrets = data.get("scan_secrets", True)
        
        if not search_term:
            return jsonify({"error": "No search term provided"}), 400
        
        results, total, has_more = graph_api.search_emails(search_term, max_results, page_from)
        
        scan_id = current_scan.get("id")
        if not scan_id:
            scan_id = db.create_scan(
                user_email=session.get("graph_user_email"),
                tenant_id=session.get("tenant_id")
            )
            current_scan["id"] = scan_id
        
        emails_data = []
        secrets_found = 0
        
        for email in results:
            email_dict = {
                "id": email.message_id,
                "subject": email.subject,
                "sender": email.sender,
                "sender_name": email.sender_name,
                "recipients": email.recipients,
                "date": email.date,
                "preview": email.preview,
                "body_content": email.body_content,
                "body_type": email.body_type,
                "has_attachments": email.has_attachments,
                "web_link": email.web_link,
                "importance": email.importance,
                "is_read": email.is_read,
                "secrets_found": 0
            }
            
            if scan_secrets and email.preview:
                secrets = detector.scan_text(
                    text=f"{email.subject} {email.preview}",
                    message_id=email.message_id,
                    conversation_id="email",
                    sender=email.sender,
                    timestamp=email.date
                )
                email_dict["secrets_found"] = len(secrets)
                secrets_found += len(secrets)
                
                for s in secrets:
                    db.save_secret(scan_id, {
                        "type": s.secret_type.value,
                        "raw_value": s.raw_value,
                        "redacted_value": s.redacted_value,
                        "confidence": s.confidence,
                        "entropy": s.entropy,
                        "sender": email.sender,
                        "timestamp": email.date,
                        "context_before": s.context_before,
                        "context_after": s.context_after,
                        "message_id": email.message_id,
                        "conversation_id": "email",
                        "conversation_name": f"Email: {email.subject[:50]}",
                        "message_content": email.preview,
                        "extra_data": {"source": "email", "subject": email.subject}
                    })
            
            db.save_email(scan_id, email_dict)
            emails_data.append(email_dict)
        
        return jsonify({
            "emails": emails_data,
            "total": total,
            "has_more": has_more,
            "secrets_found": secrets_found,
            "scan_id": scan_id
        })
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_email/<email_id>", methods=["GET"])
def api_get_email(email_id: str):
    """Get full email details including body."""
    try:
        email_details = graph_api.get_email_details(email_id)
        
        attachments = []
        if email_details.get("hasAttachments"):
            attachments = graph_api.get_email_attachments(email_id)
        
        return jsonify({
            "email": email_details,
            "attachments": attachments
        })
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/download_email/<email_id>", methods=["GET"])
def api_download_email(email_id: str):
    """Download email as EML file."""
    try:
        eml_content = graph_api.export_email_eml(email_id)
        
        return Response(
            eml_content,
            mimetype="message/rfc822",
            headers={"Content-Disposition": f"attachment; filename=email_{email_id[:8]}.eml"}
        )
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/download_attachment/<email_id>/<attachment_id>", methods=["GET"])
def api_download_attachment(email_id: str, attachment_id: str):
    """Download email attachment."""
    try:
        content, filename = graph_api.download_attachment(email_id, attachment_id)
        
        return send_file(
            io.BytesIO(content),
            as_attachment=True,
            download_name=filename
        )
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/search_files", methods=["POST"])
def api_search_files():
    """Search files in OneDrive and SharePoint."""
    try:
        data = request.get_json() or {}
        search_term = data.get("search_term", "").strip()
        max_results = int(data.get("max_results", 25))
        page_from = int(data.get("page_from", 0))
        scan_secrets = data.get("scan_secrets", True)
        
        if not search_term:
            return jsonify({"error": "No search term provided"}), 400
        
        results, total, has_more = graph_api.search_files(search_term, max_results, page_from)
        
        scan_id = current_scan.get("id")
        if not scan_id:
            scan_id = db.create_scan(
                user_email=session.get("graph_user_email"),
                tenant_id=session.get("tenant_id")
            )
            current_scan["id"] = scan_id
        
        files_data = []
        secrets_found = 0
        
        for file in results:
            file_dict = {
                "id": file.item_id,
                "drive_id": file.drive_id,
                "name": file.name,
                "size": file.size,
                "size_formatted": file.size_formatted,
                "web_url": file.web_url,
                "created_date": file.created_date,
                "modified_date": file.modified_date,
                "preview": file.preview,
                "mime_type": file.mime_type,
                "parent_path": file.parent_path,
                "secrets_found": 0
            }
            
            if scan_secrets and file.preview:
                secrets = detector.scan_text(
                    text=f"{file.name} {file.preview}",
                    message_id=file.item_id,
                    conversation_id=file.drive_id,
                    sender="file",
                    timestamp=file.modified_date
                )
                file_dict["secrets_found"] = len(secrets)
                secrets_found += len(secrets)
                
                for s in secrets:
                    db.save_secret(scan_id, {
                        "type": s.secret_type.value,
                        "raw_value": s.raw_value,
                        "redacted_value": s.redacted_value,
                        "confidence": s.confidence,
                        "entropy": s.entropy,
                        "sender": "file",
                        "timestamp": file.modified_date,
                        "context_before": s.context_before,
                        "context_after": s.context_after,
                        "message_id": file.item_id,
                        "conversation_id": file.drive_id,
                        "conversation_name": f"File: {file.name}",
                        "message_content": file.preview,
                        "extra_data": {"source": "file", "web_url": file.web_url, "path": file.parent_path}
                    })
            
            db.save_file(scan_id, file_dict, source="search")
            files_data.append(file_dict)
        
        return jsonify({
            "files": files_data,
            "total": total,
            "has_more": has_more,
            "secrets_found": secrets_found,
            "scan_id": scan_id
        })
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/download_file/<drive_id>/<item_id>", methods=["GET"])
def api_download_file(drive_id: str, item_id: str):
    """Download file from OneDrive/SharePoint."""
    try:
        content, filename, mime_type = graph_api.download_file(drive_id, item_id)
        
        return send_file(
            io.BytesIO(content),
            mimetype=mime_type,
            as_attachment=True,
            download_name=filename
        )
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_file_preview/<drive_id>/<item_id>", methods=["GET"])
def api_get_file_preview(drive_id: str, item_id: str):
    """Get file content preview."""
    try:
        preview = graph_api.get_file_content_preview(drive_id, item_id)
        thumbnail_url = graph_api.get_file_preview(drive_id, item_id)
        
        return jsonify({
            "preview": preview,
            "thumbnail_url": thumbnail_url
        })
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_sharepoint_sites", methods=["GET"])
def api_get_sharepoint_sites():
    """Get accessible SharePoint sites."""
    try:
        sites = graph_api.get_sharepoint_sites()
        return jsonify({"sites": sites})
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_onedrive", methods=["GET"])
def api_get_onedrive():
    """Get OneDrive root folder contents."""
    try:
        items = graph_api.get_onedrive_root()
        return jsonify({"items": items})
    except GraphAPIError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_detectors", methods=["GET"])
def api_get_detectors():
    """Get available secret detectors from GraphRunner."""
    detectors = load_detectors()
    return jsonify({"detectors": detectors})


@app.route("/api/scan_with_detectors", methods=["POST"])
def api_scan_with_detectors():
    """Run scan using GraphRunner detectors on files."""
    try:
        data = request.get_json() or {}
        detector_names = data.get("detectors", [])
        scan_type = data.get("type", "files")
        
        all_detectors = load_detectors()
        
        if detector_names:
            selected = [d for d in all_detectors if d.get("DetectorName") in detector_names]
        else:
            selected = all_detectors
        
        scan_id = current_scan.get("id")
        if not scan_id:
            scan_id = db.create_scan(
                user_email=session.get("graph_user_email"),
                tenant_id=session.get("tenant_id")
            )
            current_scan["id"] = scan_id
        
        total_files = 0
        total_secrets = 0
        all_results = []
        
        for det in selected:
            search_query = det.get("SearchQuery", "")
            detector_name = det.get("DetectorName", "Unknown")
            
            if not search_query:
                continue
            
            try:
                if scan_type == "files":
                    results, total, _ = graph_api.search_files(search_query, max_results=50)
                    
                    for file in results:
                        file_dict = {
                            "id": file.item_id,
                            "drive_id": file.drive_id,
                            "name": file.name,
                            "size": file.size,
                            "size_formatted": file.size_formatted,
                            "web_url": file.web_url,
                            "created_date": file.created_date,
                            "modified_date": file.modified_date,
                            "preview": file.preview,
                            "mime_type": file.mime_type,
                            "parent_path": file.parent_path,
                            "detector": detector_name
                        }
                        
                        db.save_file(scan_id, file_dict, source=detector_name)
                        all_results.append(file_dict)
                        total_files += 1
                        
                        if file.preview:
                            secrets = detector.scan_text(
                                text=f"{file.name} {file.preview}",
                                message_id=file.item_id,
                                conversation_id=file.drive_id,
                                sender="file",
                                timestamp=file.modified_date
                            )
                            total_secrets += len(secrets)
                            
                            for s in secrets:
                                db.save_secret(scan_id, {
                                    "type": s.secret_type.value,
                                    "raw_value": s.raw_value,
                                    "redacted_value": s.redacted_value,
                                    "confidence": s.confidence,
                                    "entropy": s.entropy,
                                    "sender": "file",
                                    "timestamp": file.modified_date,
                                    "context_before": s.context_before,
                                    "context_after": s.context_after,
                                    "message_id": file.item_id,
                                    "conversation_id": file.drive_id,
                                    "conversation_name": f"[{detector_name}] {file.name}",
                                    "message_content": file.preview,
                                    "extra_data": {"source": "detector", "detector": detector_name, "web_url": file.web_url}
                                })
                
                elif scan_type == "emails":
                    results, total, _ = graph_api.search_emails(search_query, max_results=50)
                    
                    for email in results:
                        email_dict = {
                            "id": email.message_id,
                            "subject": email.subject,
                            "sender": email.sender,
                            "sender_name": email.sender_name,
                            "recipients": email.recipients,
                            "date": email.date,
                            "preview": email.preview,
                            "has_attachments": email.has_attachments,
                            "detector": detector_name
                        }
                        
                        db.save_email(scan_id, email_dict)
                        all_results.append(email_dict)
                        total_files += 1
                        
                        if email.preview:
                            secrets = detector.scan_text(
                                text=f"{email.subject} {email.preview}",
                                message_id=email.message_id,
                                conversation_id="email",
                                sender=email.sender,
                                timestamp=email.date
                            )
                            total_secrets += len(secrets)
                            
                            for s in secrets:
                                db.save_secret(scan_id, {
                                    "type": s.secret_type.value,
                                    "raw_value": s.raw_value,
                                    "redacted_value": s.redacted_value,
                                    "confidence": s.confidence,
                                    "entropy": s.entropy,
                                    "sender": email.sender,
                                    "timestamp": email.date,
                                    "context_before": s.context_before,
                                    "context_after": s.context_after,
                                    "message_id": email.message_id,
                                    "conversation_id": "email",
                                    "conversation_name": f"[{detector_name}] {email.subject[:30]}",
                                    "message_content": email.preview,
                                    "extra_data": {"source": "detector", "detector": detector_name}
                                })
            except Exception as e:
                continue
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "detectors_used": len(selected),
            "items_found": total_files,
            "secrets_found": total_secrets,
            "results": all_results[:100]
        })
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/get_scan_emails/<int:scan_id>", methods=["GET"])
def api_get_scan_emails(scan_id: int):
    """Get emails from a scan."""
    emails = db.get_emails(scan_id)
    return jsonify({"emails": emails})


@app.route("/api/get_scan_files/<int:scan_id>", methods=["GET"])
def api_get_scan_files(scan_id: int):
    """Get files from a scan."""
    source = request.args.get("source")
    files = db.get_files(scan_id, source=source)
    return jsonify({"files": files})


@app.route("/api/delete_secret/<int:secret_id>", methods=["DELETE"])
def api_delete_secret(secret_id: int):
    """Delete a single secret result."""
    try:
        db.delete_secret(secret_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/clear_all_secrets", methods=["DELETE"])
def api_clear_all_secrets():
    """Delete a scan and all its data."""
    try:
        # Try to get scan_id from request args or current_scan
        scan_id = request.args.get("scan_id")
        if scan_id:
            scan_id = int(scan_id)
        else:
            scan_id = current_scan.get("id")
        
        if not scan_id:
            # Get latest scan
            scan = db.get_latest_scan()
            scan_id = scan["id"] if scan else None
        
        if scan_id:
            # Delete the entire scan (secrets + messages + conversations + scan itself)
            db.delete_scan(scan_id)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "No scan found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/emails")
def emails_page():
    return render_template("emails.html")


@app.route("/api/scan_emails_secrets", methods=["POST"])
def api_scan_emails_secrets():
    """Scan inbox emails for secrets using the built-in secret detector."""
    try:
        data = request.get_json() or {}
        max_results = int(data.get("max_results", 200))
        
        # Get inbox emails
        email_results = graph_api.get_inbox(max_messages=max_results)
        
        secrets_list = []
        emails_with_secrets = set()
        
        for email in email_results:
            # Scan subject + preview + body content
            text_to_scan = f"{email.subject} {email.preview} {email.body_content}"
            
            if text_to_scan.strip():
                secrets = detector.scan_email_text(
                    text=text_to_scan,
                    message_id=email.message_id,
                    conversation_id="email",
                    sender=email.sender,
                    timestamp=email.date
                )
                
                if secrets:
                    emails_with_secrets.add(email.message_id)
                    
                    for s in secrets:
                        secrets_list.append({
                            "type": s.secret_type.value,
                            "raw_value": s.raw_value,
                            "redacted_value": s.redacted_value,
                            "confidence": s.confidence,
                            "entropy": s.entropy,
                            "context_before": s.context_before,
                            "context_after": s.context_after,
                            "message_id": email.message_id,
                            "email_subject": email.subject,
                            "sender": email.sender,
                            "timestamp": email.date
                        })
        
        return jsonify({
            "emails_scanned": len(email_results),
            "emails_with_secrets": len(emails_with_secrets),
            "total_secrets": len(secrets_list),
            "secrets": secrets_list
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/files")
def files_page():
    return render_template("files.html")


@app.route("/api/scan_files_secrets", methods=["POST"])
def api_scan_files_secrets():
    """Scan OneDrive files for secrets using the built-in secret detector."""
    try:
        data = request.get_json() or {}
        max_results = int(data.get("max_results", 200))
        
        # Get OneDrive files
        onedrive_items = graph_api.get_onedrive_root()
        
        secrets_list = []
        files_with_secrets = set()
        file_count = 0
        
        for item in onedrive_items:
            # Skip folders
            if item.get("folder"):
                continue
            
            file_count += 1
            if file_count > max_results:
                break
            
            drive_id = item.get("parentReference", {}).get("driveId", "")
            item_id = item.get("id", "")
            file_name = item.get("name", "")
            file_size = item.get("size", 0)
            web_url = item.get("webUrl", "")
            
            # Try to get content preview for text files
            preview = ""
            try:
                preview = graph_api.get_file_content_preview(drive_id, item_id) or ""
            except:
                pass
            
            # Scan file name and preview for secrets
            text_to_scan = f"{file_name} {preview}"
            
            if text_to_scan.strip():
                secrets = detector.scan_email_text(
                    text=text_to_scan,
                    message_id=item_id,
                    conversation_id=drive_id,
                    sender="file",
                    timestamp=item.get("lastModifiedDateTime", "")
                )
                
                if secrets:
                    files_with_secrets.add(item_id)
                    
                    for s in secrets:
                        secrets_list.append({
                            "type": s.secret_type.value,
                            "raw_value": s.raw_value,
                            "redacted_value": s.redacted_value,
                            "confidence": s.confidence,
                            "entropy": s.entropy,
                            "context_before": s.context_before,
                            "context_after": s.context_after,
                            "item_id": item_id,
                            "drive_id": drive_id,
                            "file_name": file_name,
                            "file_size": graph_api._format_size(file_size),
                            "web_url": web_url
                        })
        
        return jsonify({
            "files_scanned": file_count,
            "files_with_secrets": len(files_with_secrets),
            "total_secrets": len(secrets_list),
            "secrets": secrets_list
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/terminator")
def terminator_page():
    return render_template("terminator.html")


@app.route("/api/get_teams_messages/<path:conversation_id>")
def api_get_teams_messages(conversation_id):
    """Get messages from a Teams conversation."""
    try:
        # Clean conversation_id - remove any query params or trailing numbers that might have been appended
        clean_conv_id = conversation_id.split('?')[0] if '?' in conversation_id else conversation_id
        # Remove trailing ",number" patterns (e.g. ",200" or ",50")
        if ',' in clean_conv_id:
            parts = clean_conv_id.rsplit(',', 1)
            if parts[1].isdigit():
                clean_conv_id = parts[0]
        
        # Build the messages URL (without query params - teams_api.get_conversation_messages adds them)
        messages_url = f"https://emea.ng.msg.teams.microsoft.com/v1/users/ME/conversations/{clean_conv_id}/messages"
        messages = teams_api.get_conversation_messages(messages_url)
        
        formatted_messages = []
        for msg in messages:
            content = msg.get("content", "")
            sender = msg.get("imdisplayname", msg.get("from", "Unknown"))
            timestamp = msg.get("composetime", msg.get("originalarrivaltime", ""))
            
            formatted_messages.append({
                "content": content,
                "sender": sender,
                "timestamp": timestamp
            })
        
        return jsonify({"messages": formatted_messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/terminator_init", methods=["POST"])
def api_terminator_init():
    """Initialize all APIs with a single refresh token."""
    try:
        data = request.get_json() or request.form
        refresh_token = data.get("refresh_token", "").strip()
        tenant = data.get("tenant", "common").strip()
        
        if not refresh_token:
            return jsonify({"error": "No refresh token provided"}), 400
        
        results = {
            "teams": {"success": False, "error": None, "user": None},
            "graph": {"success": False, "error": None, "user": None}
        }
        
        try:
            teams_tokens = refresh_to_access_token(refresh_token, tenant)
            token_info = teams_api.set_access_token(teams_tokens["access_token"])
            session["token_configured"] = True
            session["user_email"] = token_info.get("user", "")
            session["tenant_id"] = token_info.get("tenant_id", "")
            session["refresh_token"] = teams_tokens.get("refresh_token", refresh_token)
            results["teams"] = {
                "success": True,
                "user": token_info.get("user", ""),
                "error": None
            }
        except Exception as e:
            results["teams"]["error"] = str(e)
        
        try:
            graph_tokens = refresh_to_graph_token(refresh_token, tenant)
            graph_info = graph_api.set_access_token(graph_tokens["access_token"])
            graph_api.set_refresh_token(graph_tokens.get("refresh_token", refresh_token))
            session["graph_token_configured"] = True
            session["graph_user_email"] = graph_info.get("user", "")
            results["graph"] = {
                "success": True,
                "user": graph_info.get("user", ""),
                "error": None
            }
        except Exception as e:
            results["graph"]["error"] = str(e)
        
        return jsonify({
            "success": results["teams"]["success"] or results["graph"]["success"],
            "results": results
        })
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/api/terminator_scan", methods=["POST"])
def api_terminator_scan():
    """Run a full scan across Teams, Emails, and Files - no search term, just secret detection."""
    try:
        data = request.get_json() or {}
        scan_teams = data.get("scan_teams", True)
        scan_emails = data.get("scan_emails", True)
        scan_files = data.get("scan_files", True)
        max_results = int(data.get("max_results", 50))
        
        scan_id = db.create_scan(
            user_email=session.get("user_email") or session.get("graph_user_email"),
            tenant_id=session.get("tenant_id")
        )
        current_scan["id"] = scan_id
        
        results = {
            "scan_id": scan_id,
            "teams": {"conversations": 0, "messages": 0, "secrets": 0, "items": [], "error": None},
            "emails": {"total": 0, "secrets": 0, "items": [], "error": None},
            "files": {"total": 0, "secrets": 0, "items": [], "error": None},
            "total_secrets": 0
        }
        
        if scan_teams:
            try:
                conversations = teams_api.get_conversations()
                valid_convs = [c for c in conversations 
                              if c.get("threadProperties", {}).get("threadType") != "streamofnotifications"
                              and c.get("properties", {}).get("isemptyconversation") != "True"][:max_results]
                
                for conv in valid_convs:
                    conv_id = conv.get("id", "")
                    conv_name = get_conversation_name(conv)
                    messages_link = conv.get("messages", "")
                    
                    if not messages_link:
                        continue
                    
                    try:
                        messages = teams_api.get_conversation_messages(messages_link)
                        results["teams"]["messages"] += len(messages)
                        db.save_messages(scan_id, conv_id, messages)
                        
                        secrets = detector.scan_messages(messages, conv_id)
                        results["teams"]["secrets"] += len(secrets)
                        
                        for s in secrets:
                            db.save_secret(scan_id, {
                                "type": s.secret_type.value,
                                "raw_value": s.raw_value,
                                "redacted_value": s.redacted_value,
                                "confidence": s.confidence,
                                "entropy": s.entropy,
                                "sender": s.sender,
                                "timestamp": s.timestamp,
                                "context_before": s.context_before,
                                "context_after": s.context_after,
                                "message_id": s.message_id,
                                "conversation_id": conv_id,
                                "conversation_name": conv_name,
                                "message_content": s.message_content,
                                "extra_data": {"source": "teams"}
                            })
                        
                        if secrets:
                            results["teams"]["items"].append({
                                "conversation": conv_name,
                                "conversation_id": conv_id,
                                "messages": len(messages),
                                "secrets": len(secrets)
                            })
                    except:
                        continue
                
                results["teams"]["conversations"] = len(valid_convs)
            except Exception as e:
                results["teams"]["error"] = str(e)
        
        if scan_emails:
            try:
                # Get inbox emails directly - scan up to 200 emails
                email_limit = max(max_results, 200)
                email_results = graph_api.get_inbox(max_messages=email_limit)
                results["emails"]["total"] = len(email_results)
                
                for email in email_results:
                    email_dict = {
                        "id": email.message_id,
                        "subject": email.subject,
                        "sender": email.sender,
                        "sender_name": email.sender_name,
                        "recipients": email.recipients,
                        "date": email.date,
                        "preview": email.preview,
                        "has_attachments": email.has_attachments,
                        "web_link": email.web_link,
                        "secrets_found": 0
                    }
                    
                    # Scan subject + preview + body content using email-specific scanner
                    text_to_scan = f"{email.subject} {email.preview} {email.body_content}"
                    
                    if text_to_scan.strip():
                        secrets = detector.scan_email_text(
                            text=text_to_scan,
                            message_id=email.message_id,
                            conversation_id="email",
                            sender=email.sender,
                            timestamp=email.date
                        )
                        
                        if secrets:
                            results["emails"]["secrets"] += len(secrets)
                            email_dict["secrets_found"] = len(secrets)
                            results["emails"]["items"].append(email_dict)
                            
                            for s in secrets:
                                db.save_secret(scan_id, {
                                    "type": s.secret_type.value,
                                    "raw_value": s.raw_value,
                                    "redacted_value": s.redacted_value,
                                    "confidence": s.confidence,
                                    "entropy": s.entropy,
                                    "sender": email.sender,
                                    "timestamp": email.date,
                                    "context_before": s.context_before,
                                    "context_after": s.context_after,
                                    "message_id": email.message_id,
                                    "conversation_id": "email",
                                    "conversation_name": f"Email: {email.subject[:50]}",
                                    "message_content": text_to_scan[:500],
                                    "extra_data": {"source": "email", "subject": email.subject}
                                })
                    
                    db.save_email(scan_id, email_dict)
            except Exception as e:
                results["emails"]["error"] = str(e)
        
        if scan_files:
            try:
                # Get OneDrive files directly (no search term)
                onedrive_items = graph_api.get_onedrive_root()
                file_count = 0
                
                for item in onedrive_items:
                    # Skip folders
                    if item.get("folder"):
                        continue
                    
                    file_count += 1
                    if file_count > max_results:
                        break
                    
                    # Get file preview content
                    drive_id = item.get("parentReference", {}).get("driveId", "")
                    item_id = item.get("id", "")
                    file_name = item.get("name", "")
                    file_size = item.get("size", 0)
                    web_url = item.get("webUrl", "")
                    modified = item.get("lastModifiedDateTime", "")
                    
                    # Try to get content preview for text files
                    preview = ""
                    try:
                        preview = graph_api.get_file_content_preview(drive_id, item_id) or ""
                    except:
                        pass
                    
                    file_dict = {
                        "id": item_id,
                        "drive_id": drive_id,
                        "name": file_name,
                        "size_formatted": graph_api._format_size(file_size),
                        "web_url": web_url,
                        "preview": preview,
                        "modified_date": modified,
                        "secrets_found": 0
                    }
                    
                    # Scan file name and preview for secrets
                    text_to_scan = f"{file_name} {preview}"
                    if text_to_scan.strip():
                        secrets = detector.scan_text(
                            text=text_to_scan,
                            message_id=item_id,
                            conversation_id=drive_id,
                            sender="file",
                            timestamp=modified
                        )
                        
                        if secrets:
                            results["files"]["secrets"] += len(secrets)
                            file_dict["secrets_found"] = len(secrets)
                            results["files"]["items"].append(file_dict)
                            
                            for s in secrets:
                                db.save_secret(scan_id, {
                                    "type": s.secret_type.value,
                                    "raw_value": s.raw_value,
                                    "redacted_value": s.redacted_value,
                                    "confidence": s.confidence,
                                    "entropy": s.entropy,
                                    "sender": "file",
                                    "timestamp": modified,
                                    "context_before": s.context_before,
                                    "context_after": s.context_after,
                                    "message_id": item_id,
                                    "conversation_id": drive_id,
                                    "conversation_name": f"File: {file_name}",
                                    "message_content": preview,
                                    "extra_data": {"source": "file", "web_url": web_url}
                                })
                    
                    db.save_file(scan_id, file_dict, source="terminator")
                
                results["files"]["total"] = file_count
            except Exception as e:
                results["files"]["error"] = str(e)
        
        results["total_secrets"] = (
            results["teams"]["secrets"] + 
            results["emails"]["secrets"] + 
            results["files"]["secrets"]
        )
        
        db.update_scan(
            scan_id,
            conversations_scanned=results["teams"]["conversations"],
            messages_scanned=results["teams"]["messages"] + results["emails"]["total"],
            secrets_found=results["total_secrets"],
            status="completed"
        )
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════╗
║                    HadesHunter                          ║
║         Scan Teams conversations for leaked secrets            ║
╚════════════════════════════════════════════════════════════════╝
    """)
    app.run(host="127.0.0.1", port=5000, debug=True)
