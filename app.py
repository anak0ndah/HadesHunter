#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session
import json
import os
from datetime import datetime
from typing import Dict, List, Any
import time

from secret_detector import SecretDetector, SecretMatch, get_detector
from teams_api import TeamsAPI, TeamsAPIError, refresh_to_access_token, get_tenant_id
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

current_scan = {
    "id": None,
    "start_time": None,
    "user_email": None,
    "tenant_id": None
}

PAGE_SIZE = 20


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
            "type": s["secret_type"],
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
    return render_template("scan_results.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


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


if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════╗
║                    HadesHunter                          ║
║         Scan Teams conversations for leaked secrets            ║
╚════════════════════════════════════════════════════════════════╝
    """)
    app.run(host="127.0.0.1", port=5000, debug=True)
