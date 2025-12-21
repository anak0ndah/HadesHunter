#!/usr/bin/env python3
"""
Microsoft Graph API integration for HadesHunter.
Provides access to Email, OneDrive, and SharePoint data.
Inspired by GraphRunner by Beau Bullock (@dafthack).
"""

import requests
import jwt
import json
import base64
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime


class GraphAPIError(Exception):
    def __init__(self, message: str, status_code: int = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


@dataclass
class EmailResult:
    message_id: str
    subject: str
    sender: str
    sender_name: str
    recipients: List[str]
    date: str
    preview: str
    body_content: str
    body_type: str
    has_attachments: bool
    web_link: str
    importance: str
    is_read: bool


@dataclass
class FileResult:
    item_id: str
    drive_id: str
    name: str
    size: int
    size_formatted: str
    web_url: str
    created_date: str
    modified_date: str
    preview: str
    mime_type: str
    parent_path: str


class GraphAPI:
    """Microsoft Graph API client for Email, OneDrive, and SharePoint."""
    
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
    
    def __init__(self, user_agent: str = None):
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._user_info: Dict = {}
    
    def set_access_token(self, access_token: str) -> Dict[str, Any]:
        """Set the access token and decode user info."""
        self._access_token = access_token
        
        try:
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            self._user_info = {
                "user": decoded.get("unique_name", decoded.get("upn", "unknown")),
                "resource": decoded.get("aud", "unknown"),
                "expires_at": decoded.get("exp", 0),
                "issued_at": decoded.get("iat", 0),
                "tenant_id": decoded.get("tid", "unknown"),
            }
            return self._user_info
        except jwt.DecodeError as e:
            raise GraphAPIError(f"Invalid JWT token: {str(e)}")
    
    def set_refresh_token(self, refresh_token: str):
        """Store refresh token for later use."""
        self._refresh_token = refresh_token
    
    def _get_headers(self) -> Dict[str, str]:
        """Get standard headers for Graph API requests."""
        if not self._access_token:
            raise GraphAPIError("No access token configured. Call set_access_token first.")
        
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent
        }
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1048576:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1073741824:
            return f"{size_bytes / 1048576:.2f} MB"
        else:
            return f"{size_bytes / 1073741824:.2f} GB"
    
    # ==================== EMAIL METHODS ====================
    
    def search_emails(self, search_term: str, max_results: int = 25, 
                      page_from: int = 0) -> Tuple[List[EmailResult], int, bool]:
        """
        Search emails using Microsoft Graph Search API.
        Returns: (results, total_count, has_more)
        """
        url = f"{self.GRAPH_BASE_URL}/search/query"
        
        search_query = {
            "requests": [{
                "entityTypes": ["message"],
                "query": {
                    "queryString": search_term
                },
                "from": page_from,
                "size": max_results,
                "enableTopResults": True
            }]
        }
        
        response = requests.post(url, headers=self._get_headers(), json=search_query)
        
        if response.status_code != 200:
            raise GraphAPIError(f"Email search failed: {response.text}", response.status_code)
        
        data = response.json()
        hits_container = data.get("value", [{}])[0].get("hitsContainers", [{}])[0]
        total = hits_container.get("total", 0)
        has_more = hits_container.get("moreResultsAvailable", False)
        hits = hits_container.get("hits", [])
        
        results = []
        for hit in hits:
            resource = hit.get("resource", {})
            sender_info = resource.get("sender", {}).get("emailAddress", {})
            recipients = [r.get("emailAddress", {}).get("address", "") 
                         for r in resource.get("toRecipients", [])]
            
            # Extract real message ID from webLink if available
            web_link = resource.get("webLink", "")
            message_id = resource.get("id", "")
            
            # Try to extract ItemID from webLink for proper API access
            if web_link and "ItemID=" in web_link:
                import re
                import urllib.parse
                match = re.search(r"ItemID=([^&]+)", web_link)
                if match:
                    message_id = urllib.parse.unquote(match.group(1))
            
            results.append(EmailResult(
                message_id=message_id,
                subject=resource.get("subject", ""),
                sender=sender_info.get("address", ""),
                sender_name=sender_info.get("name", ""),
                recipients=recipients,
                date=resource.get("sentDateTime", ""),
                preview=resource.get("bodyPreview", ""),
                body_content="",
                body_type="",
                has_attachments=resource.get("hasAttachments", False),
                web_link=web_link,
                importance=resource.get("importance", "normal"),
                is_read=resource.get("isRead", False)
            ))
        
        return results, total, has_more
    
    def get_inbox(self, user_id: str = "me", max_messages: int = 200) -> List[EmailResult]:
        """Get inbox messages for a user with full body content."""
        # Request body content explicitly
        select_fields = "$select=id,subject,sender,toRecipients,sentDateTime,bodyPreview,body,hasAttachments,webLink,importance,isRead"
        if user_id == "me":
            url = f"{self.GRAPH_BASE_URL}/me/mailFolders/Inbox/messages?$top={max_messages}&{select_fields}"
        else:
            url = f"{self.GRAPH_BASE_URL}/users/{user_id}/mailFolders/Inbox/messages?$top={max_messages}&{select_fields}"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to get inbox: {response.text}", response.status_code)
        
        data = response.json()
        results = []
        
        for msg in data.get("value", []):
            sender_info = msg.get("sender", {}).get("emailAddress", {})
            recipients = [r.get("emailAddress", {}).get("address", "") 
                         for r in msg.get("toRecipients", [])]
            body = msg.get("body", {})
            
            results.append(EmailResult(
                message_id=msg.get("id", ""),
                subject=msg.get("subject", ""),
                sender=sender_info.get("address", ""),
                sender_name=sender_info.get("name", ""),
                recipients=recipients,
                date=msg.get("sentDateTime", ""),
                preview=msg.get("bodyPreview", ""),
                body_content=body.get("content", ""),
                body_type=body.get("contentType", ""),
                has_attachments=msg.get("hasAttachments", False),
                web_link=msg.get("webLink", ""),
                importance=msg.get("importance", "normal"),
                is_read=msg.get("isRead", False)
            ))
        
        return results
    
    def get_email_details(self, message_id: str, user_id: str = "me") -> Dict:
        """Get full email details including body."""
        if user_id == "me":
            url = f"{self.GRAPH_BASE_URL}/me/messages/{message_id}"
        else:
            url = f"{self.GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to get email: {response.text}", response.status_code)
        
        return response.json()
    
    def get_email_attachments(self, message_id: str, user_id: str = "me") -> List[Dict]:
        """Get attachments for an email."""
        if user_id == "me":
            url = f"{self.GRAPH_BASE_URL}/me/messages/{message_id}/attachments"
        else:
            url = f"{self.GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}/attachments"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to get attachments: {response.text}", response.status_code)
        
        return response.json().get("value", [])
    
    def download_attachment(self, message_id: str, attachment_id: str, 
                           user_id: str = "me") -> Tuple[bytes, str]:
        """Download an attachment. Returns (content_bytes, filename)."""
        if user_id == "me":
            url = f"{self.GRAPH_BASE_URL}/me/messages/{message_id}/attachments/{attachment_id}"
        else:
            url = f"{self.GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}/attachments/{attachment_id}"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to download attachment: {response.text}", response.status_code)
        
        data = response.json()
        content_bytes = base64.b64decode(data.get("contentBytes", ""))
        filename = data.get("name", "attachment")
        
        return content_bytes, filename
    
    def export_email_eml(self, message_id: str, user_id: str = "me") -> bytes:
        """Export email as EML format."""
        if user_id == "me":
            url = f"{self.GRAPH_BASE_URL}/me/messages/{message_id}/$value"
        else:
            url = f"{self.GRAPH_BASE_URL}/users/{user_id}/messages/{message_id}/$value"
        
        headers = self._get_headers()
        headers["Accept"] = "message/rfc822"
        
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to export email: {response.text}", response.status_code)
        
        return response.content
    
    # ==================== ONEDRIVE / SHAREPOINT METHODS ====================
    
    def search_files(self, search_term: str, max_results: int = 25,
                    page_from: int = 0) -> Tuple[List[FileResult], int, bool]:
        """
        Search files in OneDrive and SharePoint using Graph Search API.
        Returns: (results, total_count, has_more)
        """
        url = f"{self.GRAPH_BASE_URL}/search/query"
        
        search_query = {
            "requests": [{
                "entityTypes": ["driveItem"],
                "query": {
                    "queryString": search_term
                },
                "from": page_from,
                "size": max_results
            }]
        }
        
        response = requests.post(url, headers=self._get_headers(), json=search_query)
        
        if response.status_code != 200:
            raise GraphAPIError(f"File search failed: {response.text}", response.status_code)
        
        data = response.json()
        hits_container = data.get("value", [{}])[0].get("hitsContainers", [{}])[0]
        total = hits_container.get("total", 0)
        has_more = hits_container.get("moreResultsAvailable", False)
        hits = hits_container.get("hits", [])
        
        results = []
        for hit in hits:
            resource = hit.get("resource", {})
            parent_ref = resource.get("parentReference", {})
            file_info = resource.get("file", {})
            size = resource.get("size", 0)
            
            results.append(FileResult(
                item_id=resource.get("id", ""),
                drive_id=parent_ref.get("driveId", ""),
                name=resource.get("name", ""),
                size=size,
                size_formatted=self._format_size(size),
                web_url=resource.get("webUrl", ""),
                created_date=resource.get("createdDateTime", ""),
                modified_date=resource.get("lastModifiedDateTime", ""),
                preview=hit.get("summary", ""),
                mime_type=file_info.get("mimeType", ""),
                parent_path=parent_ref.get("path", "")
            ))
        
        return results, total, has_more
    
    def get_onedrive_root(self) -> List[Dict]:
        """Get OneDrive root folder contents."""
        url = f"{self.GRAPH_BASE_URL}/me/drive/root/children"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to get OneDrive: {response.text}", response.status_code)
        
        return response.json().get("value", [])
    
    def get_sharepoint_sites(self) -> List[Dict]:
        """Get SharePoint sites accessible to the user."""
        url = f"{self.GRAPH_BASE_URL}/sites?search=*"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to get SharePoint sites: {response.text}", response.status_code)
        
        return response.json().get("value", [])
    
    def get_drive_items(self, drive_id: str, folder_id: str = "root") -> List[Dict]:
        """Get items in a specific drive folder."""
        url = f"{self.GRAPH_BASE_URL}/drives/{drive_id}/items/{folder_id}/children"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to get drive items: {response.text}", response.status_code)
        
        return response.json().get("value", [])
    
    def download_file(self, drive_id: str, item_id: str) -> Tuple[bytes, str, str]:
        """
        Download a file from OneDrive/SharePoint.
        Returns: (content_bytes, filename, mime_type)
        """
        # First get file metadata
        meta_url = f"{self.GRAPH_BASE_URL}/drives/{drive_id}/items/{item_id}"
        meta_response = requests.get(meta_url, headers=self._get_headers())
        
        if meta_response.status_code != 200:
            raise GraphAPIError(f"Failed to get file metadata: {meta_response.text}", meta_response.status_code)
        
        metadata = meta_response.json()
        filename = metadata.get("name", "file")
        mime_type = metadata.get("file", {}).get("mimeType", "application/octet-stream")
        
        # Download content
        download_url = f"{self.GRAPH_BASE_URL}/drives/{drive_id}/items/{item_id}/content"
        
        headers = self._get_headers()
        del headers["Content-Type"]
        
        response = requests.get(download_url, headers=headers, allow_redirects=True)
        
        if response.status_code != 200:
            raise GraphAPIError(f"Failed to download file: {response.text}", response.status_code)
        
        return response.content, filename, mime_type
    
    def get_file_preview(self, drive_id: str, item_id: str) -> Optional[str]:
        """Get file preview/thumbnail URL."""
        url = f"{self.GRAPH_BASE_URL}/drives/{drive_id}/items/{item_id}/thumbnails"
        
        response = requests.get(url, headers=self._get_headers())
        
        if response.status_code != 200:
            return None
        
        thumbnails = response.json().get("value", [])
        if thumbnails:
            return thumbnails[0].get("large", {}).get("url")
        return None
    
    def get_file_content_preview(self, drive_id: str, item_id: str) -> Optional[str]:
        """Get text content preview for supported file types."""
        url = f"{self.GRAPH_BASE_URL}/drives/{drive_id}/items/{item_id}/content"
        
        headers = self._get_headers()
        headers["Range"] = "bytes=0-4096"
        del headers["Content-Type"]
        
        try:
            response = requests.get(url, headers=headers, allow_redirects=True)
            if response.status_code in [200, 206]:
                try:
                    return response.content.decode('utf-8', errors='ignore')[:1000]
                except:
                    return None
        except:
            pass
        return None


def refresh_to_graph_token(
    refresh_token: str,
    tenant_id: str = None,
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    resource: str = "https://graph.microsoft.com"
) -> Dict[str, str]:
    """
    Exchange a refresh token for a Microsoft Graph access token.
    Uses the same approach as GraphRunner.
    """
    tenants_to_try = []
    
    if tenant_id and tenant_id not in ["common", "organizations", ""]:
        tenants_to_try.append(tenant_id)
    
    tenants_to_try.extend(["organizations", "common"])
    
    last_error = None
    
    for tenant in tenants_to_try:
        url = f"https://login.microsoftonline.com/{tenant}/oauth2/token?api-version=1.0"
        
        body = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "resource": resource
        }
        
        try:
            response = requests.post(url, data=body)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token", refresh_token),
                    "expires_in": data.get("expires_in", 3600),
                    "resource": data.get("resource", resource)
                }
            else:
                error_data = response.json()
                last_error = error_data.get('error_description', 'Unknown error')
        except Exception as e:
            last_error = str(e)
    
    raise GraphAPIError(f"Token refresh failed: {last_error}")
