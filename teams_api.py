#!/usr/bin/env python3
import requests
import jwt
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


@dataclass
class TeamsSettings:
    access_token: str
    skype_token: str
    skype_id: str
    chat_service_uri: str
    teams_and_channels_service_uri: str
    expires_at: int


class TeamsAPIError(Exception):
    def __init__(self, message: str, status_code: int = None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class TeamsAPI:
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    def __init__(self, user_agent: str = None):
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._teams_settings: Optional[TeamsSettings] = None
        self._access_token: Optional[str] = None
    
    def set_access_token(self, access_token: str) -> Dict[str, Any]:
        self._access_token = access_token
        
        try:
            decoded = jwt.decode(access_token, options={"verify_signature": False})
            return {
                "user": decoded.get("unique_name", decoded.get("upn", "unknown")),
                "resource": decoded.get("aud", "unknown"),
                "expires_at": decoded.get("exp", 0),
                "issued_at": decoded.get("iat", 0),
                "tenant_id": decoded.get("tid", "unknown"),
            }
        except jwt.DecodeError as e:
            raise TeamsAPIError(f"Invalid JWT token: {str(e)}")
    
    def get_teams_settings(self) -> TeamsSettings:
        if not self._access_token:
            raise TeamsAPIError("No access token configured. Call set_access_token first.")
        
        if self._teams_settings and self._teams_settings.expires_at > datetime.now().timestamp():
            return self._teams_settings
        
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "User-Agent": self.user_agent
        }
        
        response = requests.post(
            "https://teams.microsoft.com/api/authsvc/v1.0/authz",
            headers=headers
        )
        
        if response.status_code != 200:
            raise TeamsAPIError(
                f"Failed to obtain Teams settings: {response.text}",
                response.status_code
            )
        
        try:
            data = response.json()
            skype_token = data["tokens"]["skypeToken"]
            decoded_skype = jwt.decode(skype_token, options={"verify_signature": False})
            
            self._teams_settings = TeamsSettings(
                access_token=self._access_token,
                skype_token=skype_token,
                skype_id=decoded_skype.get("skypeid", ""),
                chat_service_uri=data["regionGtms"]["chatService"],
                teams_and_channels_service_uri=data["regionGtms"]["teamsAndChannelsService"],
                expires_at=decoded_skype.get("exp", 0)
            )
            
            return self._teams_settings
        except (KeyError, jwt.DecodeError) as e:
            raise TeamsAPIError(f"Failed to parse Teams settings: {str(e)}")
    
    def get_conversations(self, page_size: int = 500) -> List[Dict]:
        settings = self.get_teams_settings()
        
        uri = f"{settings.chat_service_uri}/v1/users/ME/conversations?view=msnp24Equivalent&pageSize={page_size}"
        headers = {
            "Authentication": f"skypetoken={settings.skype_token}",
            "User-Agent": self.user_agent
        }
        
        response = requests.get(uri, headers=headers)
        
        if response.status_code != 200:
            raise TeamsAPIError(
                f"Failed to get conversations: {response.text}",
                response.status_code
            )
        
        try:
            data = response.json()
            conversations = data.get("conversations", [])
            
            for conv in conversations:
                conv["_is_from_me_skype_id"] = settings.skype_id
            
            return conversations
        except json.JSONDecodeError as e:
            raise TeamsAPIError(f"Failed to parse conversations: {str(e)}")
    
    def get_conversation_messages(self, conversation_link: str, page_size: int = 200) -> List[Dict]:
        settings = self.get_teams_settings()
        
        uri = f"{conversation_link}?startTime=0&view=msnp24Equivalent&pageSize={page_size}"
        headers = {
            "Authentication": f"skypetoken={settings.skype_token}",
            "User-Agent": self.user_agent
        }
        
        response = requests.get(uri, headers=headers)
        
        if response.status_code != 200:
            raise TeamsAPIError(
                f"Failed to get messages: {response.text}",
                response.status_code
            )
        
        try:
            data = response.json()
            messages = data.get("messages", [])
            
            for msg in messages:
                msg["isFromMe"] = msg.get("from", "").endswith(settings.skype_id)
            
            return messages
        except json.JSONDecodeError as e:
            raise TeamsAPIError(f"Failed to parse messages: {str(e)}")
    
    def get_conversation_members(self, conversation_id: str) -> List[Dict]:
        settings = self.get_teams_settings()
        
        uri = f"{settings.teams_and_channels_service_uri}/beta/teams/{conversation_id}/members"
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "User-Agent": self.user_agent
        }
        
        response = requests.get(uri, headers=headers)
        
        if response.status_code != 200:
            return []
        
        try:
            members = response.json()
            if isinstance(members, list):
                for member in members:
                    member["isCurrentUser"] = member.get("mri", "").endswith(settings.skype_id)
                return members
            return []
        except json.JSONDecodeError:
            return []
    
    def get_conversation_name_from_members(self, conversation_id: str) -> str:
        try:
            members = self.get_conversation_members(conversation_id)
            if not members:
                return ""
            
            other_members = [
                m.get("displayName", "") 
                for m in members 
                if not m.get("isCurrentUser", False) and m.get("displayName")
            ]
            
            if other_members:
                return ", ".join(other_members[:3])
            return ""
        except:
            return ""
    
    def get_all_messages_from_conversation(self, conversation: Dict) -> List[Dict]:
        messages_link = conversation.get("messages", "")
        if not messages_link:
            return []
        
        messages = self.get_conversation_messages(messages_link)
        
        conversation_id = conversation.get("id", "")
        conversation_name = (
            conversation.get("threadProperties", {}).get("topic") or
            conversation.get("threadProperties", {}).get("spaceThreadTopic") or
            "Unknown"
        )
        
        for msg in messages:
            msg["_conversation_id"] = conversation_id
            msg["_conversation_name"] = conversation_name
        
        return messages
    
    def scan_all_conversations(self, progress_callback=None) -> Dict[str, List[Dict]]:
        conversations = self.get_conversations()
        all_messages = {}
        
        total = len(conversations)
        for idx, conv in enumerate(conversations):
            conv_id = conv.get("id", "")
            
            if conv.get("threadProperties", {}).get("threadType") == "streamofnotifications":
                continue
            
            if conv.get("properties", {}).get("isemptyconversation") == "True":
                continue
            
            try:
                messages = self.get_all_messages_from_conversation(conv)
                if messages:
                    all_messages[conv_id] = {
                        "conversation": conv,
                        "messages": messages
                    }
            except TeamsAPIError:
                continue
            
            if progress_callback:
                progress_callback(idx + 1, total, conv_id)
        
        return all_messages


def refresh_to_access_token(
    refresh_token: str,
    tenant_id: str = None,
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    resource: str = "https://api.spaces.skype.com"
) -> Dict[str, str]:
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
    
    raise TeamsAPIError(f"Token refresh failed: {last_error}")


def get_tenant_id(tenant_domain: str) -> str:
    response = requests.get(
        f"https://login.microsoftonline.com/{tenant_domain}/.well-known/openid-configuration"
    )
    
    if response.status_code != 200:
        raise TeamsAPIError(f"Failed to get tenant ID for domain: {tenant_domain}")
    
    data = response.json()
    return data["authorization_endpoint"].split("/")[3]
