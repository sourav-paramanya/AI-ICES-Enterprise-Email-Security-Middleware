"""Zimbra SOAP clawback engine.

Performs post-delivery email remediation via Zimbra SOAP API.
Supports mail search, quarantine (move to Junk), deletion, and restoration.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

import httpx

from shared.config.settings import get_settings

logger = logging.getLogger(__name__)

SOAP_NAMESPACE = "urn:zimbraAccount"
ADMIN_NAMESPACE = "urn:zimbraAdmin"

# SOAP envelope template
SOAP_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns="{ns}">
  <soap:Header>
    <context xmlns="urn:zimbra">
      <authToken>{token}</authToken>
      <format type="json"/>
    </context>
  </soap:Header>
  <soap:Body>
    {body}
  </soap:Body>
</soap:Envelope>"""


class ZimbraSOAPClient:
    """SOAP client for Zimbra mail server operations."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._soap_url: Optional[str] = None
        self._admin_user: Optional[str] = None
        self._admin_password: Optional[str] = None
        self._auth_token: Optional[str] = None
        self._http_client: Optional[httpx.AsyncClient] = None
        self._token_expiry: float = 0

    async def initialize(self) -> None:
        """Initialize SOAP client with Zimbra credentials."""
        self._soap_url = self._settings.ZIMBRA_SOAP_URL or "http://localhost:7070/service/soap"
        self._admin_user = self._settings.ZIMBRA_ADMIN_USER or "admin@localhost"
        self._admin_password = self._settings.ZIMBRA_ADMIN_PASSWORD or ""

        self._http_client = httpx.AsyncClient(
            timeout=30.0,
            verify=False,  # TODO: Proper TLS verification in production
        )
        logger.info("Zimbra SOAP client initialized for %s", self._soap_url)

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.aclose()

    async def authenticate(self) -> str:
        """Authenticate with Zimbra and return auth token."""
        if self._auth_token and time.time() < self._token_expiry:
            return self._auth_token

        auth_body = """
        <AuthRequest xmlns="urn:zimbraAccount">
          <account by="adminName">{user}</account>
          <password>{password}</password>
        </AuthRequest>
        """.format(user=self._admin_user, password=self._admin_password)

        try:
            response = await self._soap_request(
                auth_body,
                ns="urn:zimbraAccount",
                is_auth=False,
            )
            self._auth_token = response.get("authToken", "")
            # Token typically valid for 12 hours
            self._token_expiry = time.time() + 43200
            logger.info("Zimbra authentication successful")
            return self._auth_token

        except Exception as e:
            logger.error("Zimbra authentication failed: %s", str(e))
            raise

    async def search_email(
        self,
        query: str,
        limit: int = 50,
        account_email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search for emails matching the query."""
        token = await self.authenticate()

        search_body = """
        <SearchRequest xmlns="urn:zimbraMail" limit="{limit}">
          <query>{query}</query>
        </SearchRequest>
        """.format(query=query, limit=limit)

        result = await self._soap_request(search_body, ns="urn:zimbraMail", token=token)

        matches = []
        for item in result.get("SearchResponse", {}).get("m", []):
            matches.append({
                "id": item.get("id"),
                "conversation_id": item.get("l"),
                "subject": self._extract_attribute(item, "su"),
                "from": self._extract_attribute(item, "e", "a"),
                "date": item.get("d"),
                "size": item.get("s"),
            })

        logger.info("Zimbra search found %d results for query: %s", len(matches), query[:100])
        return matches

    async def move_to_quarantine(
        self,
        message_id: str,
        account_email: str,
    ) -> Dict[str, Any]:
        """Move an email to the Junk/Spam folder (quarantine)."""
        token = await self.authenticate()

        # Get or create quarantine folder
        folder_id = await self._get_or_create_folder(token, "AI-ICES Quarantine", account_email)

        move_body = """
        <ItemActionRequest xmlns="urn:zimbraMail">
          <action id="{id}" op="move" l="{folder}"/>
        </ItemActionRequest>
        """.format(id=message_id, folder=folder_id)

        result = await self._soap_request(move_body, ns="urn:zimbraMail", token=token)
        logger.info("Moved message %s to quarantine folder %s", message_id, folder_id)
        return {"status": "quarantined", "folder_id": folder_id, "message_id": message_id}

    async def delete_email(self, message_id: str, account_email: str) -> Dict[str, Any]:
        """Permanently delete an email."""
        token = await self.authenticate()

        delete_body = """
        <ItemActionRequest xmlns="urn:zimbraMail">
          <action id="{id}" op="delete"/>
        </ItemActionRequest>
        """.format(id=message_id)

        result = await self._soap_request(delete_body, ns="urn:zimbraMail", token=token)
        logger.info("Deleted message %s", message_id)
        return {"status": "deleted", "message_id": message_id}

    async def restore_email(
        self,
        message_id: str,
        account_email: str,
        target_folder: str = "inbox",
    ) -> Dict[str, Any]:
        """Restore an email from quarantine to inbox."""
        token = await self.authenticate()

        # Map folder name to ID
        folder_ids = {"inbox": "2", "junk": "4", "trash": "3", "sent": "5"}
        target_id = folder_ids.get(target_folder.lower(), "2")

        restore_body = """
        <ItemActionRequest xmlns="urn:zimbraMail">
          <action id="{id}" op="move" l="{target}"/>
        </ItemActionRequest>
        """.format(id=message_id, target=target_id)

        result = await self._soap_request(restore_body, ns="urn:zimbraMail", token=token)
        logger.info("Restored message %s to %s folder", message_id, target_folder)
        return {"status": "restored", "folder": target_folder, "message_id": message_id}

    async def _get_or_create_folder(
        self,
        token: str,
        folder_name: str,
        account_email: str,
    ) -> str:
        """Get folder ID by name, or create if not exists."""
        # List folders
        folder_body = """
        <GetFolderRequest xmlns="urn:zimbraMail">
          <folder>
            <path>{name}</path>
          </folder>
        </GetFolderRequest>
        """.format(name=folder_name)

        try:
            result = await self._soap_request(folder_body, ns="urn:zimbraMail", token=token)
            folder = result.get("GetFolderResponse", {}).get("folder", {})
            if folder:
                return folder.get("id", "4")  # Default to Junk if not found
        except Exception:
            pass

        # Folder doesn't exist, create it under Junk (folder 4)
        create_body = """
        <CreateFolderRequest xmlns="urn:zimbraMail">
          <folder name="{name}" l="4"/>
        </CreateFolderRequest>
        """.format(name=folder_name)

        try:
            result = await self._soap_request(create_body, ns="urn:zimbraMail", token=token)
            return result.get("CreateFolderResponse", {}).get("folder", {}).get("id", "4")
        except Exception:
            return "4"

    async def _soap_request(
        self,
        body: str,
        ns: str,
        token: Optional[str] = None,
        is_auth: bool = True,
    ) -> Dict[str, Any]:
        """Make a SOAP request to Zimbra."""
        if not self._http_client:
            raise RuntimeError("SOAP client not initialized")

        envelope = SOAP_ENVELOPE.format(
            ns=ns,
            token=token or "",
            body=body,
        )

        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "User-Agent": "AI-ICES/1.0",
        }

        response = await self._http_client.post(
            self._soap_url,
            content=envelope.encode("utf-8"),
            headers=headers,
        )

        if response.is_error:
            logger.error(
                "SOAP request failed: %s - %s",
                response.status_code,
                response.text[:500],
            )
            raise Exception(f"SOAP error {response.status_code}: {response.text[:200]}")

        # Parse JSON response from Zimbra (Zimbra returns JSON wrapped in SOAP)
        try:
            import json
            return json.loads(response.text)
        except (json.JSONDecodeError, Exception):
            # Fallback: try to parse XML response
            return self._parse_soap_response(response.text)

    def _parse_soap_response(self, xml_text: str) -> Dict[str, Any]:
        """Minimal XML SOAP response parser."""
        try:
            root = ElementTree.fromstring(xml_text)
            result: Dict[str, Any] = {}
            for child in root.iter():
                if child.text and child.text.strip():
                    result[child.tag.split("}")[-1]] = child.text.strip()
            return result
        except Exception:
            return {}

    def _extract_attribute(self, item: Dict[str, Any], *keys: str) -> Optional[str]:
        """Extract nested attribute from Zimbra response item."""
        for key in keys:
            val = item.get(key)
            if val:
                if isinstance(val, list) and len(val) > 0:
                    return val[0] if isinstance(val[0], str) else val[0].get("_content", str(val[0]))
                return val
        return None

    @property
    def is_authenticated(self) -> bool:
        return self._auth_token is not None and time.time() < self._token_expiry


@lru_cache
def get_zimbra_client() -> ZimbraSOAPClient:
    return ZimbraSOAPClient()
