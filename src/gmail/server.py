from typing import Any
import argparse
import os
import asyncio
import json
import logging
import base64
from email.message import EmailMessage
from email.header import decode_header
from base64 import urlsafe_b64decode
from email import message_from_bytes
import webbrowser

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EMAIL_ADMIN_PROMPTS = """You are an email administrator. 
You can draft, read, trash, open, and send emails.
You've been given access to a specific gmail account. 
You have the following tools available:
- Send an email (send-email)
- Create a draft email (create-draft)
- List draft emails (list-drafts)
- Retrieve unread emails (get-unread-emails)
- Read email content (read-email)
- Trash email (trash-email)
- Open email in browser (open-email)
- List all labels (list-labels)
- Create a new label (create-label)
- Apply a label to an email (apply-label)
- Remove a label from an email (remove-label)
- Search for emails using Gmail's search syntax (search-emails)

Never send an email draft or trash an email unless the user confirms first. 
Always ask for approval if not already given.
"""

# Define available prompts
PROMPTS = {
    "manage-email": types.Prompt(
        name="manage-email",
        description="Act like an email administrator",
        arguments=None,
    ),
    "draft-email": types.Prompt(
        name="draft-email",
        description="Draft an email with content and recipient",
        arguments=[
            types.PromptArgument(
                name="content",
                description="What the email is about",
                required=True
            ),
            types.PromptArgument(
                name="recipient",
                description="Who should the email be addressed to",
                required=True
            ),
            types.PromptArgument(
                name="recipient_email",
                description="Recipient's email address",
                required=True
            ),
        ],
    ),
    "edit-draft": types.Prompt(
        name="edit-draft",
        description="Edit the existing email draft",
        arguments=[
            types.PromptArgument(
                name="changes",
                description="What changes should be made to the draft",
                required=True
            ),
            types.PromptArgument(
                name="current_draft",
                description="The current draft to edit",
                required=True
            ),
        ],
    ),
    "manage-labels": types.Prompt(
        name="manage-labels",
        description="Manage email labels for organization",
        arguments=[
            types.PromptArgument(
                name="action",
                description="What action to take with labels (create, list, apply, remove)",
                required=True
            ),
        ],
    ),
    "search-emails": types.Prompt(
        name="search-emails",
        description="Search for emails using Gmail's search syntax",
        arguments=[
            types.PromptArgument(
                name="query",
                description="What to search for in emails",
                required=True
            ),
        ],
    ),
}


def decode_mime_header(header: str) -> str: 
    """Helper function to decode encoded email headers"""
    decoded_parts = decode_header(header)
    decoded_string = ''
    for part, encoding in decoded_parts: 
        if isinstance(part, bytes): 
            decoded_string += part.decode(encoding or 'utf-8') 
        else: 
            decoded_string += part 
    return decoded_string


class GmailService:
    def __init__(self,
                 creds_file_path: str,
                 token_path: str,
                 scopes: list[str] = ['https://www.googleapis.com/auth/gmail.modify']):
        logger.info(f"Initializing GmailService with creds file: {creds_file_path}")
        self.creds_file_path = creds_file_path
        self.token_path = token_path
        self.scopes = scopes
        self.token = self._get_token()
        self.service = self._get_service()
        self.user_email = self._get_user_email()
        logger.info(f"Gmail service initialized for: {self.user_email}")

    def _get_token(self) -> Credentials:
        """Get or refresh Google API token"""
        token = None
    
        if os.path.exists(self.token_path):
            try:
                token = Credentials.from_authorized_user_info(
                    json.loads(open(self.token_path).read()),
                    self.scopes
                )
            except Exception as e:
                logger.error(f"Error loading token: {str(e)}")
                
        # Get new token if needed
        if not token or not token.valid:
            if token and token.expired and token.refresh_token:
                token.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(self.creds_file_path, self.scopes)
                token = flow.run_local_server(port=0)
                
            # Save token
            with open(self.token_path, 'w') as token_file:
                token_file.write(token.to_json())
                
        return token

    def _get_service(self):
        """Initialize Gmail API service"""
        return build('gmail', 'v1', credentials=self.token)

    def _get_user_email(self) -> str:
        """Get user email address"""
        profile = self.service.users().getProfile(userId='me').execute()
        return profile['emailAddress']

    async def send_email(self, recipient_id: str, subject: str, message_content: str) -> dict:
        """Creates and sends an email message"""
        try:
            message = EmailMessage()
            message["To"] = recipient_id
            message["From"] = self.user_email
            message["Subject"] = subject
            message.set_content(message_content)

            # Encode message
            encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            create_message = {'raw': encoded_message}

            send_message = self.service.users().messages().send(userId="me", body=create_message).execute()
            return {"status": "success", "message_id": send_message['id']}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}

    async def open_email(self, email_id: str) -> dict:
        """Opens email in browser given ID."""
        try:
            email_url = f"https://mail.google.com/mail/u/0/#inbox/{email_id}"
            webbrowser.open(email_url)
            return {"status": "success", "message": f"Email opened in browser"}
        except Exception as e:
            return {"status": "error", "error_message": str(e)}

    async def get_unread_emails(self):
        """Retrieves unread messages from mailbox."""
        try:
            response = self.service.users().messages().list(userId="me", q='is:unread').execute()
            return response.get('messages', [])
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}

    async def read_email(self, email_id: str):
        """Retrieves email contents including metadata and body."""
        try:
            # Get the email in raw format
            msg = self.service.users().messages().get(userId="me", id=email_id, format='raw').execute()
            # Decode the email
            decoded_data = urlsafe_b64decode(msg['raw'])
            mime_message = message_from_bytes(decoded_data)
            
            # Extract the body
            body = ""
            if mime_message.is_multipart():
                for part in mime_message.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes):
                            # Get the correct charset from the Content-Type header
                            charset = part.get_content_charset(failobj='utf-8')
                            try:
                                body = payload.decode(charset)
                            except (UnicodeDecodeError, LookupError):
                                # Fallback to utf-8 with error replacement if charset detection fails
                                body = payload.decode('utf-8', errors='replace')
                        else:
                            body = str(payload)
                        break
            else:
                payload = mime_message.get_payload(decode=True)
                if isinstance(payload, bytes):
                    # Get the correct charset from the Content-Type header
                    charset = mime_message.get_content_charset(failobj='utf-8')
                    try:
                        body = payload.decode(charset)
                    except (UnicodeDecodeError, LookupError):
                        # Fallback to utf-8 with error replacement if charset detection fails
                        body = payload.decode('utf-8', errors='replace')
                else:
                    body = str(payload)
            
            # Mark email as read
            self.service.users().messages().modify(
                userId="me", id=email_id, body={'removeLabelIds': ['UNREAD']}
            ).execute()
            
            return {
                'subject': decode_mime_header(mime_message.get('subject', '')),
                'from': mime_message.get('from', ''),
                'to': mime_message.get('to', ''),
                'date': mime_message.get('date', ''),
                'content': body
            }
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
        
    async def trash_email(self, email_id: str):
        """Moves email to trash given ID."""
        try:
            self.service.users().messages().trash(userId="me", id=email_id).execute()
            return {"status": "success", "message": "Email moved to trash successfully"}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def create_draft(self, recipient_id: str, subject: str, message: str):
        """Creates a draft email message"""
        try:
            # Create the email message
            email_msg = EmailMessage()
            email_msg['To'] = recipient_id
            email_msg['From'] = self.user_email
            email_msg['Subject'] = subject
            email_msg.set_content(message)
            
            # Encode and create draft
            encoded_message = base64.urlsafe_b64encode(email_msg.as_bytes()).decode()
            draft = self.service.users().drafts().create(
                userId="me", 
                body={'message': {'raw': encoded_message}}
            ).execute()
            
            return {"status": "success", "draft_id": draft["id"]}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def list_drafts(self):
        """Lists all draft emails"""
        try:
            results = self.service.users().drafts().list(userId="me").execute()
            drafts = results.get('drafts', [])
            
            draft_list = []
            for draft in drafts:
                draft_data = self.service.users().drafts().get(
                    userId="me", id=draft['id']
                ).execute()
                
                headers = draft_data.get('message', {}).get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                to = next((h['value'] for h in headers if h['name'].lower() == 'to'), 'No Recipient')
                
                draft_list.append({
                    'id': draft['id'],
                    'subject': subject,
                    'to': to
                })
                
            return draft_list
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def list_labels(self):
        """Lists all labels in the user's mailbox"""
        try:
            results = self.service.users().labels().list(userId="me").execute()
            labels = results.get('labels', [])
            return [{'id': label['id'], 'name': label['name'], 'type': label['type']} 
                   for label in labels]
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def create_label(self, name: str):
        """Creates a new label"""
        try:
            label_object = {
                'name': name,
                'labelListVisibility': 'labelShow',
                'messageListVisibility': 'show'
            }
            
            created_label = self.service.users().labels().create(
                userId="me", body=label_object
            ).execute()
            
            return {
                'status': 'success',
                'label_id': created_label['id'],
                'name': created_label['name']
            }
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def apply_label(self, email_id: str, label_id: str):
        """Applies a label to an email"""
        try:
            self.service.users().messages().modify(
                userId="me", 
                id=email_id, 
                body={'addLabelIds': [label_id]}
            ).execute()
            return {"status": "success", "message": "Label applied successfully"}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def remove_label(self, email_id: str, label_id: str):
        """Removes a label from an email"""
        try:
            self.service.users().messages().modify(
                userId="me", 
                id=email_id, 
                body={'removeLabelIds': [label_id]}
            ).execute()
            return {"status": "success", "message": "Label removed successfully"}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def search_emails(self, query: str, max_results: int = 20):
        """Searches for emails using Gmail's search syntax"""
        try:
            results = self.service.users().messages().list(
                userId="me", q=query, maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            if not messages:
                return {"status": "success", "results": [], "message": "No emails found matching the query"}
            
            email_list = []
            for message in messages[:max_results]:
                msg_data = self.service.users().messages().get(
                    userId="me", id=message['id'], format="metadata"
                ).execute()
                
                headers = msg_data.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown')
                
                email_list.append({
                    'id': message['id'],
                    'subject': subject,
                    'from': sender
                })
            
            return {"status": "success", "results": email_list}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def get_filter(self, filter_id: str) -> dict | str:
        """Gets a specific filter by ID"""
        try:
            filter_data = await asyncio.to_thread(
                self.service.users().settings().filters().get(userId="me", id=filter_id).execute
            )
            return filter_data
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
    
    async def create_filter(self, 
                           from_email: str = None,
                           to_email: str = None,
                           subject: str = None,
                           query: str = None,
                           has_attachment: bool = None,
                           exclude_chats: bool = None,
                           size_comparison: str = None,
                           size: int = None,
                           add_label_ids: list[str] = None,
                           remove_label_ids: list[str] = None,
                           forward_to: str = None) -> dict | str:
        """Creates a new email filter
        
        Args:
            from_email: Email from a specific sender
            to_email: Email to a specific recipient
            subject: Email with a specific subject
            query: Email matching a custom query
            has_attachment: Email has an attachment
            exclude_chats: Exclude chat messages
            size_comparison: Size comparison operator (smaller, larger)
            size: Size in bytes
            add_label_ids: List of label IDs to add
            remove_label_ids: List of label IDs to remove
            forward_to: Forward email to a specific address
            
        Returns:
            Dictionary with status and filter information or error message
        """
        try:
            filter_object = {
                'criteria': {},
                'action': {}
            }
            # Criteria fields
            if from_email is not None:
                filter_object['criteria']['from'] = from_email
            if to_email is not None:
                filter_object['criteria']['to'] = to_email
            if subject is not None:
                filter_object['criteria']['subject'] = subject
            if query is not None:
                filter_object['criteria']['query'] = query
            if has_attachment is not None:
                filter_object['criteria']['hasAttachment'] = has_attachment
            if exclude_chats is not None:
                filter_object['criteria']['excludeChats'] = exclude_chats
            if size is not None:
                filter_object['criteria']['size'] = size
            if size_comparison is not None:
                filter_object['criteria']['sizeComparison'] = size_comparison
            # Action fields
            if add_label_ids is not None:
                filter_object['action']['addLabelIds'] = add_label_ids
            if remove_label_ids is not None:
                filter_object['action']['removeLabelIds'] = remove_label_ids
            if forward_to is not None:
                filter_object['action']['forward'] = forward_to
            created_filter = self.service.users().settings().filters().create(
                userId="me", body=filter_object
            ).execute()
            return {
                'status': 'success',
                'filter_id': created_filter['id'],
                'criteria': created_filter['criteria'],
                'action': created_filter['action']
            }
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
    
    async def get_filter(self, filter_id: str) -> dict | str:
        """Gets a specific filter by ID"""
        try:
            filter_data = await asyncio.to_thread(
                self.service.users().settings().filters().get(userId="me", id=filter_id).execute
            )
            return filter_data
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
    
    async def delete_filter(self, filter_id: str) -> str:
        """Deletes a filter"""
        try:
            await asyncio.to_thread(
                self.service.users().settings().filters().delete(
                    userId="me", 
                    id=filter_id
                ).execute
            )
            
            return f"Filter deleted successfully."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
    
    async def list_filters(self) -> list[dict] | dict:
        """Lists all filters for the user using Gmail API."""
        try:
            results = await asyncio.to_thread(
                self.service.users().settings().filters().list(userId="me").execute
            )
            filters = results.get('filter', [])
            return {"status": "success", "filters": filters}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}

    async def batch_modify_message_labels(self, ids: list[str], add_label_ids: list[str] = None, remove_label_ids: list[str] = None) -> dict:
        """Batch modify labels on up to 1000 messages."""
        try:
            if not ids or not isinstance(ids, list) or len(ids) == 0:
                return {"status": "error", "error_message": "'ids' must be a non-empty list of message IDs."}
            if len(ids) > 1000:
                return {"status": "error", "error_message": "Cannot modify more than 1000 messages at once."}
            body = {"ids": ids}
            if add_label_ids is not None:
                body["addLabelIds"] = add_label_ids
            if remove_label_ids is not None:
                body["removeLabelIds"] = remove_label_ids
            await asyncio.to_thread(
                self.service.users().messages().batchModify(userId="me", body=body).execute
            )
            return {"status": "success", "message": f"Batch modify completed for {len(ids)} messages."}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}
  
async def main(creds_file_path: str,
               token_path: str):
    
    gmail_service = GmailService(creds_file_path, token_path)
    server = Server("gmail")

    @server.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return list(PROMPTS.values())

    @server.get_prompt()
    async def get_prompt(
        name: str, arguments: dict[str, str] | None = None
    ) -> types.GetPromptResult:
        if name not in PROMPTS:
            raise ValueError(f"Prompt not found: {name}")

        if name == "manage-email":
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=EMAIL_ADMIN_PROMPTS,
                        )
                    )
                ]
            )

        if name == "draft-email":
            content = arguments.get("content", "")
            recipient = arguments.get("recipient", "")
            recipient_email = arguments.get("recipient_email", "")
            
            # First message asks the LLM to create the draft
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""Please draft an email about {content} for {recipient} ({recipient_email}).
                            Include a subject line starting with 'Subject:' on the first line.
                            Do not send the email yet, just draft it and ask the user for their thoughts."""
                        )
                    )
                ]
            )
        
        elif name == "edit-draft":
            changes = arguments.get("changes", "")
            current_draft = arguments.get("current_draft", "")
            
            # Edit existing draft based on requested changes
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""Please revise the current email draft:
                            {current_draft}
                            
                            Requested changes:
                            {changes}
                            
                            Please provide the updated draft."""
                        )
                    )
                ]
            )
        
        elif name == "manage-labels":
            action = arguments.get("action", "")
            
            # Guide the LLM on how to manage labels
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""I need help with managing my email labels. Specifically, I want to {action}.

Here are the tools you can use for label management:
- list-labels: Lists all existing labels in my Gmail account
- create-label: Creates a new label with a specified name
- apply-label: Applies a label to a specific email
- remove-label: Removes a label from a specific email
- rename-label: Renames an existing label
- delete-label: Permanently deletes a label
- search-by-label: Finds all emails with a specific label

Please help me {action} by using the appropriate tools. If you need to list labels first to get label IDs, please do so."""
                        )
                    )
                ]
            )

        elif name == "manage-filters":
            action = arguments.get("action", "")
            
            # Guide the LLM on how to manage filters
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""I need help with managing my email filters. Specifically, I want to {action}.

Here are the tools you can use for filter management:
- list-filters: Lists all existing filters in my Gmail account
- get-filter: Gets details of a specific filter
- create-filter: Creates a new filter
- delete-filter: Deletes a specific filter

Please help me {action} by using the appropriate tools. If you need to list filters first to get filter IDs, please do so."""
                        )
                    )
                ]
            )

        elif name == "search-emails":
            query = arguments.get("query", "")
            
            # Guide the LLM on how to search emails
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""I need to search through my emails for: {query}

Here are the tools you can use for searching emails:
- search-emails: Searches all emails using Gmail's search syntax
- get-unread-emails: Gets only unread emails from the inbox

Please help me find emails matching my search criteria. You can use Gmail's search syntax for advanced searches:
- from:sender - Emails from a specific sender
- to:recipient - Emails to a specific recipient
- subject:text - Emails with specific text in the subject
- has:attachment - Emails with attachments
- after:YYYY/MM/DD - Emails after a specific date
- before:YYYY/MM/DD - Emails before a specific date
- is:important - Important emails
- label:name - Emails with a specific label

Please search for emails matching: {query}"""
                        )
                    )
                ]
            )
            
        elif name == "manage-folders":
            action = arguments.get("action", "")
            
            # Guide the LLM on how to manage folders
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""I need help with managing my email folders. Specifically, I want to {action}.

Here are the tools you can use for folder management:
- list-folders: Lists all existing folders in my Gmail account
- create-folder: Creates a new folder with a specified name
- move-to-folder: Moves an email to a specific folder (removes it from inbox)

Please help me {action} by using the appropriate tools. If you need to list folders first to get folder IDs, please do so.

Note: In Gmail, folders are implemented as labels with special handling. When you move an email to a folder, it applies the folder's label and removes the email from the inbox."""
                        )
                    )
                ]
            )
            
        elif name == "manage-archive":
            action = arguments.get("action", "")
            
            # Guide the LLM on how to manage archives
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=f"""I need help with managing my email archives. Specifically, I want to {action}.

Here are the tools you can use for archive management:
- archive-email: Archives a single email (removes from inbox without deleting)
- batch-archive: Archives multiple emails matching a search query
- list-archived: Lists emails that have been archived
- restore-to-inbox: Restores an archived email back to the inbox

Please help me {action} by using the appropriate tools.

For batch archiving, you can use Gmail's search syntax to find emails to archive:
- from:sender - Emails from a specific sender
- older_than:30d - Emails older than 30 days
- has:attachment - Emails with attachments
- subject:text - Emails with specific text in the subject
- before:YYYY/MM/DD - Emails before a specific date

Note: Archiving in Gmail means removing the email from your inbox while keeping it accessible in "All Mail". It's a great way to declutter your inbox without losing any emails."""
                        )
                    )
                ]
            )

        raise ValueError("Prompt implementation not found")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="send-email",
                description="""Sends email to recipient. 
                Do not use if user only asked to draft email. 
                Drafts must be approved before sending.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "recipient_id": {
                            "type": "string",
                            "description": "Recipient email address",
                        },
                        "subject": {
                            "type": "string",
                            "description": "Email subject",
                        },
                        "message": {
                            "type": "string",
                            "description": "Email content text",
                        },
                    },
                    "required": ["recipient_id", "subject", "message"],
                },
            ),
            types.Tool(
                name="trash-email",
                description="""Moves email to trash. 
                Confirm before moving email to trash.""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="get-unread-emails",
                description="Retrieve unread emails",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="read-email",
                description="Retrieves given email content",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="mark-email-as-read",
                description="Marks given email as read",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="open-email",
                description="Open email in browser",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="create-draft",
                description="Creates a draft email without sending it",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "recipient_id": {
                            "type": "string",
                            "description": "Recipient email address",
                        },
                        "subject": {
                            "type": "string",
                            "description": "Email subject",
                        },
                        "message": {
                            "type": "string",
                            "description": "Email content text",
                        },
                    },
                    "required": ["recipient_id", "subject", "message"],
                },
            ),
            types.Tool(
                name="list-drafts",
                description="Lists all draft emails",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="list-labels",
                description="Lists all labels in the user's mailbox",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="create-label",
                description="Creates a new label",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Label name",
                        },
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="apply-label",
                description="Applies a label to an email",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                        "label_id": {
                            "type": "string",
                            "description": "Label ID",
                        },
                    },
                    "required": ["email_id", "label_id"],
                },
            ),
            types.Tool(
                name="remove-label",
                description="Removes a label from an email",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                        "label_id": {
                            "type": "string",
                            "description": "Label ID",
                        },
                    },
                    "required": ["email_id", "label_id"],
                },
            ),
            types.Tool(
                name="rename-label",
                description="Renames an existing label",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "label_id": {
                            "type": "string",
                            "description": "Label ID to rename",
                        },
                        "new_name": {
                            "type": "string",
                            "description": "New name for the label",
                        },
                    },
                    "required": ["label_id", "new_name"],
                },
            ),
            types.Tool(
                name="delete-label",
                description="Permanently deletes a label",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "label_id": {
                            "type": "string",
                            "description": "Label ID to delete",
                        },
                    },
                    "required": ["label_id"],
                },
            ),
            types.Tool(
                name="search-by-label",
                description="Searches for emails with a specific label",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "label_id": {
                            "type": "string",
                            "description": "Label ID",
                        },
                    },
                    "required": ["label_id"],
                },
            ),
            types.Tool(
                name="list-filters",
                description="Lists all email filters in the user's mailbox",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="get-filter",
                description="Gets details of a specific filter",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter_id": {
                            "type": "string",
                            "description": "Filter ID",
                        },
                    },
                    "required": ["filter_id"],
                },
            ),
            types.Tool(
                name="create-filter",
                description="Creates a new email filter",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "from_email": {
                            "type": "string",
                            "description": "Filter emails from this sender",
                        },
                        "to_email": {
                            "type": "string",
                            "description": "Filter emails to this recipient",
                        },
                        "subject": {
                            "type": "string",
                            "description": "Filter emails with this subject",
                        },
                        "query": {
                            "type": "string",
                            "description": "Filter emails matching this query",
                        },
                        "has_attachment": {
                            "type": "boolean",
                            "description": "Filter emails with attachments",
                        },
                        "exclude_chats": {
                            "type": "boolean",
                            "description": "Exclude chats from filter",
                        },
                        "size_comparison": {
                            "type": "string",
                            "description": "Size comparison ('larger' or 'smaller')",
                        },
                        "size": {
                            "type": "integer",
                            "description": "Size in bytes for comparison",
                        },
                        "add_label_ids": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "Labels to add to matching emails",
                        },
                        "remove_label_ids": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "Labels to remove from matching emails",
                        },
                        "forward_to": {
                            "type": "string",
                            "description": "Email address to forward matching emails to",
                        },
                    },
                },
            ),
            types.Tool(
                name="delete-filter",
                description="Deletes a specific filter",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter_id": {
                            "type": "string",
                            "description": "Filter ID",
                        },
                    },
                    "required": ["filter_id"],
                },
            ),
            types.Tool(
                name="search-emails",
                description="Searches for emails using Gmail's search syntax",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Gmail search query",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                        },
                    },
                    "required": ["query"],
                },
            ),
            types.Tool(
                name="create-folder",
                description="Creates a new folder",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Folder name",
                        },
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="move-to-folder",
                description="Moves an email to a folder",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID",
                        },
                        "folder_id": {
                            "type": "string",
                            "description": "Folder ID",
                        },
                    },
                    "required": ["email_id", "folder_id"],
                },
            ),
            types.Tool(
                name="list-folders",
                description="Lists all user-created folders",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="archive-email",
                description="Archives an email (removes from inbox without deleting)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID to archive",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="batch-archive",
                description="Archives multiple emails matching a search query",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Gmail search query to find emails to archive",
                        },
                        "max_emails": {
                            "type": "integer",
                            "description": "Maximum number of emails to archive (default: 100)",
                        },
                    },
                    "required": ["query"],
                },
            ),
            types.Tool(
                name="list-archived",
                description="Lists archived emails (not in inbox)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                        },
                    },
                    "required": [],
                },
            ),
            types.Tool(
                name="restore-to-inbox",
                description="Restores an archived email back to the inbox",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email_id": {
                            "type": "string",
                            "description": "Email ID to restore to inbox",
                        },
                    },
                    "required": ["email_id"],
                },
            ),
            types.Tool(
                name="batch-modify-message-labels",
                description="Batch modify labels on up to 1000 messages.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of message IDs to modify (max 1000)",
                        },
                        "add_label_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Label IDs to add to messages",
                        },
                        "remove_label_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Label IDs to remove from messages",
                        },
                    },
                    "required": ["ids"],
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        # Handle common error cases
        if not arguments:
            arguments = {}
            
        # Simplified core email operations handlers
        try:
            if name == "send-email":
                recipient = arguments.get("recipient_id")
                subject = arguments.get("subject", "")
                message = arguments.get("message", "")
                
                if not recipient:
                    raise ValueError("Missing recipient parameter")
                    
                result = await gmail_service.send_email(recipient, subject, message)
                return [types.TextContent(type="text", text=str(result))]

            elif name == "get-unread-emails":
                result = await gmail_service.get_unread_emails()
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]           
            elif name == "read-email":
                email_id = arguments.get("email_id")
                if not email_id:
                    raise ValueError("Missing email ID parameter")
                    
                result = await gmail_service.read_email(email_id)
                return [types.TextContent(type="text", text=str(result), artifact={"type": "dictionary", "data": result})]            
            elif name == "trash-email":
                email_id = arguments.get("email_id")
                if not email_id:
                    raise ValueError("Missing email ID parameter")
                    
                result = await gmail_service.trash_email(email_id)
                return [types.TextContent(type="text", text=str(result))]            
            elif name == "create-draft":
                recipient = arguments.get("recipient_id")
                subject = arguments.get("subject", "")
                message = arguments.get("message", "")
                
                if not recipient:
                    raise ValueError("Missing recipient parameter")
                    
                result = await gmail_service.create_draft(recipient, subject, message)
                return [types.TextContent(type="text", text=str(result))]
            elif name == "list-labels":
                result = await gmail_service.list_labels()
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]
                
            elif name == "create-label":
                name_arg = arguments.get("name")
                if not name_arg:
                    raise ValueError("Missing label name parameter")
                    
                result = await gmail_service.create_label(name_arg)
                return [types.TextContent(type="text", text=str(result))]
                
            elif name == "apply-label":
                email_id = arguments.get("email_id")
                label_id = arguments.get("label_id")
                
                if not email_id or not label_id:
                    raise ValueError("Missing email_id or label_id parameter")
                    
                result = await gmail_service.apply_label(email_id, label_id)
                return [types.TextContent(type="text", text=str(result))]
            elif name == "remove-label":
                email_id = arguments.get("email_id")
                label_id = arguments.get("label_id")
                
                if not email_id or not label_id:
                    raise ValueError("Missing email_id or label_id parameter")
                    
                result = await gmail_service.remove_label(email_id, label_id)
                return [types.TextContent(type="text", text=str(result))]
                
            elif name == "search-emails":
                query = arguments.get("query")
                max_results = arguments.get("max_results", 20)
                
                if not query:
                    raise ValueError("Missing search query parameter")
                    
                result = await gmail_service.search_emails(query, max_results)
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]
            
            elif name == "create-filter":
                # Map arguments to GmailService.create_filter
                result = await gmail_service.create_filter(
                    from_email=arguments.get("from_email"),
                    to_email=arguments.get("to_email"),
                    subject=arguments.get("subject"),
                    query=arguments.get("query"),
                    has_attachment=arguments.get("has_attachment"),
                    exclude_chats=arguments.get("exclude_chats"),
                    size_comparison=arguments.get("size_comparison"),
                    size=arguments.get("size"),
                    add_label_ids=arguments.get("add_label_ids"),
                    remove_label_ids=arguments.get("remove_label_ids"),
                    forward_to=arguments.get("forward_to")
                )
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]
            elif name == "batch-modify-message-labels":
                ids = arguments.get("ids")
                add_label_ids = arguments.get("add_label_ids")
                remove_label_ids = arguments.get("remove_label_ids")
                result = await gmail_service.batch_modify_message_labels(ids, add_label_ids, remove_label_ids)
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]
            elif name == "list-filters":
                result = await gmail_service.list_filters()
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]
            elif name == "search-by-label":
                label_id = arguments.get("label_id")
                if not label_id:
                    return [types.TextContent(type="text", text="Error: label_id is required for search-by-label.")]
                # Use Gmail's search syntax for label. Quotes are used for label IDs/names with special characters.
                query = f'label:"{label_id}"'
                result = await gmail_service.search_emails(query)
                return [types.TextContent(type="text", text=str(result), artifact={"type": "json", "data": result})]
            
            else:
                # For any other tools not explicitly handled (fewer to maintain)
                logger.warning(f"Tool {name} not in core set, might be unsupported")
                return [types.TextContent(type="text", text=f"The tool '{name}' is not supported in this simplified version")]
        except ValueError as e:
            # Handle missing parameter errors
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]
        except Exception as e:
            # Handle other errors
            logger.error(f"Error executing {name}: {str(e)}")
            return [types.TextContent(type="text", text=f"An error occurred: {str(e)}")]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="gmail",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Gmail API MCP Server')
    parser.add_argument('--creds-file-path',
                        required=True,
                       help='OAuth 2.0 credentials file path')
    parser.add_argument('--token-path',
                        required=True,
                       help='File location to store and retrieve access and refresh tokens for application')
    
    args = parser.parse_args()
    asyncio.run(main(args.creds_file_path, args.token_path))