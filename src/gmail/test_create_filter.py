#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#     "google-api-python-client>=2.0.0",
#     "google-auth-httplib2>=0.1.0",
#     "google-auth-oauthlib>=1.0.0",
#     "argparse>=1.4.0"
# ]
# ///

import argparse
import asyncio
from pathlib import Path

from gmail.server import GmailService

async def main():
    parser = argparse.ArgumentParser(description="Test GmailService.create_filter functionality.")
    parser.add_argument('--creds-file-path', default="/home/lysgaard/.gmail-mcp/credentials.json", help='Path to OAuth 2.0 credentials file')
    parser.add_argument('--token-path', default="/home/lysgaard/.gmail-mcp/tokens.json", help='Path to token file')
    parser.add_argument('--from-email', default=None, help='Filter: from email address')
    parser.add_argument('--subject', default=None, help='Filter: subject')
    parser.add_argument('--add-label-id', default=None, help='Label ID to add to matching emails')
    args = parser.parse_args()

    # Prepare filter arguments
    filter_kwargs = {}
    if args.from_email:
        filter_kwargs['from_email'] = args.from_email
    if args.subject:
        filter_kwargs['subject'] = args.subject
    if args.add_label_id:
        filter_kwargs['add_label_ids'] = [args.add_label_id]

    gmail = GmailService(args.creds_file_path, args.token_path)
    result = await gmail.create_filter(**filter_kwargs)
    print("Create filter result:")
    print(result)

if __name__ == "__main__":
    asyncio.run(main()) 