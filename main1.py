#!/usr/bin/env python3
# CIDR Scanner Bot v3.0 - Multi-Server | Multi-Profile | Fast Scanning
# Author: Custom Build for Advanced Scanning

import os
import sys
import json
import re
import uuid
import time
import asyncio
import aiohttp
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Any
from colorama import init, Fore, Style
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode

init(autoreset=True)

# === CONFIGURATION ===
BOT_TOKEN = "8919629019:AAHD2e7b5L7LKshB6-5lCVG5V0r1I__J5YQ"  # Replace with your bot token
ADMIN_IDS = [5889605682]       # Replace with your Telegram ID
PROFILES_FILE = "profiles.json"
SCANS_DIR = "scans"
os.makedirs(SCANS_DIR, exist_ok=True)

# === GLOBALS ===
scanning = False
current_scan = None

# === PROFILE MANAGEMENT ===

def load_profiles() -> dict:
    """Load profiles from JSON file"""
    if os.path.exists(PROFILES_FILE):
        with open(PROFILES_FILE, 'r') as f:
            return json.load(f)
    return {"profiles": {}, "active": None}

def save_profiles(data: dict):
    """Save profiles to JSON file"""
    with open(PROFILES_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_profile(profile_id: str) -> Optional[dict]:
    """Get profile by ID"""
    data = load_profiles()
    return data["profiles"].get(profile_id)

def get_active_profile() -> Optional[dict]:
    """Get active profile"""
    data = load_profiles()
    if data["active"]:
        return data["profiles"].get(data["active"])
    return None

def list_profiles() -> List[tuple]:
    """List all profiles with their IDs"""
    data = load_profiles()
    return [(pid, p["name"]) for pid, p in data["profiles"].items()]

def create_profile(profile_type: str, name: str, config: dict) -> str:
    """Create a new profile"""
    data = load_profiles()
    profile_id = f"{profile_type}_{int(time.time())}"
    data["profiles"][profile_id] = {
        "type": profile_type,
        "name": name,
        "config": config,
        "created": datetime.now().isoformat()
    }
    save_profiles(data)
    return profile_id

def delete_profile(profile_id: str) -> bool:
    """Delete a profile"""
    data = load_profiles()
    if profile_id in data["profiles"]:
        del data["profiles"][profile_id]
        if data["active"] == profile_id:
            data["active"] = None
        save_profiles(data)
        return True
    return False

def set_active_profile(profile_id: str) -> bool:
    """Set active profile"""
    data = load_profiles()
    if profile_id in data["profiles"]:
        data["active"] = profile_id
        save_profiles(data)
        return True
    return False

# === SCANNER ENGINE ===

async def scan_ip(session: aiohttp.ClientSession, ip: str, port: int, timeout: int = 5) -> dict:
    """Scan single IP:Port"""
    try:
        url = f"https://{ip}:{port}/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Connection': 'keep-alive'
        }
        async with session.get(url, headers=headers, ssl=False, timeout=timeout) as resp:
            status_code = resp.status
            status_text = resp.reason or "Unknown"
            return {
                'ip': ip,
                'port': port,
                'status': status_code,
                'status_text': status_text,
                'working': status_code in [101, 200],
                'type': 'VLESS' if status_code == 101 else 'HTTP' if status_code == 200 else 'Other'
            }
    except asyncio.TimeoutError:
        return {'ip': ip, 'port': port, 'status': 408, 'status_text': 'Timeout', 'working': False}
    except Exception:
        return {'ip': ip, 'port': port, 'status': 0, 'status_text': 'Error', 'working': False}

async def scan_cidr(cidr: str, ports: List[int], threads: int = 100, progress_callback=None) -> dict:
    """Scan CIDR range with multiple ports"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ips = [str(ip) for ip in network.hosts()]
        total = len(ips)
        results = []
        working_ips = []
        
        semaphore = asyncio.Semaphore(threads)
        
        async def scan_with_semaphore(session, ip, port):
            async with semaphore:
                return await scan_ip(session, ip, port)
        
        async with aiohttp.ClientSession() as session:
            for idx, ip in enumerate(ips):
                if progress_callback and idx % 50 == 0:
                    await progress_callback(idx, total, len(working_ips))
                
                for port in ports:
                    result = await scan_with_semaphore(session, ip, port)
                    results.append(result)
                    if result['working']:
                        working_ips.append(result)
        
        if progress_callback:
            await progress_callback(total, total, len(working_ips))
        
        return {
            'total': total,
            'scanned': len(results),
            'working': len(working_ips),
            'results': results,
            'working_ips': working_ips
        }
    except Exception as e:
        return {'error': str(e)}

def generate_vless_config(ip: str, port: int, uuid_str: str, path: str, header_host: str) -> str:
    """Generate VLESS config"""
    return f"vless://{uuid_str}@{ip}:{port}?encryption=none&security=insecure&type=tcp&headerType=none&path={path}&host={header_host}#Scan_{ip}"

def generate_vmess_config(ip: str, port: int, uuid_str: str, path: str, header_host: str) -> str:
    """Generate VMess config"""
    config = {
        "v": "2",
        "ps": f"Scan_{ip}",
        "add": ip,
        "port": port,
        "id": uuid_str,
        "aid": "0",
        "net": "tcp",
        "type": "none",
        "host": header_host,
        "path": path,
        "tls": "none"
    }
    import base64
    return f"vmess://{base64.b64encode(json.dumps(config).encode()).decode()}"

def generate_trojan_config(ip: str, port: int, password: str, sni: str) -> str:
    """Generate Trojan config"""
    return f"trojan://{password}@{ip}:{port}?security=tls&sni={sni}#Scan_{ip}"

def save_scan_results(results: dict, cidr: str, ports: List[int]) -> str:
    """Save scan results to TXT file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    cidr_clean = cidr.replace('/', '_')
    ports_str = '_'.join(str(p) for p in ports)
    filename = f"{SCANS_DIR}/{cidr_clean}_{ports_str}_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("="*50 + "\n")
        f.write("CIDR SCAN RESULTS\n")
        f.write("="*50 + "\n")
        f.write(f"CIDR: {cidr}\n")
        f.write(f"Ports: {', '.join(str(p) for p in ports)}\n")
        f.write(f"Total IPs: {results['total']}\n")
        f.write(f"Working IPs: {results['working']}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("="*50 + "\n\n")
        
        # VLESS/VMess Ready (101)
        vless_ips = [r for r in results['working_ips'] if r['status'] == 101]
        if vless_ips:
            f.write("=== VLESS/VMess Ready (101 Switching Protocols) ===\n\n")
            for r in vless_ips:
                f.write(f"IP: {r['ip']}\n")
                f.write(f"Port: {r['port']}\n")
                f.write(f"Status: {r['status']} {r['status_text']}\n")
                profile = get_active_profile()
                if profile:
                    config = profile.get('config', {})
                    if profile['type'] == 'vless':
                        f.write(f"Config: {generate_vless_config(r['ip'], r['port'], config.get('uuid', str(uuid.uuid4())), config.get('path', '/vless'), config.get('header_host', ''))}\n")
                    elif profile['type'] == 'vmess':
                        f.write(f"Config: {generate_vmess_config(r['ip'], r['port'], config.get('uuid', str(uuid.uuid4())), config.get('path', '/vmess'), config.get('header_host', ''))}\n")
                f.write("\n")
        
        # HTTP Working (200)
        http_ips = [r for r in results['working_ips'] if r['status'] == 200]
        if http_ips:
            f.write("=== HTTP/HTTPS Working (200 OK) ===\n\n")
            for r in http_ips:
                f.write(f"IP: {r['ip']}\n")
                f.write(f"Port: {r['port']}\n")
                f.write(f"Status: {r['status']} {r['status_text']}\n\n")
        
        # Other Status Codes
        other_ips = [r for r in results['results'] if r['status'] not in [101, 200] and r['status'] > 0]
        if other_ips:
            f.write("=== Other Status Codes ===\n\n")
            for r in other_ips:
                status_icon = "⚠️" if r['status'] in [301, 302, 401, 403] else "❌"
                f.write(f"{status_icon} IP: {r['ip']}:{r['port']} — {r['status']} {r['status_text']}\n")
    
    return filename

# === TELEGRAM BOT HANDLERS ===

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    keyboard = [
        [InlineKeyboardButton("🆕 Create Profile", callback_data='create_profile')],
        [InlineKeyboardButton("📋 My Profiles", callback_data='list_profiles')],
        [InlineKeyboardButton("🔍 Start Scan", callback_data='start_scan')],
        [InlineKeyboardButton("📊 Status", callback_data='status')],
        [InlineKeyboardButton("❓ Help", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    active = get_active_profile()
    active_text = f"✅ Active: {active['name']}" if active else "❌ No active profile"
    
    await update.message.reply_text(
        f"🔥 *CIDR Scanner Bot v3.0*\n\n"
        f"📌 {active_text}\n\n"
        f"🔧 *Commands:*\n"
        f"/start — Main menu\n"
        f"/profile — Manage profiles\n"
        f"/scan — Start scan\n"
        f"/status — Bot status\n"
        f"/help — Help\n\n"
        f"Select an option:",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN
    )

async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Profile management"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    keyboard = [
        [InlineKeyboardButton("🆕 Create Profile", callback_data='create_profile')],
        [InlineKeyboardButton("📋 List Profiles", callback_data='list_profiles')],
        [InlineKeyboardButton("🔄 Switch Profile", callback_data='switch_profile')],
        [InlineKeyboardButton("🗑️ Delete Profile", callback_data='delete_profile')],
        [InlineKeyboardButton("🔙 Back", callback_data='back_main')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "📋 *Profile Management*\n\n"
        "Select an option:",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start scan command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    global scanning
    if scanning:
        await update.message.reply_text("⏳ *A scan is already in progress!*", parse_mode=ParseMode.MARKDOWN)
        return
    
    active = get_active_profile()
    if not active:
        await update.message.reply_text(
            "❌ *No active profile found!*\n"
            "Create a profile first using /profile",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    context.user_data['scan_step'] = 'cidr'
    await update.message.reply_text(
        f"🔍 *Starting Scan*\n\n"
        f"📌 Active Profile: *{active['name']}*\n\n"
        f"Step 1: Enter *CIDR range*\n"
        f"Example: `56.228.0.0/16`\n\n"
        f"Or /cancel to abort.",
        parse_mode=ParseMode.MARKDOWN
    )

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Status command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    active = get_active_profile()
    profiles = list_profiles()
    
    status = f"📊 *Bot Status*\n\n"
    status += f"✅ *Running*\n"
    status += f"🔍 *Scanning:* {'Yes' if scanning else 'No'}\n"
    status += f"📁 *Profiles:* {len(profiles)}\n"
    status += f"📌 *Active:* {active['name'] if active else 'None'}\n"
    status += f"📂 *Scans Folder:* {SCANS_DIR}\n"
    
    # Count files
    files = os.listdir(SCANS_DIR) if os.path.exists(SCANS_DIR) else []
    status += f"📄 *Results Files:* {len(files)}\n"
    
    await update.message.reply_text(status, parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    help_text = f"""
📚 *CIDR Scanner Bot Help*

🔹 *Commands:*
• /start — Main menu
• /profile — Manage profiles
• /scan — Start CIDR scan
• /status — Bot status
• /help — Help
• /cancel — Cancel scan

🔹 *Profile Types:*
• SSH — SSH proxy config
• VLESS — VLESS proxy config
• VMess — VMess proxy config
• Trojan — Trojan proxy config

🔹 *Scan Flow:*
1. Create/Select profile
2. Enter CIDR (e.g., 56.228.0.0/16)
3. Select ports (default: 80,443)
4. Enter threads (default: 100)
5. Scan runs → Results shown

🔹 *Output:*
• TXT file with all results
• Auto-generated configs for 101 IPs
• Download via Telegram
"""
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel ongoing operation"""
    global scanning
    scanning = False
    context.user_data.clear()
    await update.message.reply_text("❌ *Cancelled.*", parse_mode=ParseMode.MARKDOWN)

# === CALLBACK HANDLERS ===

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button clicks"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await query.edit_message_text("🚫 Unauthorized.")
        return
    
    data = query.data
    
    if data == 'back_main':
        await start(update, context)
        return
    
    if data == 'create_profile':
        keyboard = [
            [InlineKeyboardButton("🔧 SSH", callback_data='create_ssh')],
            [InlineKeyboardButton("🌐 VLESS", callback_data='create_vless')],
            [InlineKeyboardButton("🌐 VMess", callback_data='create_vmess')],
            [InlineKeyboardButton("🔒 Trojan", callback_data='create_trojan')],
            [InlineKeyboardButton("🔙 Back", callback_data='back_main')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "🆕 *Create Profile*\n\n"
            "Select server type:",
            reply_markup=reply_markup,
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    if data.startswith('create_'):
        profile_type = data.split('_')[1]
        context.user_data['profile_type'] = profile_type
        context.user_data['profile_step'] = 'name'
        await query.edit_message_text(
            f"🆕 *Creating {profile_type.upper()} Profile*\n\n"
            "Enter profile name:",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    if data == 'list_profiles':
        profiles = list_profiles()
        if not profiles:
            await query.edit_message_text("📋 *No profiles found.*\n\nCreate one using 'Create Profile'.", parse_mode=ParseMode.MARKDOWN)
            return
        
        text = "📋 *Your Profiles*\n\n"
        active = get_active_profile()
        for pid, name in profiles:
            is_active = "✅" if active and active.get('name') == name else "⬜"
            text += f"{is_active} `{name}`\n"
        
        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='back_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)
        return
    
    if data == 'switch_profile':
        profiles = list_profiles()
        if not profiles:
            await query.edit_message_text("📋 *No profiles found.*", parse_mode=ParseMode.MARKDOWN)
            return
        
        keyboard = []
        for pid, name in profiles:
            keyboard.append([InlineKeyboardButton(f"🔄 {name}", callback_data=f'switch_{pid}')])
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='back_main')])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "🔄 *Switch Profile*\n\n"
            "Select profile:",
            reply_markup=reply_markup,
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    if data.startswith('switch_'):
        pid = data.split('_')[1]
        if set_active_profile(pid):
            await query.edit_message_text(f"✅ *Profile switched successfully!*", parse_mode=ParseMode.MARKDOWN)
        else:
            await query.edit_message_text("❌ *Failed to switch profile.*", parse_mode=ParseMode.MARKDOWN)
        return
    
    if data == 'delete_profile':
        profiles = list_profiles()
        if not profiles:
            await query.edit_message_text("📋 *No profiles found.*", parse_mode=ParseMode.MARKDOWN)
            return
        
        keyboard = []
        for pid, name in profiles:
            keyboard.append([InlineKeyboardButton(f"🗑️ {name}", callback_data=f'delete_{pid}')])
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='back_main')])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "🗑️ *Delete Profile*\n\n"
            "Select profile to delete:",
            reply_markup=reply_markup,
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    if data.startswith('delete_'):
        pid = data.split('_')[1]
        if delete_profile(pid):
            await query.edit_message_text(f"✅ *Profile deleted successfully!*", parse_mode=ParseMode.MARKDOWN)
        else:
            await query.edit_message_text("❌ *Failed to delete profile.*", parse_mode=ParseMode.MARKDOWN)
        return
    
    if data == 'start_scan':
        await scan_command(update, context)
        return
    
    if data == 'status':
        await status_command(update, context)
        return
    
    if data == 'help':
        await help_command(update, context)
        return

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    text = update.message.text.strip()
    
    # Profile creation flow
    if 'profile_step' in context.user_data:
        step = context.user_data['profile_step']
        profile_type = context.user_data.get('profile_type')
        
        if step == 'name':
            context.user_data['profile_name'] = text
            context.user_data['profile_step'] = 'config'
            
            if profile_type in ['vless', 'vmess']:
                await update.message.reply_text("Enter *UUID* (or press enter for auto-generate):", parse_mode=ParseMode.MARKDOWN)
            elif profile_type == 'ssh':
                await update.message.reply_text("Enter *SSH Host:*", parse_mode=ParseMode.MARKDOWN)
            elif profile_type == 'trojan':
                await update.message.reply_text("Enter *Host:*", parse_mode=ParseMode.MARKDOWN)
            return
        
        elif step == 'config':
            config = {}
            if profile_type in ['vless', 'vmess']:
                if text:
                    config['uuid'] = text
                else:
                    config['uuid'] = str(uuid.uuid4())
                await update.message.reply_text(f"UUID: `{config['uuid']}`\n\nEnter *Path* (e.g., /vless):", parse_mode=ParseMode.MARKDOWN)
                context.user_data['profile_step'] = 'path'
                context.user_data['config'] = config
                return
            
            elif profile_type == 'ssh':
                config['host'] = text
                await update.message.reply_text("Enter *Port* (default: 22):", parse_mode=ParseMode.MARKDOWN)
                context.user_data['profile_step'] = 'ssh_port'
                context.user_data['config'] = config
                return
            
            elif profile_type == 'trojan':
                config['host'] = text
                await update.message.reply_text("Enter *Port* (default: 443):", parse_mode=ParseMode.MARKDOWN)
                context.user_data['profile_step'] = 'trojan_port'
                context.user_data['config'] = config
                return
        
        elif step == 'path':
            config = context.user_data.get('config', {})
            config['path'] = text
            await update.message.reply_text("Enter *Header Host* (Bug Host):")
            context.user_data['profile_step'] = 'header_host'
            context.user_data['config'] = config
            return
        
        elif step == 'header_host':
            config = context.user_data.get('config', {})
            config['header_host'] = text
            await update.message.reply_text("Enter *SNI* (optional, press enter to skip):")
            context.user_data['profile_step'] = 'sni'
            context.user_data['config'] = config
            return
        
        elif step == 'sni':
            config = context.user_data.get('config', {})
            if text:
                config['sni'] = text
            else:
                config['sni'] = ''
            
            # Save profile
            profile_type = context.user_data.get('profile_type')
            profile_name = context.user_data.get('profile_name')
            profile_id = create_profile(profile_type, profile_name, config)
            
            context.user_data.clear()
            await update.message.reply_text(
                f"✅ *Profile '{profile_name}' created successfully!*\n\n"
                f"Profile ID: `{profile_id}`\n"
                f"Type: {profile_type.upper()}\n"
                f"UUID: `{config.get('uuid', 'N/A')}`\n"
                f"Path: `{config.get('path', 'N/A')}`\n"
                f"Header Host: `{config.get('header_host', 'N/A')}`\n\n"
                f"Switch to this profile?",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Yes", callback_data=f'switch_{profile_id}')],
                    [InlineKeyboardButton("❌ No", callback_data='back_main')]
                ]),
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        elif step == 'ssh_port':
            config = context.user_data.get('config', {})
            config['port'] = int(text) if text else 22
            await update.message.reply_text("Enter *SSH User:*")
            context.user_data['profile_step'] = 'ssh_user'
            context.user_data['config'] = config
            return
        
        elif step == 'ssh_user':
            config = context.user_data.get('config', {})
            config['username'] = text
            await update.message.reply_text("Enter *SSH Password:*")
            context.user_data['profile_step'] = 'ssh_pass'
            context.user_data['config'] = config
            return
        
        elif step == 'ssh_pass':
            config = context.user_data.get('config', {})
            config['password'] = text
            await update.message.reply_text("Enter *HTTP Payload* (press enter for default):")
            context.user_data['profile_step'] = 'ssh_payload'
            context.user_data['config'] = config
            return
        
        elif step == 'ssh_payload':
            config = context.user_data.get('config', {})
            if text:
                config['payload'] = text
            else:
                config['payload'] = 'GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: websocket://127.0.0.1:8080'
            
            profile_type = context.user_data.get('profile_type')
            profile_name = context.user_data.get('profile_name')
            profile_id = create_profile(profile_type, profile_name, config)
            
            context.user_data.clear()
            await update.message.reply_text(
                f"✅ *Profile '{profile_name}' created successfully!*\n\n"
                f"Switch to this profile?",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Yes", callback_data=f'switch_{profile_id}')],
                    [InlineKeyboardButton("❌ No", callback_data='back_main')]
                ]),
                parse_mode=ParseMode.MARKDOWN
            )
            return
        
        elif step == 'trojan_port':
            config = context.user_data.get('config', {})
            config['port'] = int(text) if text else 443
            await update.message.reply_text("Enter *Password:*")
            context.user_data['profile_step'] = 'trojan_pass'
            context.user_data['config'] = config
            return
        
        elif step == 'trojan_pass':
            config = context.user_data.get('config', {})
            config['password'] = text
            await update.message.reply_text("Enter *SNI* (optional, press enter to skip):")
            context.user_data['profile_step'] = 'trojan_sni'
            context.user_data['config'] = config
            return
        
        elif step == 'trojan_sni':
            config = context.user_data.get('config', {})
            if text:
                config['sni'] = text
            else:
                config['sni'] = ''
            
            profile_type = context.user_data.get('profile_type')
            profile_name = context.user_data.get('profile_name')
            profile_id = create_profile(profile_type, profile_name, config)
            
            context.user_data.clear()
            await update.message.reply_text(
                f"✅ *Profile '{profile_name}' created successfully!*\n\n"
                f"Switch to this profile?",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Yes", callback_data=f'switch_{profile_id}')],
                    [InlineKeyboardButton("❌ No", callback_data='back_main')]
                ]),
                parse_mode=ParseMode.MARKDOWN
            )
            return
    
    # Scan flow
    if 'scan_step' in context.user_data:
        step = context.user_data['scan_step']
        
        if step == 'cidr':
            try:
                ipaddress.ip_network(text, strict=False)
                context.user_data['cidr'] = text
                context.user_data['scan_step'] = 'ports'
                await update.message.reply_text(
                    f"📌 *CIDR:* `{text}`\n\n"
                    "Step 2: Select *Ports*\n"
                    "1. Default (80,443)\n"
                    "2. Custom (e.g., 80,443,8080)\n"
                    "3. Single (e.g., 443)\n\n"
                    "Enter ports (comma-separated):",
                    parse_mode=ParseMode.MARKDOWN
                )
            except:
                await update.message.reply_text("❌ *Invalid CIDR format.*\nTry again:", parse_mode=ParseMode.MARKDOWN)
            return
        
        elif step == 'ports':
            try:
                if ',' in text:
                    ports = [int(p.strip()) for p in text.split(',') if p.strip()]
                else:
                    ports = [int(text.strip())]
                
                if not ports or any(p < 1 or p > 65535 for p in ports):
                    await update.message.reply_text("❌ *Invalid ports.*\nTry again:", parse_mode=ParseMode.MARKDOWN)
                    return
                
                context.user_data['ports'] = ports
                context.user_data['scan_step'] = 'threads'
                await update.message.reply_text(
                    f"📌 *Ports:* `{', '.join(str(p) for p in ports)}`\n\n"
                    "Step 3: Enter *Threads* (default: 100, range: 10-500):",
                    parse_mode=ParseMode.MARKDOWN
                )
            except:
                await update.message.reply_text("❌ *Invalid ports.*\nTry again:", parse_mode=ParseMode.MARKDOWN)
            return
        
        elif step == 'threads':
            try:
                threads = int(text)
                if threads < 10:
                    threads = 100
                elif threads > 500:
                    threads = 500
                
                context.user_data['threads'] = threads
                context.user_data['scan_step'] = None
                
                # Start scan
                await start_scan(update, context)
                return
            except:
                await update.message.reply_text("❌ *Invalid threads.*\nTry again:", parse_mode=ParseMode.MARKDOWN)
            return

async def start_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start the actual scan"""
    global scanning
    if scanning:
        await update.message.reply_text("⏳ *A scan is already in progress!*", parse_mode=ParseMode.MARKDOWN)
        return
    
    cidr = context.user_data.get('cidr')
    ports = context.user_data.get('ports')
    threads = context.user_data.get('threads', 100)
    
    if not cidr or not ports:
        await update.message.reply_text("❌ *Scan configuration missing.*\nStart again with /scan", parse_mode=ParseMode.MARKDOWN)
        return
    
    scanning = True
    msg = await update.message.reply_text(
        f"🔍 *Scanning CIDR:* `{cidr}`\n"
        f"🔌 *Ports:* `{', '.join(str(p) for p in ports)}`\n"
        f"⚡ *Threads:* `{threads}`\n"
        f"⏳ *Scanning...*",
        parse_mode=ParseMode.MARKDOWN
    )
    
    try:
        # Progress callback
        async def progress(current, total, working):
            if current % 500 == 0 or current == total:
                try:
                    await msg.edit_text(
                        f"🔍 *Scanning CIDR:* `{cidr}`\n"
                        f"🔌 *Ports:* `{', '.join(str(p) for p in ports)}`\n"
                        f"⚡ *Threads:* `{threads}`\n"
                        f"📊 *Progress:* `{current}/{total}`\n"
                        f"✅ *Working:* `{working}`\n"
                        f"⏳ *Scanning...*",
                        parse_mode=ParseMode.MARKDOWN
                    )
                except:
                    pass
        
        # Run scan
        results = await scan_cidr(cidr, ports, threads, progress)
        
        if 'error' in results:
            await msg.edit_text(f"❌ *Error:* {results['error']}", parse_mode=ParseMode.MARKDOWN)
            return
        
        # Save results
        filename = save_scan_results(results, cidr, ports)
        
        # Build response
        response = f"✅ *Scan Complete!*\n\n"
        response += f"📌 *CIDR:* `{cidr}`\n"
        response += f"🔌 *Ports:* `{', '.join(str(p) for p in ports)}`\n"
        response += f"🌐 *Total IPs:* `{results['total']}`\n"
        response += f"✅ *Working IPs:* `{results['working']}`\n\n"
        
        # Show working IPs
        if results['working_ips']:
            response += "*Working IPs:*\n"
            vless_ips = [r for r in results['working_ips'] if r['status'] == 101]
            http_ips = [r for r in results['working_ips'] if r['status'] == 200]
            
            if vless_ips:
                response += f"\n🔥 *VLESS/VMess Ready (101):*\n"
                for r in vless_ips[:5]:
                    response += f"✅ `{r['ip']}:{r['port']}` — 101 Switching Protocols\n"
                if len(vless_ips) > 5:
                    response += f"• ... and {len(vless_ips)-5} more\n"
            
            if http_ips:
                response += f"\n🌐 *HTTP/HTTPS Working (200):*\n"
                for r in http_ips[:5]:
                    response += f"✅ `{r['ip']}:{r['port']}` — 200 OK\n"
                if len(http_ips) > 5:
                    response += f"• ... and {len(http_ips)-5} more\n"
        
        await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
        
        # Send file
        with open(filename, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=os.path.basename(filename),
                caption=f"📁 *Scan Results:* `{cidr}`\nWorking: {results['working']}"
            )
        
    except Exception as e:
        await msg.edit_text(f"❌ *Error:* {str(e)}", parse_mode=ParseMode.MARKDOWN)
    finally:
        scanning = False
        context.user_data.clear()

# === MAIN ===

def main():
    print(f"{Fore.GREEN}[✓] Starting CIDR Scanner Bot...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Bot Token: {BOT_TOKEN[:10]}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Admin IDs: {ADMIN_IDS}{Style.RESET_ALL}")
    
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("profile", profile_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("cancel", cancel_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    
    print(f"{Fore.GREEN}[✓] Bot is running!{Style.RESET_ALL}")
    app.run_polling()

if __name__ == "__main__":
    main()
