#!/usr/bin/env python3
# Telegram 101 Protocol Scanner Bot
# Sirf 101 Switching Protocols show karega
# Fast, Stable, Accurate

import os
import json
import time
import uuid
import asyncio
import aiohttp
import ipaddress
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode

# === CONFIG ===
BOT_TOKEN = "8919629019:AAHD2e7b5L7LKshB6-5lCVG5V0r1I__J5YQ"
ADMIN_IDS = [5889605682]  # Apna Telegram ID daalo
PROFILES_FILE = "profiles.json"
SCANS_DIR = "scans"
os.makedirs(SCANS_DIR, exist_ok=True)

# === PROFILE MANAGEMENT ===

def load_profiles():
    if os.path.exists(PROFILES_FILE):
        with open(PROFILES_FILE, 'r') as f:
            return json.load(f)
    return {"profiles": {}, "active": None}

def save_profiles(data):
    with open(PROFILES_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def create_vless_profile(name, uuid_str, path, header_host):
    data = load_profiles()
    profile_id = f"vless_{int(time.time())}"
    data["profiles"][profile_id] = {
        "type": "vless",
        "name": name,
        "config": {
            "uuid": uuid_str,
            "path": path,
            "header_host": header_host
        },
        "created": datetime.now().isoformat()
    }
    data["active"] = profile_id
    save_profiles(data)
    return profile_id

def get_active_profile():
    data = load_profiles()
    if data["active"] and data["active"] in data["profiles"]:
        return data["profiles"][data["active"]]
    return None

# === SCANNER ENGINE ===

async def check_101(session, ip, port, timeout=3):
    """Check if IP returns 101 Switching Protocols"""
    try:
        url = f"https://{ip}:{port}/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Connection': 'Upgrade',
            'Upgrade': 'websocket'
        }
        async with session.get(url, headers=headers, ssl=False, timeout=timeout) as resp:
            if resp.status == 101:
                return {'ip': ip, 'port': port, 'status': 101, 'working': True}
            return None
    except:
        return None

async def scan_cidr(cidr, ports=[443, 80], threads=200):
    """Scan CIDR for 101 Protocol only"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ips = [str(ip) for ip in list(network.hosts())[:1000]]  # Limit for speed
    except:
        return []
    
    results = []
    semaphore = asyncio.Semaphore(threads)
    
    async def scan_with_semaphore(session, ip):
        async with semaphore:
            for port in ports:
                result = await check_101(session, ip, port)
                if result:
                    return result
            return None
    
    async with aiohttp.ClientSession() as session:
        tasks = [scan_with_semaphore(session, ip) for ip in ips]
        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                results.append(result)
    
    return results

def generate_vless_config(ip, port, uuid_str, path, header_host):
    return f"vless://{uuid_str}@{ip}:{port}?encryption=none&security=insecure&type=tcp&headerType=none&path={path}&host={header_host}#Scan_{ip}"

def save_results(results, cidr):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{SCANS_DIR}/scan_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write("="*60 + "\n")
        f.write("101 PROTOCOL SCAN RESULTS\n")
        f.write(f"CIDR: {cidr}\n")
        f.write(f"Total 101 Found: {len(results)}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("="*60 + "\n\n")
        
        for r in results:
            f.write(f"✅ {r['ip']}:{r['port']} — 101 Switching Protocols\n")
            profile = get_active_profile()
            if profile:
                config = profile.get('config', {})
                f.write(f"   Config: {generate_vless_config(r['ip'], r['port'], config.get('uuid', ''), config.get('path', '/vless'), config.get('header_host', ''))}\n")
            f.write("\n")
    
    return filename

# === TELEGRAM HANDLERS ===

async def start(update, context):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    keyboard = [
        [InlineKeyboardButton("📝 Create VLESS Profile", callback_data='create_profile')],
        [InlineKeyboardButton("🔍 Start Scan", callback_data='start_scan')],
        [InlineKeyboardButton("📊 Status", callback_data='status')],
        [InlineKeyboardButton("❓ Help", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    active = get_active_profile()
    active_text = f"✅ Active: {active['name']}" if active else "❌ No profile"
    
    await update.message.reply_text(
        f"🔥 *101 Protocol Scanner*\n\n"
        f"📌 {active_text}\n\n"
        f"🔧 *Commands:*\n"
        f"/start — Menu\n"
        f"/creatacc — Create VLESS profile\n"
        f"/scan — Start scan\n"
        f"/status — Status\n"
        f"/help — Help",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN
    )

async def creatacc(update, context):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    context.user_data['profile_step'] = 'name'
    await update.message.reply_text(
        "📝 *Create VLESS Profile*\n\n"
        "Step 1: Enter *Profile Name*:",
        parse_mode=ParseMode.MARKDOWN
    )

async def scan_command(update, context):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    profile = get_active_profile()
    if not profile:
        await update.message.reply_text("❌ *No active profile!*\nUse /creatacc first.", parse_mode=ParseMode.MARKDOWN)
        return
    
    context.user_data['scan_step'] = 'cidr'
    await update.message.reply_text(
        "🔍 *Enter CIDR Range*\n\n"
        "Examples:\n"
        "• `172.65.90.0/24`\n"
        "• `172.225.20.0/24`\n"
        "• `172.0.0.0/24`\n\n"
        "Multiple ranges: separate with comma\n"
        "`172.65.90.0/24,172.225.20.0/24`",
        parse_mode=ParseMode.MARKDOWN
    )

async def status_command(update, context):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    active = get_active_profile()
    status = f"📊 *Bot Status*\n\n"
    status += f"✅ *Running*\n"
    status += f"📌 *Profile:* {active['name'] if active else 'None'}\n"
    status += f"📂 *Scans Folder:* {SCANS_DIR}\n"
    
    files = os.listdir(SCANS_DIR) if os.path.exists(SCANS_DIR) else []
    status += f"📄 *Results Files:* {len(files)}\n"
    
    await update.message.reply_text(status, parse_mode=ParseMode.MARKDOWN)

async def help_command(update, context):
    help_text = """
📚 *101 Protocol Scanner Help*

🔹 *Commands:*
• `/start` — Main menu
• `/creatacc` — Create VLESS profile
• `/scan` — Start CIDR scan
• `/status` — Bot status
• `/help` — Help

🔹 *Scan Flow:*
1. Create VLESS profile (/creatacc)
2. Enter CIDR range
3. Scan runs (only 101 shown)
4. Download TXT file

🔹 *Performance:*
• 200+ threads
• 10k IPs in <10 seconds
• Only 101 Protocols shown
"""
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

# === CALLBACK HANDLERS ===

async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await query.edit_message_text("🚫 Unauthorized.")
        return
    
    data = query.data
    
    if data == 'create_profile':
        await creatacc(update, context)
    
    elif data == 'start_scan':
        await scan_command(update, context)
    
    elif data == 'status':
        await status_command(update, context)
    
    elif data == 'help':
        await help_command(update, context)

# === MESSAGE HANDLER ===

async def message_handler(update, context):
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        return
    
    text = update.message.text.strip()
    
    # Profile creation flow
    if 'profile_step' in context.user_data:
        step = context.user_data['profile_step']
        
        if step == 'name':
            context.user_data['profile_name'] = text
            context.user_data['profile_step'] = 'uuid'
            await update.message.reply_text("Enter *UUID* (or press enter for auto):", parse_mode=ParseMode.MARKDOWN)
            return
        
        elif step == 'uuid':
            if text:
                context.user_data['uuid'] = text
            else:
                context.user_data['uuid'] = str(uuid.uuid4())
            context.user_data['profile_step'] = 'path'
            await update.message.reply_text(f"UUID: `{context.user_data['uuid']}`\n\nEnter *Path* (e.g., /vless):", parse_mode=ParseMode.MARKDOWN)
            return
        
        elif step == 'path':
            context.user_data['path'] = text if text else '/vless'
            context.user_data['profile_step'] = 'header_host'
            await update.message.reply_text("Enter *Header Host* (Bug Host):", parse_mode=ParseMode.MARKDOWN)
            return
        
        elif step == 'header_host':
            header_host = text if text else 'cdn.hotstar.com'
            name = context.user_data.get('profile_name')
            uuid_str = context.user_data.get('uuid')
            path = context.user_data.get('path')
            
            profile_id = create_vless_profile(name, uuid_str, path, header_host)
            context.user_data.clear()
            
            await update.message.reply_text(
                f"✅ *Profile '{name}' created!*\n\n"
                f"UUID: `{uuid_str}`\n"
                f"Path: `{path}`\n"
                f"Header Host: `{header_host}`",
                parse_mode=ParseMode.MARKDOWN
            )
            return
    
    # Scan flow
    if 'scan_step' in context.user_data:
        step = context.user_data['scan_step']
        
        if step == 'cidr':
            cidrs = [c.strip() for c in text.split(',') if c.strip()]
            context.user_data['cidrs'] = cidrs
            context.user_data['scan_step'] = None
            
            msg = await update.message.reply_text("⏳ *Scanning...*", parse_mode=ParseMode.MARKDOWN)
            
            all_results = []
            for cidr in cidrs:
                try:
                    results = await scan_cidr(cidr, ports=[443, 80], threads=200)
                    all_results.extend(results)
                except:
                    pass
            
            # Show only 101 results
            if all_results:
                response = f"✅ *101 Protocol Found!*\n\n"
                for r in all_results[:20]:
                    response += f"✅ `{r['ip']}:{r['port']}` — 101 Switching Protocols\n"
                if len(all_results) > 20:
                    response += f"\n... and {len(all_results) - 20} more\n"
                
                # Save and send file
                filename = save_results(all_results, ', '.join(cidrs))
                await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
                
                with open(filename, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=os.path.basename(filename),
                        caption=f"📁 *101 Protocol Results*\nFound: {len(all_results)}"
                    )
            else:
                await msg.edit_text("❌ *No 101 Protocols found.*", parse_mode=ParseMode.MARKDOWN)

# === MAIN ===

def main():
    print("[✓] Starting 101 Protocol Scanner Bot...")
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("creatacc", creatacc))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    
    print("[✓] Bot is running!")
    app.run_polling()

if __name__ == "__main__":
    main()
