#!/usr/bin/env python3
# BugScanX - Advanced Domain Scanner Bot v3.0
# Complete All-in-One Scanner

import os
import sys
import json
import re
import time
import socket
import asyncio
import aiohttp
import ipaddress
import random
import subprocess
from datetime import datetime
from colorama import init, Fore, Style
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import dns.resolver

init(autoreset=True)

# === CONFIGURATION ===
BOT_TOKEN = "8919629019:AAHD2e7b5L7LKshB6-5lCVG5V0r1I__J5YQ"  # Replace with your bot token
ADMIN_IDS = [5889605682]  # Replace with your Telegram ID
OUTPUT_DIR = "scans"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === SOURCES ===
SOURCES = {
    'crt.sh': {
        'url': 'https://crt.sh/?q=%25.{domain}&output=json',
        'parser': 'json'
    },
    'alienvault': {
        'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
        'parser': 'json'
    },
    'hackertarget': {
        'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
        'parser': 'text'
    },
    'securitytrails': {
        'url': 'https://securitytrails.com/domain/{domain}/subdomains',
        'parser': 'html'
    },
    'certspotter': {
        'url': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true',
        'parser': 'json'
    },
    'wayback': {
        'url': 'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey',
        'parser': 'json'
    },
    'dnsdumpster': {
        'url': 'https://dnsdumpster.com/',
        'parser': 'html'
    },
    'rapiddns': {
        'url': 'https://rapiddns.io/subdomain/{domain}?full=1',
        'parser': 'html'
    },
    'bufferover': {
        'url': 'https://dns.bufferover.run/dns?q={domain}',
        'parser': 'json'
    },
    'netcraft': {
        'url': 'https://searchdns.netcraft.com/?restriction=site+contains&host={domain}',
        'parser': 'html'
    }
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

# === UTILITY FUNCTIONS ===

def parse_domains(text):
    """Extract domains from text"""
    pattern = re.compile(r'[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
    return list(set(pattern.findall(text)))

def parse_json_domains(data):
    """Extract domains from JSON"""
    domains = set()
    try:
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for key, value in item.items():
                        if 'domain' in key.lower() or 'host' in key.lower() or 'name' in key.lower():
                            if isinstance(value, str):
                                domains.add(value.lower())
        elif isinstance(data, dict):
            for key, value in data.items():
                if 'domain' in key.lower() or 'host' in key.lower() or 'name' in key.lower():
                    if isinstance(value, str):
                        domains.add(value.lower())
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                if 'domain' in k.lower() or 'host' in k.lower() or 'name' in k.lower():
                                    if isinstance(v, str):
                                        domains.add(v.lower())
    except:
        pass
    return domains

def ip_to_domain(ip):
    """Convert IP to domain using reverse DNS"""
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except:
        return None

def cidr_to_ips(cidr):
    """Convert CIDR to list of IPs"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except:
        return []

def scan_port(ip, port, timeout=2):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def is_alive(domain):
    """Check if domain is alive"""
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

# === SCRAPING FUNCTIONS ===

async def scrape_source(session, source_name, source_data, domain):
    """Scrape domains from a single source"""
    domains = set()
    try:
        url = source_data['url'].format(domain=domain)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        async with session.get(url, headers=headers, timeout=30) as resp:
            if resp.status == 200:
                if source_data['parser'] == 'json':
                    try:
                        data = await resp.json()
                        domains = parse_json_domains(data)
                    except:
                        pass
                elif source_data['parser'] == 'text':
                    text = await resp.text()
                    domains = parse_domains(text)
                else:
                    text = await resp.text()
                    domains = parse_domains(text)
        
        return source_name, domains, None
    except Exception as e:
        return source_name, set(), str(e)

async def scrape_domains(domain):
    """Scrape domains from all sources"""
    all_domains = set()
    results = {}
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for source_name, source_data in SOURCES.items():
            task = scrape_source(session, source_name, source_data, domain)
            tasks.append(task)
        
        for task in asyncio.as_completed(tasks):
            source_name, domains, error = await task
            results[source_name] = {'domains': domains, 'error': error}
            all_domains.update(domains)
    
    return all_domains, results

# === CIDR TO DOMAIN ===

def cidr_to_domain(cidr):
    """Convert CIDR to domains"""
    ips = cidr_to_ips(cidr)
    domains = []
    for ip in ips[:100]:  # Limit to 100 IPs
        domain = ip_to_domain(ip)
        if domain:
            domains.append(domain)
    return domains

# === PORT SCANNER ===

def port_scan(target, ports=COMMON_PORTS):
    """Scan ports on target"""
    open_ports = []
    for port in ports:
        if scan_port(target, port):
            open_ports.append(port)
    return open_ports

# === SUBDOMAIN HUNTER ===

async def subdomain_hunter(domain):
    """Find subdomains using multiple techniques"""
    all_subdomains = set()
    
    # Method 1: crt.sh
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for item in data:
                name = item.get('name_value', '')
                if name and not name.startswith('*'):
                    all_subdomains.add(name.lower())
    except:
        pass
    
    # Method 2: SecurityTrails
    try:
        resp = requests.get(f"https://securitytrails.com/domain/{domain}/subdomains", timeout=30)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text()
            domains = parse_domains(text)
            all_subdomains.update(domains)
    except:
        pass
    
    # Method 3: AlienVault
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get('passive_dns', []):
                host = item.get('hostname', '')
                if host:
                    all_subdomains.add(host.lower())
    except:
        pass
    
    return list(all_subdomains)

# === SAVE FUNCTIONS ===

def save_results(data, filename):
    """Save results to file"""
    with open(filename, 'w') as f:
        if isinstance(data, list):
            for item in data:
                f.write(str(item) + '\n')
        elif isinstance(data, dict):
            json.dump(list(all_domains), f)
        else:
            f.write(str(data))
    return filename

# === TELEGRAM BOT HANDLERS ===

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    keyboard = [
        [InlineKeyboardButton("🌐 Domain Scanner", callback_data='domain_scanner')],
        [InlineKeyboardButton("🔍 CIDR to Domain", callback_data='cidr_to_domain')],
        [InlineKeyboardButton("🎯 Subdomain Hunter", callback_data='subdomain_hunter')],
        [InlineKeyboardButton("🔌 Port Scanner", callback_data='port_scanner')],
        [InlineKeyboardButton("📊 Bulk Scanner", callback_data='bulk_scanner')],
        [InlineKeyboardButton("📁 My Scans", callback_data='my_scans')],
        [InlineKeyboardButton("ℹ️ Help", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"🔥 *BugScanX v3.0*\n\n"
        f"📌 *Features:*\n"
        f"• 🌐 Domain Scanner (10+ Sources)\n"
        f"• 🔍 CIDR to Domain Converter\n"
        f"• 🎯 Subdomain Hunter\n"
        f"• 🔌 Port Scanner (Common Ports)\n"
        f"• 📊 Bulk Scanner\n"
        f"• 📁 Export Results (TXT/JSON)\n\n"
        f"🔧 *Commands:*\n"
        f"/scan <domain> - Scan domain\n"
        f"/cidr <cidr> - Convert CIDR\n"
        f"/subdomains <domain> - Hunt subdomains\n"
        f"/ports <host> - Scan ports\n"
        f"/bulk - Bulk scan mode\n"
        f"/status - Check bot status\n"
        f"/help - Show help",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Domain scan command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "❌ *Usage:* `/scan <domain>`\n"
            "Example: `/scan example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    domain = context.args[0].lower()
    msg = await update.message.reply_text(f"🔍 *Scanning:* `{domain}`\n⏳ Please wait...", parse_mode=ParseMode.MARKDOWN)
    
    try:
        # Scrape domains
        all_domains, results = await scrape_domains(domain)
        
        # Check live status
        live_domains = []
        for d in all_domains:
            if is_alive(d):
                live_domains.append(d)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"{OUTPUT_DIR}/{domain}_{timestamp}.txt"
        json_file = f"{OUTPUT_DIR}/{domain}_{timestamp}.json"
        
        save_results(all_domains, txt_file)
        save_results({
            'domain': domain,
            'timestamp': timestamp,
            'total': len(all_domains),
            'live': len(live_domains),
            'sources': {k: len(v['domains']) for k, v in results.items() if not v['error']},
            'results': results,
            'all_domains': sorted(all_domains)
        }, json_file)
        
        # Response
        response = f"✅ *Scan Complete!*\n\n"
        response += f"📌 *Domain:* `{domain}`\n"
        response += f"🌐 *Total Domains:* {len(all_domains)}\n"
        response += f"✅ *Live:* {len(live_domains)}\n"
        response += f"📊 *Sources:* {len([s for s in results if not results[s]['error']])}/{len(SOURCES)}\n\n"
        
        response += "*Source Breakdown:*\n"
        for source_name, result in results.items():
            if result['error']:
                response += f"❌ {source_name}: Error\n"
            else:
                response += f"✅ {source_name}: {len(result['domains'])} domains\n"
        
        if all_domains:
            response += f"\n📝 *Sample Domains (First 10):*\n"
            for d in sorted(all_domains)[:10]:
                response += f"• `{d}`\n"
            if len(all_domains) > 10:
                response += f"• ... and {len(all_domains)-10} more\n"
        
        await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
        
        # Send file
        with open(txt_file, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=os.path.basename(txt_file),
                caption=f"📁 *Domains for:* `{domain}`\nTotal: {len(all_domains)}"
            )
        
    except Exception as e:
        await msg.edit_text(f"❌ *Error:* {str(e)}", parse_mode=ParseMode.MARKDOWN)

async def cidr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """CIDR to domain command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "❌ *Usage:* `/cidr <cidr>`\n"
            "Example: `/cidr 192.168.1.0/24`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    cidr = context.args[0]
    msg = await update.message.reply_text(f"🔍 *Converting:* `{cidr}`\n⏳ Please wait...", parse_mode=ParseMode.MARKDOWN)
    
    try:
        domains = cidr_to_domain(cidr)
        
        response = f"✅ *CIDR to Domain Complete!*\n\n"
        response += f"📌 *CIDR:* `{cidr}`\n"
        response += f"🌐 *Domains Found:* {len(domains)}\n\n"
        
        if domains:
            response += "*Domains:*\n"
            for d in domains[:20]:
                response += f"• `{d}`\n"
            if len(domains) > 20:
                response += f"• ... and {len(domains)-20} more\n"
            
            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{OUTPUT_DIR}/cidr_{cidr.replace('/', '_')}_{timestamp}.txt"
            save_results(domains, filename)
            
            with open(filename, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=os.path.basename(filename),
                    caption=f"📁 *CIDR Domains:* `{cidr}`"
                )
        
        await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
        
    except Exception as e:
        await msg.edit_text(f"❌ *Error:* {str(e)}", parse_mode=ParseMode.MARKDOWN)

async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Subdomain hunter command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "❌ *Usage:* `/subdomains <domain>`\n"
            "Example: `/subdomains example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    domain = context.args[0].lower()
    msg = await update.message.reply_text(f"🎯 *Hunting subdomains for:* `{domain}`\n⏳ Please wait...", parse_mode=ParseMode.MARKDOWN)
    
    try:
        subdomains = await subdomain_hunter(domain)
        
        response = f"✅ *Subdomain Hunt Complete!*\n\n"
        response += f"📌 *Domain:* `{domain}`\n"
        response += f"🎯 *Subdomains Found:* {len(subdomains)}\n\n"
        
        if subdomains:
            response += "*Subdomains:*\n"
            for s in subdomains[:20]:
                response += f"• `{s}`\n"
            if len(subdomains) > 20:
                response += f"• ... and {len(subdomains)-20} more\n"
            
            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{OUTPUT_DIR}/subdomains_{domain}_{timestamp}.txt"
            save_results(subdomains, filename)
            
            with open(filename, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=os.path.basename(filename),
                    caption=f"📁 *Subdomains for:* `{domain}`"
                )
        
        await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
        
    except Exception as e:
        await msg.edit_text(f"❌ *Error:* {str(e)}", parse_mode=ParseMode.MARKDOWN)

async def ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Port scanner command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "❌ *Usage:* `/ports <host>`\n"
            "Example: `/ports example.com`\n"
            "Or: `/ports 192.168.1.1`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    target = context.args[0]
    msg = await update.message.reply_text(f"🔌 *Scanning ports on:* `{target}`\n⏳ Please wait...", parse_mode=ParseMode.MARKDOWN)
    
    try: 
        # Resolve domain to IP if needed
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
            ip = socket.gethostbyname(target)
        else:
            ip = target
        
        open_ports = port_scan(ip)
        
        response = f"✅ *Port Scan Complete!*\n\n"
        response += f"📌 *Target:* `{target}`\n"
        response += f"🖥️ *IP:* `{ip}`\n"
        response += f"🔌 *Open Ports:* {len(open_ports)}\n\n"
        
        if open_ports:
            response += "*Open Ports:*\n"
            for port in open_ports:
                response += f"• `{port}`\n"
        else:
            response += "❌ *No open ports found*\n"
        
        # Save
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{OUTPUT_DIR}/ports_{target}_{timestamp}.txt"
        save_results(open_ports, filename)
        
        with open(filename, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=os.path.basename(filename),
                caption=f"📁 *Ports for:* `{target}`"
            )
        
        await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)
        
    except Exception as e:
        await msg.edit_text(f"❌ *Error:* {str(e)}", parse_mode=ParseMode.MARKDOWN)

async def bulk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bulk scanner command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    await update.message.reply_text(
        "📊 *Bulk Scanner Mode*\n\n"
        "Send me a list of domains (one per line).\n"
        "Example:\n"
        "example.com\n"
        "google.com\n"
        "github.com\n\n"
        "Or upload a TXT file."
    )
    context.user_data['bulk_mode'] = True

async def handle_bulk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle bulk scan input"""
    if not context.user_data.get('bulk_mode'):
        return
    
    if update.message.document:
        # Handle file upload
        file = await update.message.document.get_file()
        content = await file.download_as_bytearray()
        domains = content.decode().strip().split('\n')
    else:
        # Handle text input
        domains = update.message.text.strip().split('\n')
    
    domains = [d.strip() for d in domains if d.strip()]
    context.user_data['bulk_mode'] = False
    
    msg = await update.message.reply_text(f"📊 *Bulk Scanning {len(domains)} domains...*\n⏳ Please wait...", parse_mode=ParseMode.MARKDOWN)
    
    results = {}
    for domain in domains[:10]:  # Limit to 10
        try:
            all_domains, _ = await scrape_domains(domain)
            live = [d for d in all_domains if is_alive(d)]
            results[domain] = {'total': len(all_domains), 'live': len(live)}
        except:
            results[domain] = {'total': 0, 'live': 0, 'error': True}
    
    response = f"✅ *Bulk Scan Complete!*\n\n"
    for domain, result in results.items():
        if result.get('error'):
            response += f"❌ {domain}: Error\n"
        else:
            response += f"✅ {domain}: {result['total']} domains, {result['live']} live\n"
    
    # Save
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{OUTPUT_DIR}/bulk_{timestamp}.json"
    save_results(results, filename)
    
    with open(filename, 'rb') as f:
        await update.message.reply_document(
            document=f,
            filename=os.path.basename(filename),
            caption="📁 *Bulk Scan Results*"
        )
    
    await msg.edit_text(response, parse_mode=ParseMode.MARKDOWN)

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Status command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    status = f"📊 *Bot Status*\n\n"
    status += f"✅ *Running*\n"
    status += f"📌 *Sources:* {len(SOURCES)}\n"
    status += f"📁 *Output Directory:* `{OUTPUT_DIR}`\n"
    status += f"⏰ *Uptime:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    # Count files
    files = os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else []
    status += f"📄 *Files:* {len(files)}\n"
    
    await update.message.reply_text(status, parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    help_text = f"""
📚 *BugScanX Help*

🔹 *Commands:*
• `/scan <domain>` - Scan domain (10+ sources)
• `/cidr <cidr>` - Convert CIDR to domains
• `/subdomains <domain>` - Hunt subdomains
• `/ports <host>` - Scan ports
• `/bulk` - Bulk scan mode
• `/status` - Check bot status
• `/help` - Show help

🔹 *Features:*
• 🌐 Multi-source domain scanning
• 🔍 CIDR to domain conversion
• 🎯 Subdomain discovery
• 🔌 Port scanning
• 📊 Bulk scanning
• 📁 Export results

🔹 *Examples:*
• `/scan example.com`
• `/cidr 192.168.1.0/24`
• `/subdomains example.com`
• `/ports example.com`
"""
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button clicks"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await query.edit_message_text("🚫 Unauthorized.")
        return
    
    data = query.data
    
    if data == 'domain_scanner':
        await query.edit_message_text(
            "🌐 *Domain Scanner*\n\n"
            "Send: `/scan <domain>`\n"
            "Example: `/scan example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == 'cidr_to_domain':
        await query.edit_message_text(
            "🔍 *CIDR to Domain*\n\n"
            "Send: `/cidr <cidr>`\n"
            "Example: `/cidr 192.168.1.0/24`",
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == 'subdomain_hunter':
        await query.edit_message_text(
            "🎯 *Subdomain Hunter*\n\n"
            "Send: `/subdomains <domain>`\n"
            "Example: `/subdomains example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == 'port_scanner':
        await query.edit_message_text(
            "🔌 *Port Scanner*\n\n"
            "Send: `/ports <host>`\n"
            "Example: `/ports example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == 'bulk_scanner':
        await bulk_command(update, context)
    
    elif data == 'my_scans':
        files = os.listdir(OUTPUT_DIR) if os.path.exists(OUTPUT_DIR) else []
        if files:
            response = f"📁 *My Scans ({len(files)} files)*\n\n"
            for f in files[-10:]:
                response += f"• `{f}`\n"
            await query.edit_message_text(response, parse_mode=ParseMode.MARKDOWN)
        else:
            await query.edit_message_text("📁 *No scans found.*")
    
    elif data == 'help':
        await help_command(update, context)

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages"""
    await handle_bulk(update, context)

# === MAIN ===

def main():
    print(f"{Fore.GREEN}[✓] Starting BugScanX Bot...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Bot Token: {BOT_TOKEN[:10]}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Admin IDs: {ADMIN_IDS}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Sources: {len(SOURCES)}{Style.RESET_ALL}")
    
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("cidr", cidr_command))
    app.add_handler(CommandHandler("subdomains", subdomains_command))
    app.add_handler(CommandHandler("ports", ports_command))
    app.add_handler(CommandHandler("bulk", bulk_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_bulk))
    
    print(f"{Fore.GREEN}[✓] Bot is running!{Style.RESET_ALL}")
    app.run_polling()

if __name__ == "__main__":
    main() 
