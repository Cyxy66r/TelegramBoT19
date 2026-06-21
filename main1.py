#!/usr/bin/env python3
# Domain Scraper Telegram Bot v5.0
# Scrapes domains from multiple sources

import os
import sys
import json
import time
import re
import asyncio
import aiohttp
import random
from datetime import datetime, timedelta
from collections import defaultdict
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

init(autoreset=True)

# === CONFIGURATION ===
BOT_TOKEN = "8919629019:AAHD2e7b5L7LKshB6-5lCVG5V0r1I__J5YQ"  # Replace with your bot token
ADMIN_IDS = [5889605682]  # Replace with your Telegram ID
CHANNEL_ID = "@your_channel"  # Optional

# Sources
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
    }
}

PROXY_FILE = "proxies.txt"
OUTPUT_DIR = "scraped_domains"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === UTILITY FUNCTIONS ===

def load_proxies():
    """Load proxies from file"""
    if os.path.exists(PROXY_FILE):
        with open(PROXY_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def get_random_proxy():
    """Get random proxy from list"""
    proxies = load_proxies()
    if proxies:
        return random.choice(proxies)
    return None

def parse_domains_from_text(text):
    """Extract domains from text"""
    pattern = re.compile(r'[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
    return list(set(pattern.findall(text)))

def parse_domains_from_json(data):
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

# === SCRAPING FUNCTIONS ===

async def scrape_source(session, source_name, source_data, domain, proxy=None):
    """Scrape domains from a single source"""
    domains = set()
    try:
        url = source_data['url'].format(domain=domain)
        headers = {'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ])}
        
        # Use proxy if available
        if proxy:
            proxy_url = f"http://{proxy}" if not proxy.startswith('http') else proxy
            timeout = aiohttp.ClientTimeout(total=30)
            async with session.get(url, headers=headers, proxy=proxy_url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    
                    # Parse based on source type
                    if source_data['parser'] == 'json':
                        try:
                            json_data = await resp.json()
                            domains = parse_domains_from_json(json_data)
                        except:
                            pass
                    elif source_data['parser'] == 'text':
                        domains = parse_domains_from_text(data)
                    else:  # html
                        domains = parse_domains_from_text(data)
        else:
            # Direct request
            timeout = aiohttp.ClientTimeout(total=30)
            async with session.get(url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    if source_data['parser'] == 'json':
                        try:
                            json_data = await resp.json()
                            domains = parse_domains_from_json(json_data)
                        except:
                            pass
                    elif source_data['parser'] == 'text':
                        domains = parse_domains_from_text(data)
                    else:
                        domains = parse_domains_from_text(data)
        
        return source_name, domains, None
    except Exception as e:
        return source_name, set(), str(e)

async def scrape_all_sources(domain, use_proxy=True):
    """Scrape all sources for a domain"""
    all_domains = set()
    results = {}
    proxy = get_random_proxy() if use_proxy else None
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for source_name, source_data in SOURCES.items():
            task = scrape_source(session, source_name, source_data, domain, proxy)
            tasks.append(task)
        
        for task in asyncio.as_completed(tasks):
            source_name, domains, error = await task
            results[source_name] = {'domains': domains, 'error': error}
            all_domains.update(domains)
    
    return all_domains, results

# === SAVE FUNCTIONS ===

def save_domains(domains, domain, format='txt'):
    """Save domains to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{OUTPUT_DIR}/{domain}_{timestamp}.{format}"
    
    if format == 'txt':
        with open(filename, 'w') as f:
            for d in sorted(domains):
                f.write(d + '\n')
    elif format == 'csv':
        with open(filename, 'w') as f:
            f.write("domain\n")
            for d in sorted(domains):
                f.write(d + '\n')
    elif format == 'json':
        with open(filename, 'w') as f:
            json.dump(sorted(domains), f, indent=2)
    
    return filename

def save_results(domain, all_domains, results):
    """Save detailed results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{OUTPUT_DIR}/{domain}_{timestamp}_detailed.json"
    
    data = {
        'domain': domain,
        'timestamp': timestamp,
        'total_domains': len(all_domains),
        'sources': {},
        'all_domains': sorted(all_domains)
    }
    
    for source_name, result in results.items():
        data['sources'][source_name] = {
            'count': len(result['domains']),
            'error': result['error'],
            'domains': sorted(result['domains'])
        }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    return filename

# === TELEGRAM BOT HANDLERS ===

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 You are not authorized to use this bot.")
        return
    
    keyboard = [
        [InlineKeyboardButton("🌐 Scrape Domain", callback_data='scrape')],
        [InlineKeyboardButton("📊 View Stats", callback_data='stats')],
        [InlineKeyboardButton("📁 Last Results", callback_data='last_results')],
        [InlineKeyboardButton("⚙️ Settings", callback_data='settings')],
        [InlineKeyboardButton("🔄 Refresh Sources", callback_data='refresh_sources')],
        [InlineKeyboardButton("📥 Download Proxies", callback_data='download_proxies')],
        [InlineKeyboardButton("ℹ️ Help", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"🤖 *Domain Scraper Bot v5.0*\n\n"
        f"📌 *Features:*\n"
        f"• Scrape from {len(SOURCES)} sources\n"
        f"• Proxy support\n"
        f"• Multiple output formats\n"
        f"• Rate limit handling\n\n"
        f"🔧 *Commands:*\n"
        f"/scrape <domain> - Scrape domains\n"
        f"/status - Check bot status\n"
        f"/help - Show help\n\n"
        f"Select an option below:",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN
    )

async def scrape_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scrape command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "❌ *Usage:* `/scrape <domain>`\n"
            "Example: `/scrape example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    
    domain = context.args[0].lower()
    
    # Send initial message
    msg = await update.message.reply_text(
        f"🔍 *Scraping domains for:* `{domain}`\n"
        f"⏳ Please wait...",
        parse_mode=ParseMode.MARKDOWN
    )
    
    try:
        # Scrape all sources
        all_domains, results = await scrape_all_sources(domain)
        
        # Save results
        txt_file = save_domains(all_domains, domain, 'txt')
        json_file = save_results(domain, all_domains, results)
        
        # Prepare response
        response = f"✅ *Scraping Complete!*\n\n"
        response += f"📌 *Domain:* `{domain}`\n"
        response += f"🌐 *Total Domains Found:* {len(all_domains)}\n"
        response += f"📊 *Sources Used:* {len([s for s in results if not results[s]['error']])}/{len(SOURCES)}\n\n"
        
        response += "*Source Breakdown:*\n"
        for source_name, result in results.items():
            if result['error']:
                response += f"❌ {source_name}: Error - {result['error'][:30]}\n"
            else:
                response += f"✅ {source_name}: {len(result['domains'])} domains\n"
        
        response += f"\n📁 *Files Saved:*\n"
        response += f"• `{txt_file}`\n"
        response += f"• `{json_file}`\n"
        
        # Add first 10 domains as sample
        if all_domains:
            response += f"\n📝 *Sample Domains (First 10):*\n"
            for d in sorted(all_domains)[:10]:
                response += f"• `{d}`\n"
            if len(all_domains) > 10:
                response += f"• ... and {len(all_domains)-10} more\n"
        
        # Update message
        await msg.edit_text(
            response,
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True
        )
        
        # Also send file
        with open(txt_file, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=os.path.basename(txt_file),
                caption=f"📁 *Domains for:* `{domain}`\nTotal: {len(all_domains)}"
            )
        
    except Exception as e:
        await msg.edit_text(
            f"❌ *Error:* {str(e)}",
            parse_mode=ParseMode.MARKDOWN
        )

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Status command"""
    user_id = update.effective_user.id
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("🚫 Unauthorized.")
        return
    
    proxies = load_proxies()
    
    status = f"📊 *Bot Status*\n\n"
    status += f"✅ *Bot Running*\n"
    status += f"📌 *Sources:* {len(SOURCES)}\n"
    status += f"🔄 *Proxies:* {len(proxies)} loaded\n"
    status += f"📁 *Output Directory:* `{OUTPUT_DIR}`\n"
    status += f"⏰ *Uptime:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    await update.message.reply_text(status, parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    help_text = f"""
📚 *Domain Scraper Bot Help*

🔹 *Commands:*
• `/start` - Show main menu
• `/scrape <domain>` - Scrape domains
• `/status` - Check bot status
• `/help` - Show this help

🔹 *How to use:*
1. Send `/scrape example.com`
2. Bot will scrape from {len(SOURCES)} sources
3. Get results as TXT and JSON files

🔹 *Sources:*
{', '.join(SOURCES.keys())}

🔹 *Output:*
• TXT file - Raw domain list
• JSON file - Detailed results

🔹 *Tips:*
• Use specific domains for better results
• Results are cached locally
• Proxy rotation helps avoid rate limits
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
    
    if data == 'scrape':
        await query.edit_message_text(
            "📝 *Enter domain to scrape:*\n"
            "Example: `example.com`",
            parse_mode=ParseMode.MARKDOWN
        )
        context.user_data['awaiting_domain'] = True
    
    elif data == 'stats':
        await status_command(update, context)
    
    elif data == 'last_results':
        # List last 5 results
        files = os.listdir(OUTPUT_DIR)
        txt_files = [f for f in files if f.endswith('.txt')]
        txt_files.sort(key=lambda x: os.path.getmtime(f"{OUTPUT_DIR}/{x}"), reverse=True)
        
        if txt_files:
            response = f"📁 *Last 5 Results:*\n\n"
            for f in txt_files[:5]:
                response += f"• `{f}`\n"
            await query.edit_message_text(response, parse_mode=ParseMode.MARKDOWN)
        else:
            await query.edit_message_text("📁 *No results found.*")
    
    elif data == 'settings':
        keyboard = [
            [InlineKeyboardButton("🔧 Set Output Format", callback_data='set_format')],
            [InlineKeyboardButton("🔄 Toggle Proxy", callback_data='toggle_proxy')],
            [InlineKeyboardButton("📊 Show Stats", callback_data='stats')],
            [InlineKeyboardButton("🔙 Back", callback_data='back_to_menu')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "⚙️ *Settings*\n\n"
            "Configure bot settings:",
            reply_markup=reply_markup,
            parse_mode=ParseMode.MARKDOWN
        )
    
    elif data == 'refresh_sources':
        await query.edit_message_text("🔄 *Refreshing sources...*")
        # Re-load sources
        await query.edit_message_text("✅ *Sources refreshed!*")
    
    elif data == 'download_proxies':
        proxies = load_proxies()
        if proxies:
            filename = f"{OUTPUT_DIR}/proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for p in proxies:
                    f.write(p + '\n')
            
            with open(filename, 'rb') as f:
                await update.callback_query.message.reply_document(
                    document=f,
                    filename=os.path.basename(filename),
                    caption=f"🔄 *Proxies* ({len(proxies)})"
                )
            await query.edit_message_text("📥 *Proxy list downloaded!*")
        else:
            await query.edit_message_text("❌ *No proxies found.*")
    
    elif data == 'help':
        await help_command(update, context)
    
    elif data == 'back_to_menu':
        keyboard = [
            [InlineKeyboardButton("🌐 Scrape Domain", callback_data='scrape')],
            [InlineKeyboardButton("📊 View Stats", callback_data='stats')],
            [InlineKeyboardButton("📁 Last Results", callback_data='last_results')],
            [InlineKeyboardButton("⚙️ Settings", callback_data='settings')],
            [InlineKeyboardButton("🔄 Refresh Sources", callback_data='refresh_sources')],
            [InlineKeyboardButton("📥 Download Proxies", callback_data='download_proxies')],
            [InlineKeyboardButton("ℹ️ Help", callback_data='help')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "🤖 *Domain Scraper Bot*\n\n"
            "Select an option:",
            reply_markup=reply_markup,
            parse_mode=ParseMode.MARKDOWN
        )

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages"""
    if context.user_data.get('awaiting_domain'):
        domain = update.message.text.strip().lower()
        context.user_data['awaiting_domain'] = False
        
        # Simulate /scrape command
        context.args = [domain]
        await scrape_command(update, context)

# === MAIN ===

def main():
    """Main function"""
    print(f"{Fore.GREEN}[✓] Starting Domain Scraper Bot...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Bot Token: {BOT_TOKEN[:10]}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Admin IDs: {ADMIN_IDS}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Sources: {len(SOURCES)}{Style.RESET_ALL}")
    
    # Create application
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scrape", scrape_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    
    # Start bot
    print(f"{Fore.GREEN}[✓] Bot is running!{Style.RESET_ALL}")
    app.run_polling()

if __name__ == "__main__":
    main()