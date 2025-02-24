import discord
import requests
import validators
import os
import time
from discord.ext import commands
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Set up bot and enable MESSAGE CONTENT INTENT
intents = discord.Intents.default()
intents.message_content = True  # Explicitly enable message content intent

bot = commands.Bot(command_prefix="!", intents=intents)

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# Function to check URL in VirusTotal
def check_virustotal(url):
    if not validators.url(url):
        return "⚠️ Invalid URL format."

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    # Step 1: Submit the URL for scanning
    response = requests.post(VIRUSTOTAL_URL, headers=headers, data=data)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/gui/url/{analysis_id}/detection"

        # Step 2: Wait for the scan to be completed (VirusTotal takes a few seconds)
        time.sleep(10)

        # Step 3: Fetch the scan report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            report_data = report_response.json()
            stats = report_data["data"]["attributes"]["stats"]
            malicious_count = stats["malicious"]
            total_engines = sum(stats.values())

            if malicious_count > 0:
                return f"⚠️ WARNING: The URL was flagged as malicious by {malicious_count}/{total_engines} security engines. [View Report]({analysis_url})"
            else:
                return f"✅ SAFE: The URL appears clean. [View Report]({analysis_url})"
        else:
            return "⚠️ Could not retrieve analysis results. Try again later."

    return "❌ Unable to scan the URL at the moment."

# Discord command to check links
@bot.command()
async def checklink(ctx, url: str):
    await ctx.send("⏳ Checking the link on VirusTotal, please wait...")
    result = check_virustotal(url)
    await ctx.send(result)

@bot.event
async def on_ready():
    print(f"✅ Logged in as {bot.user}")

# Run the bot
bot.run(BOT_TOKEN)
