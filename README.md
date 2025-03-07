# Phishing Detection Discord Bot  

🚀 **A Python-powered Discord bot that analyzes URLs for phishing risks using the VirusTotal API and provides real-time safety reports.**  

## 📌 Features  
- 🔍 **URL Analysis:** Users can check the safety of links using the `!checklink` command.  
- 🛡️ **VirusTotal Integration:** The bot submits URLs to VirusTotal and retrieves security reports.  
- ⚙️ **Secure API Handling:** Environment variables are used to protect sensitive API keys.  
- 📢 **User Assistance:** A `!help` command provides instructions for usage.  
- 🔄 **Error Handling & Reliability:** The bot gracefully handles API errors and ensures smooth operation.  

## 🛠️ Installation  

1. **Clone the repository:**  
   ```bash
   git clone https://github.com/yourusername/phishing-detection-bot.git
   cd phishing-detection-bot
For macOS/Linux:
bash
Copy
Edit
python3 -m venv venv
source venv/bin/activate  # Activates the virtual environment

For Windows:
bash
Copy
Edit
python -m venv venv
venv\Scripts\activate  # Activates the virtual environment

Install project dependencies:
The project requires specific libraries, such as discord.py and requests. These dependencies are listed in the requirements.txt file.

bash
Copy
Edit
pip install -r requirements.txt

Set up environment variables:
To keep sensitive API keys secure, store them in environment variables.

Create a .env file in the project directory.
Add the following lines, replacing with your actual keys:
env
Copy
Edit
DISCORD_BOT_TOKEN=your_discord_bot_token
VIRUSTOTAL_API_KEY=your_virustotal_api_key

Generate a requirements.txt file (if it’s not present):
If you don't have a requirements.txt file yet, you can generate one by running the following command within your virtual environment:

bash
Copy
Edit
pip freeze > requirements.txt

Run the bot:
After setting everything up, run the bot with the following command:

bash
Copy
Edit
python phish_bot.py
Use the bot commands in Discord:

!checklink <url> → Scans the URL for phishing threats.
!help → Displays available commands.
🛡️ Security Considerations
Never share your API keys in public repositories.
Use environment variables to keep credentials secure.
Implement rate limiting if needed to avoid API request limits.


