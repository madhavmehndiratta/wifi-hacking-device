import os
from discord_webhook import DiscordWebhook
import subprocess

hashfiles_dir = "hc22000"
rockyou_path = "rockyou.txt"
WEBHOOK_URL = "" # discord webhook url

def main():
    for file in os.listdir(hashfiles_dir):
        if not file.endswith(".hc22000") or not os.path.isfile(os.path.join(hashfiles_dir, file)):
            continue

        hashfile_path = os.path.join(hashfiles_dir, file)

        cmd = f"hashcat -m 22000 {hashfile_path} {rockyou_path}"
        message = f"Starting Cracking Job for file {file}\n\n"
        message += f"`{cmd}`"
        webhook = DiscordWebhook(url=WEBHOOK_URL, rate_limit_retry=True, content=message)
        webhook.execute()

        try:
            subprocess.run(cmd, shell=True, check=True)
            print("[+] hashcat finished\n\n")

            passwd = f"hashcat -m 22000 {hashfile_path} --show > crack.txt"
            subprocess.run(passwd, shell=True, check=True)

            with open('crack.txt', 'r') as passfile:
                contents = passfile.read()
                send_discord_message(f"Hash file {file} cracked successfully.\n\n`{contents}`")

        except subprocess.CalledProcessError as e:
            print(f"[-] Error running hashcat: {e}")
            send_discord_message(f"Error cracking hash file {file}: {e}")

def send_discord_message(message):
    webhook = DiscordWebhook(url=WEBHOOK_URL, rate_limit_retry=True, content=message)
    webhook.execute()

if __name__ == "__main__":
    main()

