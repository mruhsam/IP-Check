import os, json, requests
from datetime import datetime
from termcolor import colored

from dotenv import load_dotenv
BASE_DIR = os.path.dirname(__file__)
load_dotenv(os.path.join(BASE_DIR, "idk"))
API_KEY = os.getenv("VT_API_KEY")

choice = ""

while True:

    print("Please input an ip address: ")
    ip = input()
    print(f"you entered: {ip}")

    resp = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"accept": "application/json", "x-apikey": API_KEY},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    lad = data["data"]["attributes"]["last_analysis_date"]
    timestamp = int(lad)
    formatted_date = datetime.fromtimestamp(timestamp).strftime("%m-%d-%y %H:%M:%S")


    def get_score():
        score = data["data"]["attributes"]["last_analysis_stats"]
        malScore = score["malicious"]
        susScore = score["suspicious"]
        
        totalScore = 0
        
        for x in score.values(): # getting vendor total from each section
            totalScore += int(x)
            
        # check both first
        if malScore > 0 and susScore > 0:
            return (
                colored(f"Malicious: {malScore}/{totalScore}", "red")
                + "  "
                + colored(f"Suspicious: {susScore}/{totalScore}", "yellow")
            )
        
        if malScore > 0:
            return "Malicious!: " + colored(f"{malScore}/{totalScore}", "red")
        if susScore > 0:
            return "Suspicious!: " + colored(f"{susScore}/{totalScore}", "yellow")
        else:
            return "Beningn :) " + colored(f"{malScore}/{totalScore}", "green")
        
            
    print(get_score())

    print(f"Last Analysis Date: {formatted_date}")

    with open("ip_details.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

           
    while True:
        choice = input("Press 'c' to check another IP, or 'x' to exit: ").lower().strip()
        if choice in ("c", "x"):
            break
        print("please try again!")
        
    if choice == "c":
        continue
    else:
        break
