#!/usr/bin/python3

# Need execute with root premissions in order to change TOR IP
# Librerias importadas de 3os
import requests  # Request to external site or api
import urllib3  # Request to external site or api
import sys  # To read arguments
import json  # To parse json response
import re  # To parse regular expressions
import hashlib  # To create the email hash for certain webs
import os
import subprocess
import argparse

######## Global variables
# proxy
tor_proxy = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
# Text colors
normal_color = "\33[00m"
info_color = "\033[1;33m"
red_color = "\033[1;31m"
gren_color = "\033[1;32m"
whiteB_color = "\033[1;37m"
detect_color = "\033[1;34m"

######### Print banner

print("\033[1;33;40m __  __    _    ____ ___ ____ _     _____    _    _  ______  \33[00m")
print("\033[1;33;40m|  \/  |  / \  / ___|_ _/ ___| |   | ____|  / \  | |/ / ___| \33[00m")
print("\033[1;33;40m| |\/| | / _ \| |  _ | | |   | |   |  _|   / _ \ | ' /\___ \ \33[00m")
print("\033[1;33;40m| |  | |/ ___ \ |_| || | |___| |___| |___ / ___ \| . \ ___) |\33[00m")
print("\033[1;33;40m|_|  |_/_/   \_\____|___\____|_____|_____/_/   \_\_|\_\____/ \33[00m")
print("\033[1;33;40m                                                             \33[00m")
print("\033[1;37;40m--> By Magichk and BinaryShadow                              \33[00m\n")


######### Check Arguments
def checkArgs():
	parser = argparse.ArgumentParser()
	parser = argparse.ArgumentParser(description=red_color + 'MagicLeaks 1.0\n' + info_color)
	parser.add_argument('-e', "--email", action="store",
						dest='email',
	                    help="Email address to search")
	parser.add_argument('-f', "--file", action="store",
						dest='file',
	                    help="File with email accounts to search leaks")
	parser.add_argument('-d', "--domain", action="store",
						dest='domain',
	                    help="Domain to search email leaks")
	parser.add_argument('-t', "--tor", action="store_true",
	                    help="Use Tor to search leaks in onion sites, need also set the domain or file.")
	args = parser.parse_args()
	if (len(sys.argv)==1) or (args.tor==True and (not args.email and not args.file and not args.domain)):
		parser.print_help(sys.stderr)
		sys.exit(1)
	return args


############ Script functions ##############
# Check the email in Firefox Monitor
def check_email(email):
	print(whiteB_color + "----------------------------------------\nChecking email account " + email + " ...\n----------------------------------------")
	pattern = "(^[a-zA-Z-1-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
	result = re.match(pattern, email)
	if (result):
		check_firefox_monitor(email)
		check_pastebinLeaks(email)
		emailreputation(email)
		if (args.tor):
			tor_main(email)
	else:
		print(red_color + "Error: " + email + " is not a valid email (bad format email)" + normal_color)
	print(whiteB_color + "----------------------------------------\n----------------------------------------")


def parse_firefox_monitor(response):
	start_breachName = response.text.find("breach-title")
	leaks = False
	while start_breachName != -1:
		leaks = True
		print(detect_color +"Leak Detected!!!")
		start_breachName = start_breachName + 14
		end_breachName = response.text.find("</span>", start_breachName)
		print(red_color + "--> " + response.text[start_breachName:end_breachName])
		end_key = end_breachName
		start_index = response.text.find("breach-key", end_key) + 12
		while start_index > 12 and (start_index < response.text.find("breach-title", start_breachName + 12) or response.text.find("breach-title", start_breachName + 12) < 12):
			end_index = response.text.find("</span>", start_index)
			start_key = response.text.find("breach-value", end_index) + 14
			end_key = response.text.find("</span>", start_key)
			value = response.text[start_index:end_index]
			key = response.text[start_key:end_key]
			print("\t\t- " + value + " " + key)
			start_index = response.text.find("breach-key", end_key) + 12
		start_breachName = response.text.find("breach-title", end_breachName)
	if not leaks:
		print(gren_color + "This email account not appears on Firefox Monitor")


def check_firefox_monitor(email):
	print(info_color + "--------------------\nChecking on Firefox Monitor...\n--------------------")
	# Extract valid csrf token from request.
	url_form = 'https://monitor.firefox.com'
	headers = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url_form, proxies=tor_proxy)
	inicio_csrf = response.text.find("_csrf")
	if (inicio_csrf != -1):
		inicio_csrf = response.text.find("value", inicio_csrf)
		if (inicio_csrf != -1):
			inicio_csrf = inicio_csrf + 7
			fin_csrf = response.text.find("\"", inicio_csrf)
			csrfToken = response.text[inicio_csrf:fin_csrf]
			inicio_scannedEmailId = response.text.find("scannedEmailId")
			inicio_scannedEmailId = response.text.find("value",inicio_scannedEmailId)
			inicio_scannedEmailId = inicio_scannedEmailId+7
			fin_scannedEmailId = response.text.find("\"",inicio_scannedEmailId)
			scannedEmailID = response.text[inicio_scannedEmailId:fin_scannedEmailId]
			emailHash = hashlib.sha1(bytes(email, "utf8"))
			emailHash = emailHash.hexdigest().upper()
			# Do the query
			url = "https://monitor.firefox.com/scan"
			params = {"_csrf": csrfToken, "email": email, "pageToken": "", "scannedEmailId": scannedEmailID, "emailHash": emailHash}
			response = client.post(url, params, proxies=tor_proxy)
			client.close()
			parse_firefox_monitor(response)
	else:
		print(red_color + "Error: It was not possible to access firefox monitor (there is a limit of requests per hour)")


def check_pastebinLeaks(email):
	print(info_color + "--------------------\nChecking on pastebin leaks...\n--------------------")
	r = requests.get("https://psbdmp.ws/api/search/" + email)
	resp_json = json.loads(r.text)

	total = resp_json["count"]
	if (total > 0):
		print(detect_color + "This email account appears on pastebin in " + red_color + str(
			total) +  detect_color + " results listed bellow:" + red_color)
		cont = 0
		while (cont <= (total - 1)):
			link = "\thttps://pastebin.com/" + str(resp_json["data"][cont]["id"])
			print(link)
			cont = cont + 1
	else:
		print(gren_color + "This email account not appears on pastebin leaks")


def emailreputation(email):
	print(info_color + "--------------------\nChecking on emailrep.io...\n--------------------")
	response = requests.get('https://emailrep.io/' + email, proxies=tor_proxy)
	emailreputation = json.loads(response.text)
	try:
		reputation = emailreputation["reputation"]
		credentials_leaked = emailreputation["details"]["credentials_leaked"]
		data_breach = emailreputation["details"]["data_breach"]
		last_seen = emailreputation["details"]["last_seen"]
		if (credentials_leaked == True or data_breach == True):
			print(detect_color + "This email account has " + red_color + reputation + " reputation\n" +
				detect_color + "Credentials leaked? " + red_color + str(
				credentials_leaked) + detect_color + "\nHas data breach? " + red_color + str(data_breach) +
				detect_color + "\nLast seen: " + red_color + str(last_seen))
		else:
			print(gren_color + "This email account has " + reputation + " reputation\nCredentials leaked? " + str(
				credentials_leaked) + "\nHas data breach? " + str(data_breach))
	except:
		print(red_color + "Error: " + emailreputation["reason"])


###### Tor leaks fonts
def pwndb_main(source, is_domain):
	session = requests.session()
	session.proxies = tor_proxy
	leaks = pwndb_find_leaks(source, session, is_domain)
	if leaks:
		leaks.pop(0)
	return leaks


def pwndb_find_leaks(source, session, is_domain):
    url = "http://pwndb2am4tzkvold.onion/"
    username = source
    domain = "%"
    if "@" in source:
        username = source.split("@")[0]
        domain = source.split("@")[1]
        if not username:
            username = '%'
    request_data = {'luser': username, 'domain': domain, 'luseropr': 1, 'domainopr': 1, 'submitform': 'em'}
    r = session.post(url, data=request_data)
    return parse_pwndb_response(r.text, is_domain)


def parse_pwndb_response(text, is_domain):
	if "Array" not in text:
		return None
	leaks = text.split("Array")[1:]
	dataLeak = []
	for leak in leaks:
		try:
			if is_domain:
				data = leak.split("[luser] =>")[1].split("[")[0].strip() + "@" + leak.split("[domain] =>")[1].split("[")[0].strip()
				if not data in dataLeak:
					dataLeak.append(data.lower())
			else:
				data = leak.split("[password] =>")[1].split(")")[0].strip()
				dataLeak.append(data)
		except:
			pass
	return dataLeak

def tor_main(email):
	try:
		print(info_color + "--------------------\nChecking leaks on tor...\n--------------------")
		passwords = pwndb_main(email, False)
		if not passwords:
			print (gren_color + "No leaks found" + normal_color)
		for i in passwords:
			print (detect_color + "This is a passwords leakeds for this email account: " + red_color + str(i) + normal_color)
	except:
		print (red_color + "You have problems with your connection to the tor proxy or pwndb is not accessible." + normal_color)


########## Main function #################3
if __name__ == "__main__":
	args = checkArgs()
	if (args.tor):
		tor_service = os.system("service tor status >> /dev/null")
		if(tor_service != 0):
			print(red_color + "Tor service no started. You need started this to execute this option.")
			exit(1)
	else:
		tor_proxy = None
	if (args.email):
			email = args.email
			if (args.tor):
				os.system("killall -HUP tor")
			check_email(email)
	if (args.file):
		try:
			print(whiteB_color + "--->Reading file with email accounts...<---")
			with open(sys.argv[2]) as myfile:
				lines = myfile.readlines()
			for email in lines:
				os.system("killall -HUP tor")
				email = email[0:len(email) - 1]
				check_email(email)
		except IOError:
			print(red_color + "Error: The file not exist or bad format.")
	if (args.domain):
		try:
			if not args.tor:
				print(red_color + "Error: This functionality need tor to work.")
				exit(1)
			domain = args.domain
			if (domain[0] != '@'):
				domain = '@' + domain
			print(whiteB_color + "--->Searching email accounts leaks on " + domain + " domain...<---")
			email_list = pwndb_main(domain, True)
			if not email_list:
				print(gren_color + "No leaks found for this domain" + normal_color)
			else:
				print(detect_color + "Found " + str(len(email_list)) + " accounts with leaks in selected domain: \n" +
					red_color + ' || '.join(email_list))
				for email in email_list:
					os.system("killall -HUP tor")
					check_email(email)
		except IOError:
			print(red_color + "Error: Unknow error.")
