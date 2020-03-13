#!/usr/bin/python3

# Librerias importadas de 3os
import requests  # Request to external site or api
import urllib3  # Request to external site or api
import sys  # To read arguments
import json  # To parse json response
import re  # To parse regular expressions
import hashlib  # To create the email hash for certain webs

# Print banner

print("\033[1;33;40m __  __    _    ____ ___ ____ _     _____    _    _  ______  ")
print("\033[1;33;40m|  \/  |  / \  / ___|_ _/ ___| |   | ____|  / \  | |/ / ___| ")
print("\033[1;33;40m| |\/| | / _ \| |  _ | | |   | |   |  _|   / _ \ | ' /\___ \ ")
print("\033[1;33;40m| |  | |/ ___ \ |_| || | |___| |___| |___ / ___ \| . \ ___) |")
print("\033[1;33;40m|_|  |_/_/   \_\____|___\____|_____|_____/_/   \_\_|\_\____/ ")
print("\033[1;33;40m                                                             ")
print("\033[1;37;40mBy Magichk and BinaryShadow")


# Check Arguments
def checkArgs():
	if len(sys.argv) > 1:
		if (sys.argv[1] == "-e" or sys.argv[1] == "--email"):
			return 1
		elif (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
			helpUsage()
		elif (sys.argv[1] == "-f" or sys.argv[1] == "--file"):
			return 2
		else:
			print("Argumento no valido")
			print(" ")
			helpUsage()
			return 0
	else:
		helpUsage()


# Help usage
def helpUsage():
	print("\033[1;33;40mMagicLeaks 0.1 Beta")
	print("\033[1;33;40mUsage: magicleaks.py [Options] {target specification}")
	print("\033[1;33;40mOptions Avilable")
	print("\033[1;33;40m\t-e, --email         email address to search")
	print("\033[1;33;40m\t-f, --file          File with email accounts to search leaks")
	print("\033[1;33;40m\t-h, --help          Help")
	print("\033[1;33;40m                        ")


# Check the email in Firefox Monitor
def check_email(email):
	pattern = "(^[a-zA-Z-1-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
	result = re.match(pattern, email)
	if (result):
		check_firefox_monitor(email)
		check_pasterbinLeaks(email)
	else:
		print("\033[1;31;40mError: La direccion de correo no esta en un formato correcto")

def parse_firefox_monitor(response):
	start_breachName = response.text.find("breach-title")
	while start_breachName != -1:
		print("\033[1;31;40mLeak Detected!!!")
		start_breachName = start_breachName + 14
		end_breachName = response.text.find("</span>", start_breachName)
		print("\033[1;31;40m\t--> " + response.text[start_breachName:end_breachName])
		end_key = end_breachName
		start_index = response.text.find("breach-key", end_key) + 12
		while start_index > 12:
			end_index = response.text.find("</span>", start_index)
			start_key = response.text.find("breach-value", end_index) + 14
			end_key = response.text.find("</span>", start_key)
			print("\033[1;31;40m\t\t- " + response.text[start_index:end_index] + " " + response.text[start_key:end_key])
			start_index = response.text.find("breach-key", end_key) + 12
		start_breachName = response.text.find("breach-title", end_breachName)

def check_firefox_monitor(email):
	print("\033[1;30;40mChecking email account " + email + " on Firefox Monitor...")
	print("\033[1;30;40m-----------------------------------------------")
	# Extract valid csrf token from request.
	url_form = 'https://monitor.firefox.com'
	headers = {
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url_form)
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
			response = client.post(url, params)
			client.close()
			parse_firefox_monitor(response)
	print("\033[1;30;40m--------------------------------------------------------")
	print("\033[1;30;40m--------------------------------------------------------")

def check_pasterbinLeaks(email):
	print("\033[1;30;40mChecking email account " + email + " on pastebin leaks...")
	print("\033[1;30;40m-----------------------------------------------")
	r = requests.get("https://psbdmp.ws/api/search/" + email)
	resp_json = json.loads(r.text)

	total = resp_json["count"]
	if (total > 0):
		print("\033[1;31;40mThis email account " + email + " appears on pastebin in " + str(
			total) + " results listed bellow:")
		print("\033[1;31;40m ")
		cont = 0
		while (cont <= (total - 1)):
			link = "https://pastebin.com/" + str(resp_json["data"][cont]["id"])
			print(link)
			cont = cont + 1
	else:
		print("\033[1;32;40mThis email account not appears on pastebin leaks")
	print("\033[1;30;40m--------------------------------------------------------")
	print("\033[1;30;40m--------------------------------------------------------")

def emailreputation(email):
	print("\033[1;30;40mChecking emailrep.io for " + email + " account ")
	print("\033[1;30;40m-----------------------------------------------")
	response = requests.get('https://emailrep.io/' + email)
	emailreputation = json.loads(response.text)
	try:
		reputation = emailreputation["reputation"]
		print(response.text)
		credentials_leaked = emailreputation["details"]["credentials_leaked"]
		print(response.text)
		data_breach = emailreputation["details"]["data_breach"]
		last_seen = emailreputation["details"]["last_seen"]
		print(" ")
		print("\033[1;37;40mEmail reputation")
		print("-----------------------------")
		if (credentials_leaked == True or data_breach == True):
			print("\033[1;31;40mThis email account has " + reputation + " reputation\nCredentials leaked? " + str(
				credentials_leaked) + "\nHas data breach? " + str(data_breach) + "\nLast seen: " + str(last_seen))
		else:
			print("\033[1;32;40mThis email account has " + reputation + " reputation\nCredentials leaked? " + str(
				credentials_leaked) + "\nHas data breach? " + str(data_breach))
	except:
		print("\033[1;31;40mError: " + emailreputation["reason"])
	print("\033[1;30;40m--------------------------------------------------------")
	print("\033[1;30;40m--------------------------------------------------------")


# Main function
def main():
	check = False
	check = checkArgs()
	if (check == 1):
		try:
			# check if its email or its file.
			pattern = "(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
			result = re.match(pattern, sys.argv[2])
			if (result):
				print("\033[1;37;40mChecking this email account...")
				print("\033[1;37;40m------------------------------")
				email = sys.argv[2]
				check_email(email)
				emailreputation(email)
		except:
			print("\033[1;31;40mEl formato del email no es correcto o ha habido un problema durante la peticion!")
	elif (check == 2):
		try:
			print("\033[1;37;40mReading file with email accounts...")
			print("\033[1;37;40m-----------------------------------")
			with open(sys.argv[2]) as myfile:
				lines = myfile.readlines()
			for email in lines:
				email = email[0:len(email) - 1]
				check_email(email)
				try:
					emailreputation(email)
				except:
					print("No hay informacion disponible de este email")
		except IOError:
			print("\033[1;31;40mEl formato del fichero no es correcto o bien el fichero no existe")
	elif (check == 0):
		print("\033[1;31;40mOpcion no valida")


# Execute main function
main()
