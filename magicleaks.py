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
import platform
import urllib
import base64 # for leakpeek
try:
	from googlesearch import search
except ImportError:
	print("No module named 'google' found")
from fpdf import FPDF


sistema = format(platform.system())

######## Global variables
# proxy
tor_proxy = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}

##Global variables

#Nombre de la persona que analizamos.
owner = ""
phone = ""
address = ""

#Variables para imprimir en el informe (en caso de ser necesario)
firefoxmonitor = list()
firefoxmonitor.append(["Source","Date","Compromised Data"])

passwords_list= list()
passwords_list.append(["Source", "Password"])

socialmedia_list = list()

passwords_company_list = list()
passwords_company_list.append(["Email", "Password"])

###################


if (sistema == "Linux"):
	# Text colors
	normal_color = "\33[00m"
	info_color = "\033[1;33m"
	red_color = "\033[1;31m"
	green_color = "\033[1;32m"
	whiteB_color = "\033[1;37m"
	detect_color = "\033[1;34m"
	banner_color="\033[1;33;40m"
	end_banner_color="\33[00m"
elif (sistema == "Windows"):
	normal_color = ""
	info_color = ""
	red_color = ""
	green_color = ""
	whiteB_color = ""
	detect_color = ""
	banner_color=""
	end_banner_color=""

# Output Type
onlyPasswords = False

######### Print banner

print(banner_color+" __  __    _    ____ ___ ____ _     _____    _    _  ______  "+end_banner_color)
print(banner_color+"|  \/  |  / \  / ___|_ _/ ___| |   | ____|  / \  | |/ / ___| "+end_banner_color)
print(banner_color+"| |\/| | / _ \| |  _ | | |   | |   |  _|   / _ \ | ' /\___ \ "+end_banner_color)
print(banner_color+"| |  | |/ ___ \ |_| || | |___| |___| |___ / ___ \| . \ ___) |"+end_banner_color)
print(banner_color+"|_|  |_/_/   \_\____|___\____|_____|_____/_/   \_\_|\_\____/ "+end_banner_color)
print(banner_color+"                                                             "+end_banner_color)
print(green_color+"["+red_color+"+"+green_color+"]"+whiteB_color+" By Magichk                                               "+end_banner_color)
print(green_color+"["+red_color+"+"+green_color+"]"+whiteB_color+" Collaborators: BinaryShadow                              \n"+end_banner_color)


######### Check Arguments
def checkArgs():
	parser = argparse.ArgumentParser()
	parser = argparse.ArgumentParser(description=red_color + 'MagicLeaks 2.0\n' + info_color)
	parser.add_argument('-e', "--email", action="store",
						dest='email',
						help="Email address to search.")
	parser.add_argument('-f', "--file", action="store",
						dest='file',
						help="File with email accounts to search leaks.")
	parser.add_argument('-d', "--domain", action="store",
						dest='domain',
						help="Domain to search email leaks")
	parser.add_argument('-t', "--tor", action="store_true",
						help="Use Tor to search leaks in onion sites, need also set the domain or file.")
	parser.add_argument("--pdf", action="store_true",
				help="Generate a report from results in PDF file")
	parser.add_argument('-oP', "--onlyPasswords", action="store_true",
						help="Return only the ouput in format -> user@domain:password.")
	parser.add_argument('-mD', "--makeDict", action="store_true",
						help="Make a Dictionary with some username masks, only works with -d or with -oP option")
	parser.add_argument('-p', "--pgp", action="store_true",
						dest='pgp',
						help="Obtain pgp key if exists")
	parser.add_argument('-a', "--avast", action="store_true",
						dest='avast',
						help="Check list of breaches in Avast service. NOTE: Take care, this service send an email to the checked account. Only works without --domain and --file options")

	args = parser.parse_args()
	if (len(sys.argv)==1) or (args.tor==True and (not args.email and not args.file and not args.domain)):
		parser.print_help(sys.stderr)
		sys.exit(1)
	return args


############ Script functions ##############
# Check the email in Firefox Monitor
def check_email(email):
	if not onlyPasswords:
		print(whiteB_color + "----------------------------------------\nChecking email account " + email + " ...\n----------------------------------------")
	pattern = "(^[a-zA-Z-0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
	result = re.match(pattern, email)
	if (result):
		if not onlyPasswords:
			try:
				check_firefox_monitor(email)
				print (" ")
				check_pastebinLeaks(email)
				print (" ")
				emailreputation(email)
				print (" ")
				sistema = format(platform.system())
				#Have I been pwned only works with linux systems now.
				if (sistema == "Linux"):
					haveibeenpwned(email)
				print (" ")
				haveibeensold(email)
				print (" ")
			except:
				pass
		if (args.tor):
			tor_main(email)
			print (" ")
		try:
			leakpeek(email)
			print (" ")
		except:
			pass

		#Search this user in possible social media accounts
		try:
			print(info_color + "--------------------\nChecking social media possible accounts for this email address ...\n--------------------")
			thatsthem(email)
			publicemailrecords(email)
			usersearch(email)
			gitlab(email)
			github(email)
			picuki(email)
		except:
			pass

	else:
		print(red_color + "Error: " + email + " is not a valid email (bad format email)" + normal_color)
	if not onlyPasswords:
		print(whiteB_color + "----------------------------------------\n----------------------------------------")


def parse_firefox_monitor(response):
	global firefoxmonitor
	start_breachName = response.text.find("breach-title")
	leaks = False
	date=""
	compromised_data=""
	flag = 0

	while start_breachName != -1:
		leaks = True
		print(whiteB_color +"Leak Detected!!!")
		start_breachName = start_breachName + 14
		end_breachName = response.text.find("</span>", start_breachName)
		service = response.text[start_breachName:end_breachName]
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
			if (flag == 0):
				date=key
				flag = 1
			else:
				compromised_data = key
				flag = 0

			start_index = response.text.find("breach-key", end_key) + 12
		start_breachName = response.text.find("breach-title", end_breachName)
		firefoxmonitor.append([service,date,compromised_data])


	if not leaks:
		print(green_color + "This email account not appears on Firefox Monitor")
	return firefoxmonitor

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
		print(whiteB_color + "This email account appears on pastebin in " + red_color + str(
			total) +  whiteB_color + " results listed bellow:" + red_color)
		cont = 0
		while (cont <= (total - 1)):
			link = "\thttps://pastebin.com/" + str(resp_json["data"][cont]["id"])
			print(link)
			cont = cont + 1
	else:
		print(green_color + "This email account not appears on pastebin leaks")


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
			print(whiteB_color + "This email account has " + red_color + reputation + " reputation\n" +
				whiteB_color + "Credentials leaked? " + red_color + str(
				credentials_leaked) + whiteB_color + "\nHas data breach? " + red_color + str(data_breach) +
				whiteB_color + "\nLast seen: " + red_color + str(last_seen))
		else:
			print(green_color + "This email account has " + reputation + " reputation\nCredentials leaked? " + str(
				credentials_leaked) + "\nHas data breach? " + str(data_breach))
	except:
		print(red_color + "Error: " + emailreputation["reason"])


#Search have I been pwned.
def haveibeenpwned(email):
	global firefoxmonitor

	print(info_color + "--------------------\nChecking breaches on haveibeenpwned.com...\n--------------------")

	email = email.replace("@","%40") #Replace @ with url encode character
	url = "https://haveibeenpwned.com/unifiedsearch/" + email
	headers = {
		#'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
		'User-Agent': 'Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0', "Accept-Language": "en-US,en;q=0.5"}
	newclient = requests.Session()
	newclient.headers.update(headers)
	response = newclient.get(url, proxies=None)

	total = 0
	try:
		resp_json = json.loads(response.text)

		inicio = 0
		total = 0
		while (inicio != -1):
			inicio = response.text.find("BreachDate", inicio)
			if (inicio != -1):
				total = total + 1
			inicio = response.text.find("BreachDate", inicio+1)

		print(whiteB_color+"Total leaks detected on haveIbeenpwned: " + red_color + str(total))
		cont = 0

		while (cont < total):
			print(whiteB_color +"Leak Detected!!!" + "\n" + red_color + "--> " + resp_json["Breaches"][cont]["Name"] + "\n\t" + red_color + "- Breach Date:" + resp_json["Breaches"][cont]["BreachDate"]+"\n\t- Is Verified? "+ str(resp_json["Breaches"][cont]["IsVerified"]))
			firefoxmonitor.append([resp_json["Breaches"][cont]["Name"],resp_json["Breaches"][cont]["BreachDate"],""])
			cont = cont + 1
	except:
		pass

	if (total == 0):
		print (green_color + "No breaches detected in have I been pwned")

#Search account into publicemailrecords.
def publicemailrecords(email):
	global owner
	global address
	flag = 0
	url = 'http://publicemailrecords.com/find_emails'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	params = {"email": email}
	response = client.post(url, params, proxies=tor_proxy)

	#print (response.text)

	inicio = response.text.find("Best estimate address")
	if (inicio != -1):
		inicio = response.text.find(":", inicio)
		inicio = inicio + 1
		fin = response.text.find(",", inicio)
		if (fin != -1):
			location = response.text[inicio:fin]

	inicio = response.text.find('id="hidden-address" value="')
	if (inicio != -1):
		inicio = inicio + 29
		fin = response.text.find(", HI", inicio)
		if (fin != -1):
			address = response.text[inicio:fin]
			address = address.replace("n?", "nº")

	inicio = 0
	while (inicio != -1):
		inicio = response.text.find("<h2>", inicio)
		if (inicio != -1):
			inicio2 = response.text.find("results")
			if (inicio2 == -1):
				inicio = inicio + 4
				fin = response.text.find("</h2>", inicio)
				if (fin != -1):
					owner = response.text[inicio:fin]
					flag = 1
			else:
				inicio = response.text.find("<h2>", inicio+1)


	if (flag == 1):
		print(info_color + "--------------------\nChecking personal information about this email account in publicemailrecords.com ...\n--------------------")
		print(green_color + "The owner of this email account is: " + owner)
		print(green_color + "The location of " + owner + " is: " + address)
		print(" ")
		google(owner,email)
		print ("")

	client.close()


def usersearch(email):
	fin = email.find("@")
	user = email[0:fin]

	#print(info_color + "--------------------\nChecking social media possible accounts for this email address in usersearch.org ...\n--------------------")

	url = 'https://usersearch.org/results_normal.php'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	params = {"ran":"5ef471c71ae996.70559847","username": user}
	response = client.post(url, params, proxies=tor_proxy)

	inicio = response.text.find('<div class="results-button-wrapper"')
	while (inicio != -1):
		inicio = response.text.find("http", inicio)
		if (inicio != -1):
			fin = response.text.find("target", inicio)
			if (fin != -1):
				socialmedia = response.text[inicio:fin-2]
				print(whiteB_color + "It's possible that the user has the following social media account: " + green_color + socialmedia)
				socialmedia_list.append([socialmedia])
		inicio = response.text.find('<div class="results-button-wrapper"', fin)



def thatsthem(email):
	global owner
	global phone
	#email = email.replace("@","%40") #Replace @ with url encode character
	url = 'https://thatsthem.com/'
	url1 = 'https://thatsthem.com/email/' + email
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url, proxies=None)
	response = client.get(url1, proxies=None)

	inicio = 0
	flag = 0
	inicio = response.text.find('class="web"')
	if (inicio != -1):
		inicio = response.text.find(">", inicio)
		inicio = inicio + 1
		fin = response.text.find("</a>", inicio)
		if (fin != -1):
			owner = response.text[inicio:fin]

	inicio = response.text.find('<span class="street">')
	if (inicio != -1):
		inicio = response.text.find(">", inicio)
		inicio = inicio + 1
		fin = response.text.find("</span>", inicio)
		if (fin != -1):
			address = response.text[inicio:fin]

	inicio = response.text.find('<span class="city">')
	if (inicio != -1):
		inicio = response.text.find(">", inicio)
		inicio = inicio + 1
		fin = response.text.find("</span>", inicio)
		if (fin != -1):
			city = response.text[inicio:fin]

	inicio = response.text.find('telephone')
	if (inicio != -1):
		inicio = inicio + 13
		fin = response.text.find('"', inicio)
		if (fin != -1):
			phone = response.text[inicio:fin]

	try:
		print(info_color + "--------------------\nChecking personal information about this email account in thatsthem.com ...\n--------------------")
		if (owner):
			print(green_color + "The owner of this email account is: " + owner)
		print(green_color + "The location of " + owner + " is: " + address + " from " + city)
		print(green_color + "This is a phone from " + owner + " : " + str(phone))
		print(" ")
		google(owner,email)
		print ("")
	except:
		pass

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
				if onlyPasswords:
					dataLeak.append(leak.split("[luser] =>")[1].split("[")[0].strip() + "@" +
						leak.split("[domain] =>")[1].split("[")[0].strip() + ":" +
						leak.split("[password] =>")[1].split(")")[0].strip())
				else:
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
		if  not onlyPasswords:
			print(info_color + "--------------------\nChecking leaks on tor...\n--------------------")
		passwords = pwndb_main(email, False)
		if  not onlyPasswords:
			if not passwords:
				print (green_color + "No leaks found" + normal_color)
			for i in passwords:
				print (whiteB_color + "This is a password leaked for this email account: " + red_color + str(i) + normal_color)
				passwords_list.append(["TOR",i])
				if (args.makeDict):
					makeDict(email+":"+str(i))
		else:
			for i in passwords:
				print (email+ ":" + str(i))
	except:
		print (red_color + "You have problems with your connection to the tor proxy or pwndb is not accessible." + normal_color)

def makeDict(email):
	nuevofichero = open("dict.txt" , "a+")
	nuevofichero.write(email+"\n")

	inicio = email.find("-")
	if (inicio == -1):
		fin = email.find("@")
		if (fin != -1):
			nombre = email[0:fin] #get email name before @.
			inicio = email.find(":")
			if (inicio != -1):
				inicio = inicio + 1
				fin = len(email)+1
				password = email[inicio:fin]

				#write in our dict
				nuevofichero.write(nombre+":"+password+"\n")

				inicial = nombre[0:1]
				inicio = nombre.find(".")
				if (inicio != -1):
					inicio = inicio + 1
					fin = len(nombre)
					if (fin != -1):
						nuevonombre = inicial+nombre[inicio:fin]
						nuevofichero.write(nuevonombre+":"+password+"\n")

				inicio = nombre.find(".")
				if (inicio != -1):
					nuevonombre = nombre[0:inicio]
					inicio = inicio + 1
					inicial = nombre[inicio:inicio+1]
					nuevonombre = nuevonombre + inicial
					nuevofichero.write(nuevonombre+":"+password+"\n")

				inicial = nombre[0:1]
				inicio = nombre.find(".")
				if (inicio != -1):
					inicio = inicio + 1
					fin = len(nombre)
					if (fin != -1):
						nuevonombre = nombre[inicio:fin] + inicial
						nuevofichero.write(nuevonombre+":"+password+"\n")

	nuevofichero.close()

def searchpgp(email):
	print(info_color + "--------------------\nChecking PGP key for this email account...\n--------------------")
	email = email.replace("@","%40") #Replace @ with url encode character
	url = 'https://pgp.surfnet.nl/pks/lookup?search='+email+'&fingerprint=on&op=index'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
	client.headers.update(headers)
	response = client.get(url, proxies=None,timeout=90)

	inicio = response.text.find("op=get")

	found = 0

	if (inicio != -1):
		inicio = response.text.find("href=")
		inicio = inicio + 6
		fin = response.text.find("\"", inicio)
		if (fin != -1):
			print (green_color + "[+] PGP Key found!")
			print ("")
			found = 1
			link = response.text[inicio:fin]
			link = link.replace("&amp;", "&")
			url= "https://pgp.surfnet.nl" + link
			client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
			client.headers.update(headers)
			get_page = urllib.request.urlopen(url)
			response = get_page.readlines()


			flag = 0

			for line in response:
				line = line.decode("utf-8")
				line = line[0:len(line)-1]
				line = str(line)
				if (flag == 1):
					inicio = line.find("pre>")
					if (inicio != -1):
						flag = 0
					else:
						print (red_color + line)
				else:
					inicio = line.find("pre>")
					if (inicio != -1):
						flag = flag + 1

	if (found == 0):
		print (green_color + "[+] No PGP Key found!")

def gitlab(email):
	global owner
	fin = email.find("@")
	user = email[0:fin]

	url = 'https://gitlab.com/users/'+str(user)+'/exists'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session() #Make a Dictionary with some username masks, only works with -d or with -oP option
	client.headers.update(headers)
	response = client.get(url, proxies=None)
	for obj in response:
		inicio = obj.find(b"true")
		if (inicio != -1):
			print(whiteB_color + "It's possible that the user has the following Gitlab account: " + green_color + 'https://gitlab.com/users/'+str(user))
			url = "https://gitlab.com/users/" + str(user)
			client = requests.Session()
			client.headers.update(headers)
			get_page = urllib.request.urlopen(url)
			response = get_page.readlines()

			for line in response:
				line = line.decode("utf-8")
				inicio = line.find('property="og:title"')
				if (inicio != -1):
					inicio = line.find("content=")
					if (inicio != -1):
						inicio = inicio + 9
						fin = line.find("\"", inicio)
						if (fin != -1):
							owner = line[inicio:fin]
							google(owner,email)
							socialmedia_list.append([url])

def avast(email):
	print(info_color + "--------------------\nSending an email with account leaks to "+ email + " with Avast service...\n--------------------")
	url = "https://digibody.avast.com/v1/web/email/subscribe"
	url2 = "https://digibody.avast.com/v1/web/leaks"

	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5", "Accept": "application/json, text/plain, */*", "Referer": "https://www.avast.com/", "Origin": "https://www.avast.com"}
	client = requests.Session()
	client.headers.update(headers)
	params = {"email": email}
	response = client.post(url, json={"email": email})

	response2 = client.post(url2, json={"email": email})

	client.close()

	print (green_color + "["+ red_color + "+" + green_color +"]" + whiteB_color + " Email send ok!")


def picuki(email):
	global owner
	fin = email.find("@")
	user = email[0:fin]

	url = 'https://www.picuki.com/profile/' + user
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url, proxies=None)


	inicio = response.text.find("profile-name-top")
	if (inicio != -1):
		print(whiteB_color + "It's possible that the user has the following picuki account: " + green_color + 'https://www.picuki.com/profile/'+str(user))
		print(whiteB_color + "It's possible that the user has the following instagram account: " + green_color + 'https://www.instagram.com/'+str(user))
		print ("")

	inicio = response.text.find("profile-name-bottom")
	if (inicio != -1):
		inicio = response.text.find(">", inicio)
		if (inicio != -1):
			inicio = inicio + 1
			fin = response.text.find("<", inicio)
			if (fin != -1):
				owner = response.text[inicio:fin]
				print (whiteB_color + "The name of this user is: " + green_color + owner)
				google(owner, email)


def haveibeensold(email):
	fin = email.find("@")

	print(info_color + "--------------------\nChecking haveibeensold.app service...\n--------------------")

	url = 'https://haveibeensold.app/api/api.php'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	params = {"email": email, "action": "check"}
	response = client.post(url, params)

	inicio = response.text.find('"data":[]')
	if (inicio != -1):
		print(green_color + "[+] This email account is not on any sold list we are currently aware of!")
	else:
		print(red_color + "[-] This email account is on a list of accounts that are sold")


def leakpeek(email):
	global passwords_list
	fin = email.find("@")

	print(info_color + "--------------------\nChecking leakpeek.com service...\n--------------------")

	url = 'https://leakpeek.com/'
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36', "Accept-Language": "en-US,en;q=0.5"}
	client = requests.Session()
	client.headers.update(headers)
	response = client.get(url)

	url = 'https://leakpeek.com/inc/iap3?t=1606297345&input=' + email
	response2 = client.get(url)

	myjson = json.loads(response2.text)

	flag = 0

	for object in myjson:
		if (object == "found"):
			if (myjson[object] != None):
				print (green_color+"[" + whiteB_color + "+" + green_color + "]" + whiteB_color + " Total of leaked passwords found: " + red_color + str(myjson[object]))

				for object in myjson["result"]:
					b64pass = object["password"]
					base64_bytes = b64pass.encode('ascii')
					message_bytes = base64.b64decode(base64_bytes)
					password = message_bytes.decode('ascii')
					print (whiteB_color + "This is a password leaked for this email account: " + red_color + str(password) + normal_color)
					passwords_list.append(["LeakPeek", password])

				flag = 1

	if (flag == 0):
		print (green_color+"[" + whiteB_color + "-" + green_color + "] No leaked passwords for this email account in leakpeek.com!")

def github(email):
	global owner
	fin = email.find("@")
	name = email[0:fin]
	name = name.replace(".","")
	print ("")
	print(info_color + "--------------------\nSearching user in github.com...\n--------------------")

	url = 'https://github.com/' + name
	get_page = urllib.request.urlopen(url)
	response = get_page.readlines()

	flag = 0

	for line in response:
		line = line.decode("utf-8")

		if (flag == 1):
			owner = line.strip()
			print(whiteB_color + "Github repository: " + green_color + url)
			socialmedia_list.append([url])
			if owner:
				print(whiteB_color + "The owner of this email account is: " + green_color + owner)
			flag = 0

		inicio = line.find('itemprop="name"')
		if (inicio != -1):
			flag = 1 #Next line is the line that contains Name

		#Obtain company
		inicio = line.find('class="p-org"')
		if (inicio != -1):
			inicio = line.find("<div>", inicio)
			inicio = inicio + 5
			fin = line.find("</div>", inicio)
			if (fin != -1):
				company = line[inicio:fin]
				cleanr = re.compile('<.*?>')
				company = re.sub(cleanr, '', company)
				print(whiteB_color + "Company: " + green_color + company)

		inicio = line.find('rel="nofollow me" class="Link--primary')
		if (inicio != -1):
			inicio = line.find("href")
			if (inicio != -1):
				inicio = inicio + 6
				fin = line.find('"', inicio)
				link = line[inicio:fin]
				print (green_color + "["+red_color+"+"+green_color+"]"+whiteB_color+" Link found: " + green_color + link)
				socialmedia_list.append([link])

	if owner:
		google(owner, email)

def google(query,email):
	global socialmedia_list
	print (info_color + "--------------------\nSearching in Google: " + query + "...\n--------------------")
	inicio = email.find("@")
	fin = email.find(".", inicio)
	tld = email[inicio+1:fin]
	flag = 0
	if tld in "gmail, hotmail, protonmail":
		tld2 = tld
		tld=""
		flag = 1

	query = query + " " + tld
	for j in search(query, tld="co.in", num=4, stop=4, pause=2):
		print(green_color + "["+red_color+"+"+green_color+"]"+whiteB_color+" Link Found: " + green_color+j)
		socialmedia_list.append([j])
	#if (flag == 1):
	#	for j in search(query+" "+tld2, tld="co.in", num=4, stop=4, pause=2):
	#		print(green_color + "["+red_color+"+"+green_color+"]"+whiteB_color+" Link Found: " + green_color+j)



def generateuserpdf(email):
	global firefoxmonitor
	global owner
	global address
	global passwords
	global socialmedia_list
	RRSS_Strings = {'fotolog', 'dropbox', 'shein', 'facebook'}
	TLD_domains = {'gmail.com', 'outlook.es', 'hotmail.com', 'hotmail.es', 'protonmail.com'}

	inicio = email.find("@")
	if (inicio != -1):
		tld = email[inicio+1:len(email)]

	print (info_color + "--------------------\nGenerating PDF File with results...\n--------------------")
	pdf = FPDF()
	pdf.add_page()
	#Header
	pdf.set_font('Helvetica', 'B', 8)
	pdf.cell(130)
	pdf.cell(60,1,'Magicleaks 2.0',0,0,'R')
	pdf.ln(20)

	#Title
	pdf.set_font('Helvetica', 'B', 12)
	pdf.cell(40, 10, 'Email account analyzed: ' + email)
	pdf.ln(10)

	#Owner
	if (owner):
		pdf.set_font('Helvetica', 'B', 10)
		pdf.cell(40, 10, 'User Owner: ' + owner)
		pdf.ln(10)

	if (phone):
		pdf.set_font('Helvetica', '', 10)
		pdf.cell(40, 10, 'Phone: ' + str(phone))
		pdf.ln(10)

	if (address):
		pdf.set_font('Helvetica', '', 10)
		pdf.cell(40, 10, 'Address: ' + address)
		pdf.ln(10)

	#################################
	#Body
	#################################
	#Firefox Monitor
	#################################

	# Effective page width, or just epw
	epw = pdf.w - 2*pdf.l_margin

	col_width = epw/3

	th = pdf.font_size
	# Line break equivalent to 4 lines
	pdf.ln(4*th)

	pdf.set_font('Times','B',14.0)
	pdf.cell(epw, 0.0, 'Data Breaches', align='L')
	pdf.set_font('Times','',10.0)
	pdf.ln(5)

	# Here we add more padding by passing 2*th as height
	flag = 0
	for row in firefoxmonitor:
		for datum in row:
			# Enter data in colums
			#datum = datum.decode('utf-8')
			try:
				if (flag == 0):
					data = datum.lower()
					if tld not in TLD_domains:
						if data in RRSS_Strings:
							flag = 1
				pdf.cell(col_width, 2*th, str(datum), border=1)
			except:
				pass


		pdf.ln(2*th)

	#Passwords leaked
	epw = pdf.w - 2*pdf.l_margin

	col_width = epw/3

	th = pdf.font_size
	# Line break equivalent to 4 lines
	pdf.ln(4*th)

	pdf.set_font('Times','B',14.0)
	pdf.cell(epw, 0.0, 'Leaked Passwords', align='L')
	pdf.set_font('Times','',10.0)
	pdf.ln(5)

	# Here we add more padding by passing 2*th as height
	for row in passwords_list:
		for datum in row:
			# Enter data in colums
			#datum = datum.decode('utf-8')
			try:
				pdf.cell(col_width, 2*th, str(datum), border=1)
			except:
				pass


		pdf.ln(2*th)

	if (flag == 1):
		epw = pdf.w - 2*pdf.l_margin

		col_width = epw/1

		th = pdf.font_size
		# Line break equivalent to 4 lines
		pdf.ln(4*th)

		pdf.set_font('Times','',10.0)
		pdf.ln(5)
		pdf.cell(col_width, 2*th, "[+] Social network leaks detected in a company email!", border=1)

	if (socialmedia_list):

		# Effective page width, or just epw
		epw = pdf.w - 2*pdf.l_margin

		col_width = epw/1

		th = pdf.font_size
		# Line break equivalent to 4 lines
		pdf.ln(4*th)

		pdf.set_font('Times','B',14.0)
		pdf.cell(epw, 0.0, 'RRSS', align='L')
		pdf.set_font('Times','',10.0)
		pdf.ln(5)

		# Here we add more padding by passing 2*th as height
		for row in socialmedia_list:
			pdf.cell(col_width, 2*th, str(row), border=1)
			pdf.ln(2*th)

	pdf.output(email+'.pdf', 'F')

def generatecompanypdf(domain):
	global passwords_company_list
	print (info_color + "--------------------\nGenerating PDF File with results...\n--------------------")
	pdf = FPDF()
	pdf.add_page()
	#Header
	pdf.set_font('Helvetica', 'B', 8)
	pdf.cell(130)
	pdf.cell(60,1,'Magicleaks 2.0',0,0,'R')
	pdf.ln(20)

	#Title
	pdf.set_font('Helvetica', 'B', 12)
	pdf.cell(40, 10, 'Domain Analyzed: ' + domain)
	pdf.ln(10)


	#Passwords leaked
	epw = pdf.w - 2*pdf.l_margin

	col_width = epw/3

	th = pdf.font_size
	# Line break equivalent to 4 lines
	pdf.ln(4*th)

	pdf.set_font('Times','B',14.0)
	pdf.cell(epw, 0.0, 'Leaked Passwords', align='L')
	pdf.set_font('Times','',10.0)
	pdf.ln(5)

	# Here we add more padding by passing 2*th as height
	for row in passwords_company_list:
		for datum in row:
			# Enter data in colums
			#datum = datum.decode('utf-8')
			try:
				pdf.cell(col_width, 2*th, str(datum), border=1)
			except:
				pass


		pdf.ln(2*th)

	pdf.output(domain+'.pdf', 'F')


def emailProcess(args, email=""):
	if not email:
		email = args.email
	if args.tor:
		if sistema == "Linux":
			os.system("killall -HUP tor")
	check_email(email)
	if args.avast and not args.domain and not args.file:
		avast(email)
	if args.pgp:
		searchpgp(email)

########## Main function #################3
if __name__ == "__main__":
	args = checkArgs()
	onlyPasswords = args.onlyPasswords
	if args.tor:
		sistema = format(platform.system())
		if sistema == "Linux":
			tor_service = os.system("service tor status >> /dev/null")
			if tor_service != 0:
				print(red_color + "Tor service no started. You need started this to execute this option.")
				exit(1)
	elif sistema == "Windows":
		tor_proxy = {'http': 'socks5h://127.0.0.1:9150', 'https': 'socks5h://127.0.0.1:9150'}
	else:
		tor_proxy = None
	if args.email:
		emailProcess(args)
		if args.pdf:
			generateuserpdf(args.email)
	if args.file:
		try:
			if not onlyPasswords:
				print(whiteB_color + "--->Reading file with email accounts...<---")
			with open(sys.argv[2]) as myfile:
				lines = myfile.readlines()
			if args.avast:
				print(red_color + "Avast feature is only intended to be used with your own email address and not on a list of emails."+ normal_color)

			for email in lines:
				emailProcess(args, email[0:len(email) - 1])
		except IOError:
			print(red_color + "Error: The file not exist or bad format.")
	if args.domain:
		domain = args.domain
		pwndb_online = True
		try:
			if not args.tor:
				print(red_color + "Error: This functionality need tor to work.")
				exit(1)
				domain = args.domain
			if domain[0] != '@':
					domain = '@' + domain
			if not onlyPasswords:
				print(whiteB_color + "--->Searching email accounts leaks on " + domain + " domain...<---")
			try:
				email_list = pwndb_main(domain, True)
			except:
				print(red_color + "You have problems with your connection to the tor proxy or pwndb is not accessible." + normal_color)
				pwndb_online=False

			if pwndb_online:
				if not email_list:
					print(green_color + "No leaks found for this domain" + normal_color)
				elif onlyPasswords:
					for line in email_list:
						fin = line.find(":", 0)
						print(whiteB_color + line[0:fin]+ banner_color + ":" + red_color + line[fin+1:len(line)])
						passwords_company_list.append([line[0:fin], line[fin+1:len(line)]])
						if args.makeDict:
							makeDict(line)
					if args.makeDict:
						print("")
						print(green_color + "["+red_color+"+"+green_color+"] "+whiteB_color+" The dict is created successfully and saved into dict.txt in this folder")
						print(banner_color + "* In order to use it with Burp Suite use intruder module with "+red_color+"PITCHFORK " +banner_color+ "attack type and "+red_color+"PROCESS PAYLOAD"+banner_color+" with a "+red_color+"Match/Replace"+banner_color+" adding a regex "+red_color+"(.*):"+banner_color+" for username"+banner_color+" and "+red_color+":(.*) "+banner_color+"for password")
				else:
					print(whiteB_color + "Found " + str(len(email_list)) + " accounts with leaks in selected domain: \n" + red_color + ' || '.join(email_list))
					if args.avast:
						print(red_color + "Avast feature is only intended to be used with your own email address and not on a domain."+ normal_color)
					for email in email_list:
						emailProcess(args, email)
				if args.pdf:
					generatecompanypdf(args.domain)
		except IOError:
			print(red_color + "Error: Unknow error.")