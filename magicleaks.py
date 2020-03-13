#!/usr/bin/python3

#Librerias importadas de 3os
import requests #Request to external site or api
import urllib3 #Request to external site or api 
import sys #To read arguments
import json #To parse json response
import re #To parse regular expressions

#Print banner

print ("\033[1;33;40m __  __    _    ____ ___ ____ _     _____    _    _  ______  ")
print ("\033[1;33;40m|  \/  |  / \  / ___|_ _/ ___| |   | ____|  / \  | |/ / ___| ")
print ("\033[1;33;40m| |\/| | / _ \| |  _ | | |   | |   |  _|   / _ \ | ' /\___ \ ")
print ("\033[1;33;40m| |  | |/ ___ \ |_| || | |___| |___| |___ / ___ \| . \ ___) |")
print ("\033[1;33;40m|_|  |_/_/   \_\____|___\____|_____|_____/_/   \_\_|\_\____/ ")
print ("\033[1;33;40m                                                             ")


#Check Arguments
def checkArgs():
    if len(sys.argv) > 1:
        if (sys.argv[1] == "-e" or sys.argv[1] == "--email"):
            return 1
        elif (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
            helpUsage()
        elif (sys.argv[1] == "-f" or sys.argv[1] == "--file"):
            return 2
        else:
            print ("Argumento no valido")
            print (" ")
            helpUsage()
            return 0
    else:
        helpUsage()


#Help usage
def helpUsage():
    print ("\033[1;33;40mMagicLeaks 0.1 Beta")
    print ("\033[1;33;40mUsage: magicleaks.py [Options] {target specification}")
    print ("\033[1;33;40mOptions Avilable")
    print ("\033[1;33;40m\t-e, --email         email address to search")
    print ("\033[1;33;40m\t-f, --file          File with email accounts to search leaks")
    print ("\033[1;33;40m\t-h, --help          Help")
    print ("\033[1;33;40m                        ")


#Check the email in Firefox Monitor
def check_email(email):
	print("\033[1;30;40mChecking email account " + email + " on pastebin leaks...")
	print ("\033[1;30;40m--------------------------------------------------------")
	pattern = "(^[a-zA-Z-1-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
	result = re.match(pattern, email)
	if (result):
		r = requests.get("https://psbdmp.ws/api/search/"+email)
		resp_json = json.loads(r.text)

		total = resp_json["count"]
		if (total > 0):
			print ("\033[1;31;40mThis email account "+ email + " appears on pastebin in " + str(total) + " results listed bellow:" )
			print ("\033[1;31;40m ")
			cont = 0
			while (cont <= (total-1)):
                		link = "https://pastebin.com/"+str(resp_json["data"][cont]["id"])
		                print(link)
        		        cont = cont + 1
		else:
        	    	print ("\033[1;32;40mThis email account not appears on pastebin leaks")
	else:
		print ("\033[1;31;40mError: La direccion de correo no esta en un formato correcto")


def check_firefox_monitor(email):

        #Extract valid csrf token from request.
        url = 'https://monitor.firefox.com'
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}

        response = requests.get(url, headers=headers)
        inicio = response.text.find("_csrf")
        if (inicio != -1):
            inicio = response.text.find("value", inicio)
            if (inicio != -1):
                inicio = inicio + 7
                fin = response.text.find("\"", inicio)
                csrfToken = response.text[inicio:fin]
                print (csrfToken)

                #Do the query
                url="https://monitor.firefox.com/"
                #headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
                params ={"email":email, "_csrf":csrfToken, "pageToken":"", "scannedEmailId":"","emailHash":""}
                r = requests.get(url=url,params=params)
                print (r.text)
                #data=urllib.parse.urlencode({"email":"joan12.1989@gmail.com", "_csrf":"\""+csrfToken+"\"","Check for Breaches":"1"})
                #response_query = requests.get(url,data=data)
                #response_query = urllib.request.urlopen(url,data)
                #print(response_query.content)

def emailreputation(email):
    print ("\033[1;30;40mChecking emailrep.io for " + email + " account ")
    print ("\033[1;30;40m-----------------------------------------------")
    response = requests.get('https://emailrep.io/'+email)

    emailreputation = json.loads(response.text)
    reputation = emailreputation["reputation"]
    credentials_leaked = emailreputation["details"]["credentials_leaked"]
    data_breach = emailreputation["details"]["data_breach"]
    last_seen = emailreputation["details"]["last_seen"]

    print (" ")
    print ("\033[1;37;40mEmail reputation")
    print ("-----------------------------")
    if (credentials_leaked == True or data_breach == True):
	    print("\033[1;31;40mThis email account has "+reputation+" reputation\nCredentials leaked? " +str(credentials_leaked)+"\nHas data breach? "+str(data_breach)+"\nLast seen: " +str(last_seen))
    else:
	    print("\033[1;32;40mThis email account has "+reputation+" reputation\nCredentials leaked? " +str(credentials_leaked)+"\nHas data breach? "+str(data_breach))


#Main function
def main():
    check = False
    check = checkArgs()
    if (check == 1):
        try:
            #check if its email or its file.
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
                email = email[0:len(email)-1]
                check_email(email)
                try:
                    emailreputation(email)
                except:
                    print("No hay informacion disponible de este email")
        except IOError:
            print ("\033[1;31;40mEl formato del fichero no es correcto o bien el fichero no existe")
    elif (check == 0):
        print ("\033[1;31;40mOpcion no valida")



#Execute main function
main()

