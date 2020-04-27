## **MagicLeaks**

### Project description
A python3 script for search possible email account leaks. This project is for educational use, we are not responsible for its misuse.

### Dependencies
You can install the dependencies using the requests.txt file:
```pip3 install -r requirements.txt```

### Checks
    - Firefox monitor
    - Pastebin leaks
    - Email reputation
    - Have I Been Pwned
    - pwndb2am4tzkvold.onion (Using tor service)

### Example Magicleaks with a clean email
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-ok.png "MagicLeaks - OK")

### Example Magicleaks with a compromised email account
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-bad1.png "MagicLeaks - Compromised1")
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-bad2.png "MagicLeaks - Compromised2")


**-> In order to use tor version: you need install tor service on your system, start the service and execute the script with root privileges with -t flag.**

### File mode usage:
The required file needs one email account per line

## TODO:
- Add option to dump data in cvs/json format.
