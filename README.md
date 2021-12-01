## **MagicLeaks**

### Project description
A python3 script for search possible email account leaks. This project is for educational use, we are not responsible for its misuse.

### Dependencies
You can install the dependencies using the requests.txt file:
```pip3 install -r requirements.txt```

* Note: The new versions of tor package not works properly with magicleaks. So please, install a version before 0.4.6.XX-X , for example this package https://packages.debian.org/bullseye/amd64/tor/download in case if you use a debian distribution.

If you have alredy installed a new version of tor service, follow this steps in order to downgrade the version of the package:

```
1.- sudo apt-get purge tor --remove 
2.- Download tor package , for example this for debian based distributions https://packages.debian.org/bullseye/amd64/tor/download
3.- chmod +x tor_0.4.5.10-1\~deb11u1_amd64.deb
4.- sudo dpkg -i tor_0.4.5.10-1\~deb11u1_amd64.deb
```


### Checks
    - Firefox monitor
    - Pastebin leaks
    - Email reputation
    - Have I Been Pwned
    - Public Mail Records
    - Usersearch
    - Social network Search like instagram, github and more
    - Thatsthem
    - haveibeensold.app
    - leakpeek
    - PGP Public Keys search
    - pwndb2am4tzkvold.onion (Using tor service)
    - Avast Hack Check (Take care, this service send an email to the account checked)

### Options available
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-menu.png "MagicLeaks - menu")

### Example Magicleaks with a clean email
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-ok.png "MagicLeaks - OK")

### Example Magicleaks with a compromised email account
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-bad1.png "MagicLeaks - Compromised1")
![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-bad2.png "MagicLeaks - Compromised2")

### Relationship between email and people
In some cases the tool can identify people by his email account. In this cases, maybe, the tool can obtain the physical address too.

![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/magicleaks-identify.png "MagicLeaks - Identify")


**-> In order to use tor version: you need install tor service on your system, start the service and execute the script with root privileges with -t flag.**

### File mode usage:
The required file needs one email account per line.

### Extra
Initial support for Windows environments but this tool is make it for Linux environments.

![alt text](https://raw.githubusercontent.com/magichk/magicleaks/master/images/windows.png "MagicLeaks - Windows")
