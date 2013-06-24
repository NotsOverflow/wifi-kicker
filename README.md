wifi-kicker
===========

**It's a program that kick automatically peoples that are connected to the same wifi as you do using airmon-ng,airodump-ng and areplay-ng**
**very useful when you need 5 minutes alone in a train station where the wifi is usually saturated**

you need Linux, python 2.7 and aircrack suite

If you append to have 2 wifi card all you have to do is to connect to a wifi and lunch the program

> **wifi-kicker configure itself automatically.**

But you can override automatic configuration by forcing params like this

> **wifi-kicker.py [bssid] [essid] [channel] [interface] [whitelist]**

You can use a whitelist to not kick your cellphone and other friends

### TODO:
	* Make a more flexible use of params 
	* Fix issue with subprocess.Popen and airodump in the long run
	* Use C bindings to comunicate with aircrack tools
	* Get rid of aircrack by crafting packets directly
