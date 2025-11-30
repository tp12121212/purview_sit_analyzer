**Here’s how ViewPower handles *admin password resets* and how you can recover access depending on the version you’re using. The software is a bit old‑school, so the methods depend on whether you’re using the standard ViewPower, ViewPower Pro, or the Network Edition (HTML version).**  
  
**I’ll lay out the practical recovery paths.**  
  
⸻  
  
**1. ViewPower (Standard / Local Install, Windows or Linux)**  
  
**This is the version where ViewPower runs as a local service and you access it via browser (http://localhost:15178 or 15179).**  
  
**Default credentials**  
**	•	User: **administrator  
**	•	Password: **administrator  
  
**If that fails, the reset depends on OS:**  
  
**Windows reset (local install)**  
  
**ViewPower stores its credentials in its program directory. You can reset it by:**  
	1.	**Stop the ViewPower service**  
**	•	Open *Services***  
**	•	Find ViewPowerService (or similarly named)**  
**	•	Stop it**  
	2.	**Navigate to the config directory**  
**Usually:**  
  
```
C:\Program Files (x86)\ViewPower\

```
  
**or**  
  
```
C:\Program Files\ViewPower\

```
  
  
	3.	**Delete the user/password config file**  
**Look for files named:**  
**	•	**user.db  
**	•	**users.xml  
**	•	**vp_users.xml  
**	•	**vp.db  
**Deleting this resets the login database.**  
	4.	**Start the service again**  
**Open your browser → you will be prompted to log in using the defaults:**  
**	•	**administrator** / **administrator  
  
**Linux reset**  
  
**For Linux versions (daemon mode or GUI):**  
	1.	Stop the daemon using:  
  
```
sudo /etc/init.d/vpdaemon stop

```
  
**or**  
  
```
sudo systemctl stop viewpower

```
  
  
	2.	Navigate to the install directory:  
Common locations:  
	•	/usr/local/ViewPower/  
**	•	**/opt/ViewPower/  
**	•	**/etc/ViewPower/  
	3.	Delete the credential DB file:  
Usually called:  
	•	vp_users.xml  
**	•	**user.db  
	4.	Restart the daemon  
  
```
sudo systemctl start viewpower

```
  
**or**  
  
```
sudo /etc/init.d/vpdaemon start

```
  
  
  
**Login returns to: **administrator / administrator**.**  
  
⸻  
  
**2. ViewPower Pro (Enterprise Version)**  
  
**This version supports more network UPS units.**  
  
**Password reset process:**  
**	•	Uses an internal SQLite database (**vp.db**)**  
**	•	Reset by renaming or deleting the database**  
**	•	On startup, the system re‑creates the DB and resets the login**  
  
**Location:**  
  
```
C:\Program Files\ViewPower Pro\db\

```
  
**Default login restored:**  
```
administrator / administrator

```
  
⸻  
  
**3. ViewPower Network Edition (Web HTML interface)**  
  
**This is the one many people install now because it’s cross-platform.**  
  
**Reset method:**  
	1.	Stop service (vpnet** or **viewpowernetd**)**  
	2.	Go to the install folder  
	3.	Delete the folder:  
  
```
/config/users/

```
  
**or file:**  
  
```
user-config.js

```
  
  
  
**After restart, default login is restored:**  
```
administrator / administrator

```
  
⸻  
  
**If you want, I can walk you through the exact reset path for:**  
**	•	Windows**  
**	•	Debian**  
**	•	Ubuntu**  
**	•	macOS**  
**	•	Or whichever OS you plan to install this on**  
  
**Just tell me your OS and ViewPower edition.**  
