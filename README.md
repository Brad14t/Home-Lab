# Home-Lab


# Overview 

* `pfSense`: Gateway and firewall for network security
* `Kali Linux`: Management virtual machine for penetration testing and security tools
* `Active Directory Lab`: Includes a domain controller and two client machines for directory services practice
* `Malware Analysis Lab`: Dedicated Windows and Linux environments for analyzing malware
* `Security VMs`: Virtual machines configured for digital forensics, incident response (DFIR), and SIEM use cases
* `Cyber Range`: Vulnerable virtual machines designed for Capture The Flag (CTF) and security training exercises


# Installing Virtual Box

Head to this link: `https://www.virtualbox.org/wiki/Downloads` and make sure to download the correct download for the correct Host machine.

I chose Windows.

<img width="221" alt="Screenshot 2025-01-24 091215" src="https://github.com/user-attachments/assets/7f31946c-553a-47cb-b0d7-55c53e497f9b" />

Then make sure to download the VirtualBox Extension Pack.

![Screenshot 2025-01-24 091432](https://github.com/user-attachments/assets/9b390f2a-2ce9-4f84-abb8-50628ba17013)

Select the .exe file and go through the installer, no need to change any settings, just selct ok and finish install.

<img width="196" alt="Screenshot 2025-01-24 091835" src="https://github.com/user-attachments/assets/71056fc0-ac49-49ed-9c79-7811bc016457" />

![Screenshot 2025-01-24 091924](https://github.com/user-attachments/assets/2f3c7ca8-9eb1-4b5f-b2d5-43a6ad934a2d)

# Installing Extension Pack

Inside Virtual Box select `File` -> `Tools` -> `Extension Pack Manager` -> `Install +`

<img width="255" alt="Screenshot 2025-01-24 092358" src="https://github.com/user-attachments/assets/6dcdee00-d14c-4dc0-914d-76c2df345942" />

Select the Extension Pack

<img width="334" alt="Screenshot 2025-01-24 092416" src="https://github.com/user-attachments/assets/e9577a2a-ae9d-4a3b-b63f-3cb68aa75f8e" />

<img width="355" alt="Screenshot 2025-01-24 092432" src="https://github.com/user-attachments/assets/b0755dcf-fd85-4554-b06a-16e7b096a725" />

<img width="445" alt="Screenshot 2025-01-24 092449" src="https://github.com/user-attachments/assets/3e5f21db-a6cc-4f62-b7ba-2c7d645e4c57" />

![Screenshot 2025-01-24 092625](https://github.com/user-attachments/assets/ac72ae90-de64-4fc0-8353-afcd02668850)

Next I want to prepare for downloading lots of data, and I recommend having atleast 250 gigabytes free on your computer. I bought a external HDD to store mine, since I dont have room on my laptop.

To make the changes needed to have the VM's being saved inside the HDD instead of my local drive.

Select `File` -> `Prefrences` -> `Expert` -> `Default Machine Folder` -> Make a new folder within your drive label it anything, I names mine `VMs` -> Select that folder to save VM's in

<img width="472" alt="Screenshot 2025-01-24 093435" src="https://github.com/user-attachments/assets/375a3f1b-a4ce-4587-a7d2-b699f2e4f26d" />

# Setting up Pfsense

* `pfSense Role`: Serves as the default gateway and firewall for the home lab.
* `Boot Priority`: The pfSense VM must be the first virtual machine started.
* `Sequence`: Once the pfSense VM is up and running, other VMs in the lab can be launched.

To download pfsense head to this site: https://atxfiles.netgate.com/mirror/downloads/

This will allow you to download the ISO directly from them

<img width="500" alt="Screenshot 2025-01-24 093954" src="https://github.com/user-attachments/assets/a24288e0-3bf4-44b4-b12e-111c5ebd6571" />

Extract the files to isolate the `.iso` file.

<img width="456" alt="Screenshot 2025-01-24 094444" src="https://github.com/user-attachments/assets/ec41e102-f17c-4a73-a711-5f6dc7db59ff" />

![Screenshot 2025-01-24 094733](https://github.com/user-attachments/assets/f97f25fd-ab88-496c-9a5f-eb4514072223)

# VM Setup (pfSense)

Inside VirtualBox select `Tools` -> `New`

Name the vm anything youd like, I name mine pfSense.

Select the folder you want the VM saved to.

Select the .iso image we just extracted.

Type: BSD

Subtype: Free BSD

Version: Free BSD (64 bit)

<img width="592" alt="Screenshot 2025-01-24 095301" src="https://github.com/user-attachments/assets/909cbdc0-df51-4ad7-bea6-dd2b02e7f270" />

Leave `Unintened Install` alone, and move to `Hardware`

Ill leave the compute the default, and move to the `Hard Disk` option.

![Screenshot 2025-01-24 095631](https://github.com/user-attachments/assets/0b06855b-6f9e-4e39-ab98-7a755100dd39)

In the `Hard Disk` drop down, change the disk to `20 GB`. And select `Finish`

<img width="589" alt="Screenshot 2025-01-24 100208" src="https://github.com/user-attachments/assets/dfd10bda-66a6-42ce-8afc-316a9aa82b1f" />

Once VM is created it will show on the right side. If you would like to have a little more orginization you can add the VM to a group, this isnt needed now, but once you have a few VM's its nice to quickly look and see what VM's are for.

Select the newly created VM -> `Machine` in the top left -> `Move to Group` -> `[New]` -> select the new group -> `Group` -> `Rename Group`

<img width="282" alt="Screenshot 2025-01-24 100805" src="https://github.com/user-attachments/assets/ce47f18e-d1d1-48a3-b9ac-e625af4291c9" />

<img width="372" alt="Screenshot 2025-01-24 100824" src="https://github.com/user-attachments/assets/b3d41fac-1192-4940-8d7d-d3d32383f43b" />

![Screenshot 2025-01-24 100848](https://github.com/user-attachments/assets/89b50212-b43f-4463-b4aa-cf04d09a9b98)

# pfSense VM Configuration Changes

Before starting the VM some changes are needed to the configuration.

First select the `pfSense VM` -> `Settings`-> `Expert` -> `System` -> inside `Motherboard` -> Deselect `Flobby` and move it down to the 3rd position, move `Hard disk` to the 1st spot and `Optical` to 2nd

<img width="574" alt="Screenshot 2025-01-24 102128" src="https://github.com/user-attachments/assets/150a6f82-2122-49f8-841d-d24b32dc667f" />

Next change is `Audio` in the same settings of the VM scroll down to `Audio` -> `Deselect` audio since this is a router it doesnt need audio.

![Screenshot 2025-01-24 102453](https://github.com/user-attachments/assets/2baae548-1845-4368-bfcf-d0438e194f98)

Next is `USB`  this can be deselected to since usb inputs arent needed. Inside the settings of VM scroll down to `USB` -> `Deslect USB controler`

![Screenshot 2025-01-24 103350](https://github.com/user-attachments/assets/2108016d-9be3-497c-8ddf-04639443b4bb)

# Network Configuration

If further Network Configuration instructions or troubleshooting visit: https://www.nakivo.com/blog/virtualbox-network-setting-guide/

Inside `pfSense` vm settings, scroll down to `Network` -> `Adapter ` -> Attached to `NAT` -> Adapter Type: `Paravirtualized Network`

<img width="577" alt="Screenshot 2025-01-24 103533" src="https://github.com/user-attachments/assets/7ce2f7eb-fac9-489c-a4d3-e16093a2c014" />

`Adapter 2` -> Select `Enable Network Adapter` -> Attached to `Internal Network` -> Name `LAN 0` -> Adapter Type `Paravirtualized Network`

![Screenshot 2025-01-24 104515](https://github.com/user-attachments/assets/c25ba877-57c9-46d5-9a4b-7448569a3b79)

`Adapter 3` -> Select `Enable Network Adapter` -> Attached to `Internal Network` -> Name `LAN 1` -> Adapter Type `Paravirtualized Network`

![Screenshot 2025-01-24 104522](https://github.com/user-attachments/assets/06e85c6d-77df-407d-8e98-b0eec23e1f5d)

`Adapter 4` -> Select `Enable Network Adapter` -> Attached to `Internal Network` -> Name `LAN 2` -> Adapter Type `Paravirtualized Network`

![Screenshot 2025-01-24 104531](https://github.com/user-attachments/assets/6990c5ed-c09c-4684-a5f8-6de40a623000)

# pfSense Installation

To start select the pfSense VM annd select `Start`

<img width="550" alt="Screenshot 2025-01-24 105007" src="https://github.com/user-attachments/assets/59f995ed-add5-4804-8992-ff4044d58288" />

I cam across an issue when trying to start my new VM.























