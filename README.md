![image](https://github.com/user-attachments/assets/c6d46b86-e6e1-47e7-92ee-7543fd7f0707)# Home-Lab


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

![Screenshot 2025-01-24 105045](https://github.com/user-attachments/assets/caef7305-f3ae-43cf-983a-f4112a733c02)

I went through a few different stack overflow chats about what could be causing this. Ultimatly I just updated my computer and it worked.

But once you can get the VM to start, lots of text will pop up, wait till you see this screen and click `enter`.

![Screenshot 2025-01-24 112630](https://github.com/user-attachments/assets/f6b16a44-fdfb-45f0-aa9e-edd9a522e402)

Go through the menus -> Press `Enter` to start the Installation -> Press `Enter` to select the Auto (ZFS) partition option -> Press `Enter` to select Proceed with Installation -> Press `Enter` to select Stripe - No Redundancy -> Use the `Spacebar` key to select the Hard Drive (ada0) then press Enter to continue -> Use the Left Arrow to select YES and then press Enter to continue -> Wait for the installation to complete.

![Screenshot 2025-01-24 113337](https://github.com/user-attachments/assets/13e8fa73-f45a-4e81-8fe2-47d4078b16d3)

After select `Reboot`

# pfSense Configuration

After Reboot Next step is to include the adapter we configured earlier.

Should VLANs be set up now? `n` and press `enter`

<img width="577" alt="Screenshot 2025-01-24 113530" src="https://github.com/user-attachments/assets/45ae3032-b125-4e1f-95d3-437a4a4ee4ac" />

Enter the WAN interface name: `vtnet0`
Enter the LAN interface name: `vtnet1`
Enter the Optional 1 interface name: `vtnet2`
Enter the Optional 2 interface name: `vtnet3`
Do you want to proceed?: `y`

<img width="577" alt="Screenshot 2025-01-24 113650" src="https://github.com/user-attachments/assets/55cac4c7-0e4d-480d-98a4-5cb920a67d42" />

<img width="525" alt="Screenshot 2025-01-24 113711" src="https://github.com/user-attachments/assets/d52bdb60-47d1-4688-bc76-19478cc8b3e8" />

The WAN interface of pfSense gets its IPv4 address automatically from VirtualBox's DHCP server. Similarly, the LAN interface receives an IPv4 address from pfSense's own DHCP service. However, the OPT1 and OPT2 interfaces don’t have any IP addresses assigned yet. To ensure the IP addresses for the LAN, OPT1, and OPT2 interfaces remain the same after each reboot, we will assign them static IPv4 addresses.

To configure the static Ip addresses type `2` and `enter`

<img width="360" alt="Screenshot 2025-01-24 114021" src="https://github.com/user-attachments/assets/26dd192f-9ced-4f8b-a53a-81f23aa4872d" />

Configure IPv4 address LAN interface via DHCP?: n
Enter the new LAN IPv4 address: 10.0.0.1
Enter the new LAN IPv4 subnet bit count: 24

<img width="361" alt="Screenshot 2025-01-24 114156" src="https://github.com/user-attachments/assets/9faa473b-13e2-48ca-ba5d-025caa76e96b" />

Then click `enter` since this is a LAN interface it doesnt need data upstreaming

Configure IPv6 address LAN interface via DHCP6: `n`
For the new LAN IPv6 address question press `Enter`
Do you want to enable the DHCP server on LAN?: `y`
Enter the start address of the IPv4 client address range: `10.0.0.11`
Enter the end address of the IPv4 client address range: `10.0.0.243`
Do you want to revert to HTTP as the webConfigurator protocol?: `n`

Press `Enter` to finish setup of interface and you will see the new static IP applied

<img width="359" alt="Screenshot 2025-01-24 114410" src="https://github.com/user-attachments/assets/dd94ff12-843d-4e77-85cd-8d44814729bf" />

Configuring OPT1 (vtnet2)

Enter `2` then `3` to select the interface
Configure IPv4 address OPT1 interface via DHCP?: n
Enter the new OPT1 IPv4 address: 10.6.6.1
Enter the new OPT1 IPv4 subnet bit count: 24

<img width="361" alt="Screenshot 2025-01-24 114536" src="https://github.com/user-attachments/assets/fb0db242-5c9a-40e9-80d9-ba827da029af" />


Configure IPv6 address OPT1 interface via DHCP6: `n`
For the new OPT1 IPv6 address question press `Enter`
Do you want to enable the DHCP server on OPT1?: `y`
Enter the start address of the IPv4 client address range: `10.6.6.11`
Enter the end address of the IPv4 client address range: `10.6.6.243`
Do you want to revert to HTTP as the webConfigurator protocol?: `n`

<img width="358" alt="Screenshot 2025-01-24 114652" src="https://github.com/user-attachments/assets/1f6a42e2-f739-4e6c-bcca-8b65421fe739" />

Press `Enter` to save changes

<img width="244" alt="Screenshot 2025-01-24 114807" src="https://github.com/user-attachments/assets/4a4285a1-0865-4b42-bbc2-ae3555ec6268" />

Configuring OPT2 (vtnet3)

Enter `2` then `4` to select the correct interface
Configure IPv4 address OPT2 interface via DHCP?: `n`
Enter the new OPT2 IPv4 address: `10.80.80.1`
Enter the new OPT2 IPv4 subnet bit count: `24`

<img width="364" alt="Screenshot 2025-01-24 114913" src="https://github.com/user-attachments/assets/dffe5f64-464c-4359-b326-8db6bc0cafe6" />

Select `Enter`
Configure IPv6 address OPT2 interface via DHCP6: `n`
For the new OPT2 IPv6 address question press `Enter`
Do you want to enable the DHCP server on OPT2?: `n`
Do you want to revert to HTTP as the webConfigurator protocol?: `n`

<img width="363" alt="Screenshot 2025-01-24 115041" src="https://github.com/user-attachments/assets/25b2e1df-04a8-4de9-8582-20faf7a6dd0b" />


The OPT2 interface will be used to set up the Active Directory (AD) Lab. In this setup, the Domain Controller (DC) will function as the DHCP server. Because the DC will handle DHCP tasks, we have disabled DHCP-based IP address assignment for the OPT2 interface in pfSense.

Select `Enter` to save configuration.

<img width="360" alt="Screenshot 2025-01-24 115108" src="https://github.com/user-attachments/assets/b78ddfdb-2684-4433-913c-3a75716112dd" />

Shutting down pfSense VM

Its important to remember that this vm needs to be the first vm to boot and the last to shutdown.

Back in the menu type `6` to `hault system`, then `y` to continue. 

<img width="359" alt="Screenshot 2025-01-24 115156" src="https://github.com/user-attachments/assets/65074e38-c56e-40b2-9c6b-9598167aa217" />

After Installation 

Go to the VM and select `settings`

<img width="450" alt="Screenshot 2025-01-24 115247" src="https://github.com/user-attachments/assets/af361261-174b-405c-8507-a72d07886f72" />

Select `Expert` -> `Storage` -> select the `.iso` image -> select the disk to the right -> `Remove disk from Virtual Drive`

<img width="565" alt="Screenshot 2025-01-24 115753" src="https://github.com/user-attachments/assets/f82e6d50-8bb0-4be6-a593-b7b16884d309" />

Why do this?

When you install an operating system like pfSense from an .iso file, the VM treats it as if it's booting from a physical CD/DVD.
After installation is complete, the VM no longer needs the .iso file to run because the operating system is now installed on the virtual hard drive.
By removing the disk, you:
Prevent the VM from booting into the installer again (which would restart the installation process if left in the drive).
Free up the virtual optical drive for other uses.


# Kali Linux INstall & Configuration

Start by downloading Kali Linux: https://www.kali.org/get-kali/#kali-installer-images

Download the 64 bit recommended installer

<img width="787" alt="Screenshot 2025-01-25 130201" src="https://github.com/user-attachments/assets/e57811b6-edb9-4700-b9f5-a20244cbbffa" />

Once downloaded, we can find our `.iso` file.

![Screenshot 2025-01-25 130712](https://github.com/user-attachments/assets/0f315a0d-3d44-4a57-af13-2ca0b0fdd29f)

Go back to `VirtualBox`, selct `tools` -> `new` -> make a new name and save the new vm to the `vm` file we created 

Leave the ISO image field blank -> select `Linux` -> `Debian` -> 64-bit

<img width="586" alt="Screenshot 2025-01-25 131304" src="https://github.com/user-attachments/assets/6bddb152-385b-424b-bd16-7003bffb78df" />

`Unattended Install` leave default

![Screenshot 2025-01-25 131825](https://github.com/user-attachments/assets/f91a2bc7-efdd-4aae-8e85-687e922790dc)

`Hardware` leave default

![Screenshot 2025-01-25 131855](https://github.com/user-attachments/assets/dbda154b-5a29-448d-80b2-d9681de465e9)

`Hard Disk` increase memory to `80 GB` -> select `Finish`

<img width="586" alt="Screenshot 2025-01-25 131304" src="https://github.com/user-attachments/assets/c563b0f3-ea0a-430c-b1a9-c9ae1c2e9ac4" />

Next select `Machine`-> `Add to Group` -> `New` -> select `New Group` -> `Group` -> `Rename Group` -> rename to managment 

<img width="384" alt="Screenshot 2025-01-25 133002" src="https://github.com/user-attachments/assets/30969274-8d48-4816-90d7-4bd805862481" />

# Kali Linux VM Configuration

Next is to select the Kali Linux VM -> `Settings` -> Scroll down to `System` and change the boot order to `Hard disc` then `Optical` and uncheck `Floppy`

<img width="573" alt="Screenshot 2025-01-26 120117" src="https://github.com/user-attachments/assets/e4d50025-8def-4cb0-90a7-328a95cedd5c" />

Next go to proccesor and enable `PAE/NX`

Enabling PAE/NX is required for many modern operating systems and software to run correctly within a virtual environment. If your VM needs access to more RAM or the OS being installed requires NX for security (e.g., many Linux distributions or Windows Server versions), enabling this option is a good idea.

If you don’t enable it, some systems may fail to install or function correctly, especially those that rely on security mechanisms or large memory spaces.

<img width="567" alt="Screenshot 2025-01-26 120424" src="https://github.com/user-attachments/assets/5f43f4cf-dbee-4669-b056-fdac4dd8eb6d" />

Next go to `Display` and `Screen` then increase `Video Memory` to `128 MB`

<img width="568" alt="Screenshot 2025-01-26 120716" src="https://github.com/user-attachments/assets/82a297a9-80ec-4af6-bb33-382c3c91772b" />

Next step is the boot image configuration

Scroll down to `Storage` -> Select the `empty` disk image under `Controller IDE` -> Select the cd image to the right -> select `choose a disk file` -> select the `.iso` Kali Linux file downloded previously.

<img width="576" alt="Screenshot 2025-01-26 121356" src="https://github.com/user-attachments/assets/0245656e-e84e-4fd2-8851-332b695ac87b" />

Next is the network configuration.

Scrol down to `Network` -> Adapter 1 

Attached to: `Internal Network`

Adapter type: `Paravirtual Network`

<img width="577" alt="Screenshot 2025-01-26 124200" src="https://github.com/user-attachments/assets/1324f810-f363-438c-8398-0e857aaf6393" />

Select `OK` when complete

# Kali Linux Installation

Fist step is to boot up, `pfsense vm` first if it is currently shut down. 

<img width="571" alt="Screenshot 2025-01-26 125422" src="https://github.com/user-attachments/assets/a991a6ad-a966-4ea2-9b06-8ad852e11ba0" />

Select `Graphical Install`

![Screenshot 2025-01-26 125639](https://github.com/user-attachments/assets/34031c63-9085-4165-a5a0-459e662493bd)

Select the correct language, Country, and Keyboard

<img width="400" alt="Screenshot 2025-01-26 125713" src="https://github.com/user-attachments/assets/c024c154-a73d-488e-b80a-1e778aeae24e" />

<img width="406" alt="Screenshot 2025-01-26 125738" src="https://github.com/user-attachments/assets/5b46a719-d97d-4e12-8841-0fc0c3488af1" />

<img width="401" alt="Screenshot 2025-01-26 125754" src="https://github.com/user-attachments/assets/6c8eb868-a34d-4fcf-a59e-0ae3be720cd8" />

Enter a `Hostname`

<img width="399" alt="Screenshot 2025-01-26 130005" src="https://github.com/user-attachments/assets/0af56e57-e8a1-4e8a-8cce-148d5251446f" />

Leave `Domain Name` blank

<img width="401" alt="Screenshot 2025-01-26 130102" src="https://github.com/user-attachments/assets/63f5636f-dec9-4492-9848-cfffc872ce06" />

Enter your name and username

<img width="399" alt="Screenshot 2025-01-26 130203" src="https://github.com/user-attachments/assets/8f7968fc-c558-4695-afd0-f6041ce84197" />

<img width="398" alt="Screenshot 2025-01-26 130305" src="https://github.com/user-attachments/assets/a5f63c4a-0dcf-4365-b1ea-e9caf9a3ba79" />

Add a `password` then select your timezone 

![Screenshot 2025-01-26 130421](https://github.com/user-attachments/assets/f788d5c7-2f56-4e47-b73f-0d774fdcd0b5)

<img width="404" alt="Screenshot 2025-01-26 130757" src="https://github.com/user-attachments/assets/b78ffcef-772c-4f98-b569-3f1c2c828b54" />

<img width="396" alt="Screenshot 2025-01-26 130858" src="https://github.com/user-attachments/assets/6c2139bc-2c73-4390-a2de-90bd28d7a341" />

Next select `Guided - use entire risk`

<img width="398" alt="Screenshot 2025-01-26 130841" src="https://github.com/user-attachments/assets/c1d37f03-868d-4b4c-a972-7217d98c5959" />

Select `All files`

<img width="403" alt="Screenshot 2025-01-26 130917" src="https://github.com/user-attachments/assets/158c61e1-32cd-4369-ad94-a3dcff6c0311" />

Select `Finish particioning and write to disc`

<img width="401" alt="Screenshot 2025-01-26 131001" src="https://github.com/user-attachments/assets/0dc910cf-8098-434a-924a-a8950a127e26" />

Select `Yes` then wait for installation.

<img width="416" alt="Screenshot 2025-01-26 131043" src="https://github.com/user-attachments/assets/199e42c4-7b98-478b-baee-866b04ad8054" />

For the desktop enviorment its up to personal choiice, I chose `GNOME`

These are desktop environment options for Kali Linux, each offering a unique interface and user experience:

`Xfce`: Lightweight, fast, and minimal, ideal for performance on systems with limited resources.
`GNOME`: Modern, visually appealing, and feature-rich, focusing on a sleek and intuitive user interface.
`KDE Plasma`: Highly customizable with a polished appearance, offering advanced features and options for power users.

<img width="394" alt="Screenshot 2025-01-26 131610" src="https://github.com/user-attachments/assets/55afcfc5-8d0c-4a16-8d73-b53caacad384" />

Wait for install

<img width="400" alt="Screenshot 2025-01-26 131755" src="https://github.com/user-attachments/assets/e7c6934d-3071-41a4-968d-ae371e565912" />

Select `Yes`

<img width="401" alt="Screenshot 2025-01-26 133645" src="https://github.com/user-attachments/assets/ccb3b69a-89d0-4760-b902-0a1b7b6eee76" />

<img width="395" alt="Screenshot 2025-01-26 133732" src="https://github.com/user-attachments/assets/830fd0a6-a3a9-491a-a7df-1083d74b80d5" />

Select `Continue` to reboot.

<img width="400" alt="Screenshot 2025-01-26 134043" src="https://github.com/user-attachments/assets/995c79ec-ca62-4100-8f73-2dd05e5ecceb" />

Next loginto your Kali Linux Account

<img width="638" alt="Screenshot 2025-01-26 134233" src="https://github.com/user-attachments/assets/c4191a33-2a1a-4902-a180-dc6ad60b4c03" />

Once inside Kali Linux, open the terminal

<img width="290" alt="Screenshot 2025-01-26 135301" src="https://github.com/user-attachments/assets/f712b449-a401-4308-8da0-d0f74984d5a9" />

Once inside terminal run the command: `ip a`

This will show the IP range that was made, also you can see it is connected to the internet as well.

<img width="427" alt="Screenshot 2025-01-26 135210" src="https://github.com/user-attachments/assets/16aff80d-5cda-4a1e-9676-0115a2c4bc94" />

Next enter this command to update the system: `sudo apt update && sudo apt full-upgrade` also enter password.

<img width="493" alt="Screenshot 2025-01-26 135907" src="https://github.com/user-attachments/assets/5988da9b-9774-487c-9cf9-f76614274827" />

Enter `Y` to continue

<img width="498" alt="Screenshot 2025-01-26 140022" src="https://github.com/user-attachments/assets/ab737d20-1421-475b-bb1f-003dc7927589" />

After finished run this command: `sudo apt autoremove` to remove any unused packages.

<img width="498" alt="Screenshot 2025-01-26 140022" src="https://github.com/user-attachments/assets/3361eff4-8c70-480d-aa96-5623bdf2b37c" />

<img width="510" alt="Screenshot 2025-01-26 143325" src="https://github.com/user-attachments/assets/0f1f9549-57dc-41da-9786-3e326a202bb9" />

Feel free to delete the `.iso` file for Kali Linux.

# Web Portal/ pfSense Setup

Inside Kali vm open the web browser and paste http://10.0.0.1

You will see this warning -> Select `Advanced` -> `Accept the Risk and Continue`

<img width="471" alt="Screenshot 2025-01-26 144053" src="https://github.com/user-attachments/assets/a8a85fe8-99a8-4a45-9d1e-6e4259d27260" />


Once at the pfSenese login menu use the default credentials:

Username: `admin`
Password: `pfsense`

Then select `Next`

<img width="921" alt="Screenshot 2025-01-26 144812" src="https://github.com/user-attachments/assets/fbf82cb4-3952-42a7-a35b-98452705641c" />

`Next` again

<img width="818" alt="Screenshot 2025-01-26 144854" src="https://github.com/user-attachments/assets/118daf68-1c9a-4c2b-9778-f794236d8d32" />

Once the default menu pops up add a `Hostname` and `domain`, then uncheck `Override DNS`

<img width="580" alt="Screenshot 2025-01-26 145139" src="https://github.com/user-attachments/assets/67cad4b6-5183-4289-a565-d0b25c534807" />

Then select your timezone

<img width="623" alt="Screenshot 2025-01-26 145410" src="https://github.com/user-attachments/assets/64592556-79ee-43fd-8680-017412fe5205" />

Scroll to `RFC1918 Networks` section. Uncheck the `Block RFC1918 Private Networks` option.

<img width="607" alt="Screenshot 2025-01-26 145853" src="https://github.com/user-attachments/assets/884b2df5-6427-4019-a141-98565457782e" />

Leave the next page default.

<img width="588" alt="Screenshot 2025-01-26 150045" src="https://github.com/user-attachments/assets/fe27b0b1-31ac-4dbf-9f85-1ec5047de429" />

Enter a password and make sure to save somewhere secure.

Then click `Reload`

<img width="591" alt="Screenshot 2025-01-26 151557" src="https://github.com/user-attachments/assets/dd010039-b00e-4508-82b0-293a43e573f9" />

Then select `Finish`

<img width="573" alt="Screenshot 2025-01-26 151631" src="https://github.com/user-attachments/assets/9152033d-4161-477a-8546-893911e20489" />

Now at the pfSense dashboard 

<img width="592" alt="Screenshot 2025-01-26 153120" src="https://github.com/user-attachments/assets/a7a1fefb-24a2-4dcd-8674-c32547e6d18a" />

Next is to change the name of the interface. Select `Interfaces` then `OPT 1`

<img width="313" alt="Screenshot 2025-01-26 153819" src="https://github.com/user-attachments/assets/d8d75782-26c6-4204-bb53-31f7debd37df" />

Rename `OPT 1` to `CYBER_RANGE` click `save`

Then you will see the new name and a pop-up, click `Apply Changes`

<img width="582" alt="Screenshot 2025-01-26 154333" src="https://github.com/user-attachments/assets/fea2d35e-a55c-4f59-9a48-85b617ea0b2b" />

GO back to the top and select `Interfaces` and select `OPT 2`

<img width="591" alt="Screenshot 2025-01-26 154517" src="https://github.com/user-attachments/assets/cea4838a-3fb4-4396-9b7c-149838d1ebbb" />

Desription: `AD_LAB` -> scroll down select `save` -> Select `Apply changes` in pop up

<img width="580" alt="Screenshot 2025-01-26 154849" src="https://github.com/user-attachments/assets/f8575688-a419-469b-bc8f-294c746b9001" />

# DNS Resolver 

At the top of the page select `Services` -> `DNS Resolver`

<img width="339" alt="Screenshot 2025-01-26 155234" src="https://github.com/user-attachments/assets/2e1cc969-ddc8-4277-8fa5-581e38f6e73c" />

Then scroll down to `DHCP Registration` and enable it, then enable `static dhcp`.

<img width="577" alt="Screenshot 2025-01-26 155420" src="https://github.com/user-attachments/assets/e5dd1178-b42c-488d-bdc0-9510fa0274c3" />

Dont save yet, go back to the top and select `Advanced settings`

<img width="346" alt="Screenshot 2025-01-26 155515" src="https://github.com/user-attachments/assets/d274a80a-5e38-435e-9686-75f1de45e784" />

Scroll down to the `Advanced Resolver Option` and enable `Prefetched Support` and `Prefetch DNS Key Support`

<img width="586" alt="Screenshot 2025-01-26 155734" src="https://github.com/user-attachments/assets/06f134e5-e92f-477e-a4b2-a769e70227ba" />

Then scroll down and save and apply changes.

<img width="592" alt="Screenshot 2025-01-26 155840" src="https://github.com/user-attachments/assets/7904bae2-c515-447e-b4ba-76846b37bd0b" />

Next go back to top and select `System` -> `Advanced`

<img width="248" alt="Screenshot 2025-01-26 160157" src="https://github.com/user-attachments/assets/7acedb47-32e7-4920-926f-f471452ff96e" />

Go to `Network`

<img width="583" alt="Screenshot 2025-01-26 160340" src="https://github.com/user-attachments/assets/4591ab8a-0111-418c-9778-ff556364899a" />

Then scroll down and disable `Hardware Checksum Offloading` 

<img width="577" alt="Screenshot 2025-01-26 160502" src="https://github.com/user-attachments/assets/2f39d573-cf29-41c4-9880-0577529f7847" />

Then save and click ok for popup.

<img width="251" alt="Screenshot 2025-01-26 160541" src="https://github.com/user-attachments/assets/acebfa45-9731-4b0b-8363-5a6c10c017e5" />

# Static IP Assignment 

From the dashboard go to `Status` -> `DHCP Leases`

<img width="595" alt="Screenshot 2025-01-27 094129" src="https://github.com/user-attachments/assets/0d75c9c6-399c-4785-bbd5-648b2d560b5f" />

Here we can see the IP address and range we set, select the `+` to thre right. This will allow us to easily make firewall changes to the interfaces.

<img width="604" alt="Screenshot 2025-01-27 094421" src="https://github.com/user-attachments/assets/869203f2-c8a4-45ab-bf3c-f7312c953820" />

Scroll down to `IP Address` -> add `10.0.0.2` -> `save`

<img width="573" alt="Screenshot 2025-01-27 094456" src="https://github.com/user-attachments/assets/b749292a-2217-4c66-a049-088258399728" />

`Apply chnages`

<img width="591" alt="Screenshot 2025-01-27 094606" src="https://github.com/user-attachments/assets/4aa06e86-9bd0-4434-bbf3-e27bbd0dbe7a" />

# Update Ip Address of Kali Linux

Open the `Terminal` same as  before and enter this command: `ip a l eth0` this shows the current IP address

<img width="427" alt="Screenshot 2025-01-27 095224" src="https://github.com/user-attachments/assets/ac7e6de4-4911-4dcf-9e90-0ade0e18ff44" />

Then use this command to release the current ip and set the new static ip address: `sudo ip l set eth0 down && sudo ip l set eth0 up`

use command: `ip a l eth0` to check to see if it worked.

<img width="413" alt="Screenshot 2025-01-27 095559" src="https://github.com/user-attachments/assets/1bfc4dee-b657-4f10-98ab-bed38776b6c0" />

# pfSense Firewall Configuration

Back in the Kali Linux VM, inside the dashboard, go to the top and select `Firewall` -> `Rules`

<img width="382" alt="Screenshot 2025-01-27 095833" src="https://github.com/user-attachments/assets/fcb67702-c088-4ead-99cf-c1326ea6b1c4" />

Then select `LAN`

<img width="621" alt="Screenshot 2025-01-27 100120" src="https://github.com/user-attachments/assets/d54d3e49-5ee3-44b9-ab23-2f6dc1cf0b3f" />

Then select the highlighted arrow to `Add new rule`

<img width="592" alt="Screenshot 2025-01-27 100205" src="https://github.com/user-attachments/assets/f8464be9-eeda-4978-991e-9dac1c2c5bec" />

* Action: `Block`
* Address Family: `Ipv4+IPv6`
* Protocol: `Any`
* Source: `LAN subnets`
* Destination: `WAN subnets`
* Description: `Block access to services on WAN interface`

<img width="577" alt="Screenshot 2025-01-27 100552" src="https://github.com/user-attachments/assets/8789ddd6-c7c8-4d78-adcc-520441da54dc" />

Then click `Save` -> `Apply Chnages`

<img width="597" alt="Screenshot 2025-01-27 100647" src="https://github.com/user-attachments/assets/f83ba814-16c1-4e19-b502-a99a744ef777" />

The firewall rules status, make sure they are in the correct order aswell.

<img width="602" alt="Screenshot 2025-01-27 100751" src="https://github.com/user-attachments/assets/0aff2b00-354a-4928-990d-9b82f8e2d2fd" />

# CYBER_RANGE Rules

At the top select `Firewall` -> `Aliases`

<img width="842" alt="Screenshot 2025-01-27 101042" src="https://github.com/user-attachments/assets/0578430e-ec36-4242-a7f5-20eb190df183" />

Then in the `IP` tab select the `+` button

<img width="593" alt="Screenshot 2025-01-27 101109" src="https://github.com/user-attachments/assets/2e832e65-fca3-4ccb-8f32-f92fc6a33084" />

* Name: `RFC1918`
* Description: `Private IPv4 Address Space`
* Type: `Network(s)`
* Network 1: `10.0.0.0/8`
* Network 2: `172.16.0.0/12`
* Network 3: `192.168.0.0/16`
* Network 4: `169.254.0.0/16`
* Network 5: `127.0.0.0/8`

<img width="594" alt="Screenshot 2025-01-27 101824" src="https://github.com/user-attachments/assets/b9b9b902-9309-4570-8cd0-e886755fe808" />

Then `save` -> `Apply Changes`

<img width="601" alt="Screenshot 2025-01-27 101857" src="https://github.com/user-attachments/assets/6f2000d8-2596-441b-9bf9-e861f8a1d918" />

Final Aliase look

<img width="592" alt="Screenshot 2025-01-27 101946" src="https://github.com/user-attachments/assets/dac847ea-f706-4201-bf6c-7e049614e36a" />

Next go back to the top and select `Firewall` -> `Rules`

<img width="602" alt="Screenshot 2025-01-27 102031" src="https://github.com/user-attachments/assets/ccd2df48-aab0-4b34-bfd2-a26e1198dc53" />

Select `CYBER_RANGE`

<img width="592" alt="Screenshot 2025-01-27 102104" src="https://github.com/user-attachments/assets/df463889-1cb2-43ef-8a7b-f54f09147fd6" />

Select the highlighted `down arrow` to `add new rule at end`

<img width="592" alt="Screenshot 2025-01-27 102228" src="https://github.com/user-attachments/assets/af7454df-31bc-4d8b-85ff-1366340391ca" />

* Address Family: `IPv4+IPv6`
* Protocol: `Any`
* Source: `CYBER_RANGE subnets`
* Destination: `CYBER_RANGE address`
* Description: `Allow traffic to all devices on the CYBER_RANGE network`

<img width="587" alt="Screenshot 2025-01-27 102600" src="https://github.com/user-attachments/assets/d6b5ffb8-5192-4691-9414-54f943a50dc2" />

Click `save` -> `Add rule to end` again

<img width="583" alt="Screenshot 2025-01-27 102711" src="https://github.com/user-attachments/assets/8a0ea2f2-aac1-45a3-9c44-a287adcbfc7c" />

* Protocol: `Any`
* Source: `CYBER_RANGE subnets`
* Destination: `Address or Alias - 10.0.0.2`
* Description: `Allow traffic to Kali Linux VM`

<img width="573" alt="Screenshot 2025-01-27 102932" src="https://github.com/user-attachments/assets/1f28d449-f46b-4316-83f9-732c225bb7c5" />

Then select `save` and `add new rule to end`

<img width="582" alt="Screenshot 2025-01-27 103029" src="https://github.com/user-attachments/assets/1e4aa94e-9133-4449-bdb1-ebd947a7880d" />

* Protocol: `Any`
* Source: `CYBER_RANGE subnets`
* Destination: `Address or Alias - RFC1918 (Select Invert match)`
* Description: `Allow to any non-private IPv4 Address`

<img width="584" alt="Screenshot 2025-01-27 103239" src="https://github.com/user-attachments/assets/39592702-ce37-4943-8cf1-bb6c9092d0fc" />

Select `save` -> `add new rule to end`

<img width="586" alt="Screenshot 2025-01-27 103345" src="https://github.com/user-attachments/assets/2270c752-d9b9-447b-ad96-41bf90ed8d4c" />

* Action: `Block`
* Address Family: `IPv4+IPv6`
* Protocol: `Any`
* Source: `CYBER_RANGE subnets`
* Description: `Block access to everything`

<img width="574" alt="Screenshot 2025-01-27 103549" src="https://github.com/user-attachments/assets/5b77ac1d-5fa0-4541-823d-59e2d1e79e7f" />

Select `save` -> `Apply Changes`

And this is what the final rules should look like.

<img width="587" alt="Screenshot 2025-01-27 103630" src="https://github.com/user-attachments/assets/98cd343c-2514-4e39-8aff-ecf037091b76" />

# AD_Lab Rules

In the top bar select `AD_Lab`

<img width="587" alt="Screenshot 2025-01-27 105701" src="https://github.com/user-attachments/assets/c9720c6f-962e-4e77-acd4-0782a89e5257" />

Then select `add rule to end`

<img width="591" alt="Screenshot 2025-01-27 105827" src="https://github.com/user-attachments/assets/c1d514e6-b5c0-432a-aba4-ea2e5b7b485d" />

* Action: `Block`
* Address Family: `IPv4+IPv6`
* Protocol: `Any`
* Source: `AD_LAB subnets`
* Destination: `WAN subnets`
* Description: `Block access to services on WAN interface`

<img width="583" alt="Screenshot 2025-01-27 110048" src="https://github.com/user-attachments/assets/cef122ae-d989-425d-ad42-4a21aad79f3d" />

Select `save` -> skip apply chnages -> select `add rule to end`

<img width="589" alt="Screenshot 2025-01-27 110530" src="https://github.com/user-attachments/assets/fe8d6dc8-77f6-4bf1-9748-63cdd2ab6d16" />

* Action: `Block`
* Address Family: `IPv4+IPv6`
* Protocol: `Any`
* Source: `AD_LAB subnets`
* Destination: `CYBER_RANGE subnets`
* Description: `Block traffic to CYBER_RANGE interface`

<img width="422" alt="Screenshot 2025-01-27 111535" src="https://github.com/user-attachments/assets/3f327f7b-fca6-474e-99d7-ffed7e51b10a" />

Select `save` -> `add rule to end`

<img width="588" alt="Screenshot 2025-01-27 111643" src="https://github.com/user-attachments/assets/f6516ae1-fc0c-4459-92d4-cff3f965c7e6" />

* Address Family: `IPv4+IPv6`
* Protocol: `Any`
* Source: `AD_LAB subnets`
* Description: `Allow traffic to all other subnets and Internet`

<img width="579" alt="Screenshot 2025-01-27 111855" src="https://github.com/user-attachments/assets/ffdb6508-b9b3-4a85-b32f-68f9891877e5" />

Select `save` -> `Apply Changes`

Then make sure it all looks correct

<img width="591" alt="Screenshot 2025-01-27 111951" src="https://github.com/user-attachments/assets/2d168cd4-60a9-4588-98f4-8e475ad0b579" />

Next step is to apply these new firewall rules, and to do that pfSense is needing to reboot.

At the top of the dashboard go to `Diagnostics` -> `Reboot`

<img width="592" alt="Screenshot 2025-01-27 112146" src="https://github.com/user-attachments/assets/7aea6064-6abf-4ba2-9bfb-dcd48554fabf" />

Then select `submit`

<img width="355" alt="Screenshot 2025-01-27 112158" src="https://github.com/user-attachments/assets/40006104-6483-4eb5-bf67-38577a0c8b1f" />

# Setting up Vulnerable VM's

Head to this link to download `Metasploitable`: https://www.vulnhub.com/entry/metasploitable-2,29/

<img width="922" alt="Screenshot 2025-01-27 141706" src="https://github.com/user-attachments/assets/3bd9f943-d79d-456a-8466-116127693268" />

Download the the compressed file, and extract it. -> Inside the folder look for the `.vmdk` file 

<img width="586" alt="Screenshot 2025-01-27 142822" src="https://github.com/user-attachments/assets/e90ac926-a729-412f-9d63-f4bad43c1dba" />

Next go to VirtualBox and select `Tools` -> `New`

<img width="441" alt="Screenshot 2025-01-27 142901" src="https://github.com/user-attachments/assets/c4b050d0-38e0-46b9-a7b7-df30c52efdea" />

* Give the VM a name: `Metasploitable 2`
* Set the folder to where youve been saving all your vm's
* Leave the `iso` blank
* Type: `Linux`
* Version: `Debian 64-bit`

<img width="591" alt="Screenshot 2025-01-27 143054" src="https://github.com/user-attachments/assets/e630d646-e8c8-4f6e-bac1-55815e1182c1" />

Then go to `Hardware` and reduce the base memory to `1048`

<img width="472" alt="Screenshot 2025-01-27 144025" src="https://github.com/user-attachments/assets/181da592-078c-4c98-8e6b-cf82903d4d3a" />

Then in `Hard Disk` select `Do Not Add a Hard Disk` since the file we downloaded has the OS pre installed.

<img width="586" alt="Screenshot 2025-01-27 144158" src="https://github.com/user-attachments/assets/204c4d5d-a1ca-4543-b20e-4b13883fff51" />

Next add the new VM to a new group by selecting the vm -> `Machine` -> `Move to Group` -> `New`

Then select the new group -> `Machine` -> `Rename Group` -> `Cyber Range`

<img width="595" alt="Screenshot 2025-01-28 090014" src="https://github.com/user-attachments/assets/f4cfe135-97d0-432e-9a27-5174feaa8351" />

Next step is to add the `.vmdk` to the hard disk.

Select the new vm -> `settings`

<img width="592" alt="Screenshot 2025-01-28 090536" src="https://github.com/user-attachments/assets/fbdac17d-ccaa-45cb-a98f-68cd5cdf8d16" />

Then select `storage` -> Then select the highlighted `adds hard disk`

<img width="577" alt="Screenshot 2025-01-28 090619" src="https://github.com/user-attachments/assets/d4803dcf-53e0-4a9a-9aa9-6664dbd63dd3" />

Select `Add`

<img width="473" alt="Screenshot 2025-01-28 090923" src="https://github.com/user-attachments/assets/72defa80-e054-47df-a532-795ad04f73b9" />

Choose the `.vdmk` file

<img width="476" alt="Screenshot 2025-01-28 091025" src="https://github.com/user-attachments/assets/054771e9-9c7f-41a2-a277-d2c3e27aa32b" />

This is how it should look

<img width="567" alt="Screenshot 2025-01-28 091041" src="https://github.com/user-attachments/assets/caad9f72-cb55-4751-9974-2b23e77f039f" />

Then go to `System` -> Change the boot order to `Hard Disk` `Optical` `Deselected Floppy` `Deselected Network`

<img width="564" alt="Screenshot 2025-01-28 091306" src="https://github.com/user-attachments/assets/63ef47bc-7efc-43ee-bab9-f8f9c0873a48" />

Next go to `Network` tab

Then change the `Attached to`: `Internal Network` -> Name: `LAN 1` -> select `ok`

<img width="424" alt="Screenshot 2025-01-28 091649" src="https://github.com/user-attachments/assets/181acf65-e841-446b-9022-2b1e64d6f5fc" />

Lets check that everything is setup correctly

Go to the VM and select `Start`

<img width="450" alt="Screenshot 2025-01-28 092349" src="https://github.com/user-attachments/assets/a34d24b8-21a1-481e-8090-31af52c5d7b9" />

Once it says to enter Username and password use:

Username: `msfadmin`
Password: `msfadmin`

<img width="478" alt="Screenshot 2025-01-28 092620" src="https://github.com/user-attachments/assets/4fcf3c4c-a8e5-4937-9eee-d4f359b78579" />

Then enter this command to receive ip address: `ip a l eth0`

<img width="381" alt="Screenshot 2025-01-28 092738" src="https://github.com/user-attachments/assets/49299351-b82d-4bc6-b1a0-d16ce0df0e55" />

Then to test connectivity you can ping 8.8.8.8 or google.com whatever you choose. I entered `ping 8.8.8.8 -c 5` this will ping to a count of 5 times.

<img width="293" alt="Screenshot 2025-01-28 092858" src="https://github.com/user-attachments/assets/92c47e2e-9c06-47fb-bae1-ba15078025f6" />

Check if you can connect to your Kali Linux vm: `ping 10.0.0.2 -c 5`

<img width="378" alt="Screenshot 2025-01-28 093115" src="https://github.com/user-attachments/assets/e9e609c6-9d7b-471e-8c14-28101127c208" />

Then we can check connectivity from Kali vm to Metasploit vm by going into the terminal of the Kali box, sending this command: `ping 10.6.6.11 -c 5` (ip address might be different for you.

<img width="347" alt="Screenshot 2025-01-28 093236" src="https://github.com/user-attachments/assets/3902d262-2a69-4104-a542-7aeaea436dfc" />

# Chronos VM Setup

First go to: https://www.vulnhub.com/entry/chronos-1,735/

And download the mirror of Chronos

<img width="871" alt="Screenshot 2025-01-28 093550" src="https://github.com/user-attachments/assets/a39e4f26-5052-43b2-83c0-e88154cb80ca" />

The file downloaded will be a `.ova` file

<img width="580" alt="Screenshot 2025-01-28 100607" src="https://github.com/user-attachments/assets/0b2a6fd3-649a-44f5-9016-4489eab5aa0f" />

Back inside VirtualBox select `Tools` -> `Import` -> select the `folder icon` -> select the newly downloaded `.ova` file.

<img width="387" alt="Screenshot 2025-01-28 100721" src="https://github.com/user-attachments/assets/ac46ad8d-20b1-4c07-843a-782d275cde5b" />

Select `Settings` -> reduce the RAM to `1024 MB` -> make sure MAC Address Policy: `Generate a new MAC address for all network adapters`

Then add the new vm to `Cyber Range`

<img width="412" alt="Screenshot 2025-01-28 101150" src="https://github.com/user-attachments/assets/19b1a9da-9ac7-40b7-aff8-9edb8143a8ac" />

# Chronos VM Configuration

In VirtualBox select `Chronos` -> `Settings`

<img width="445" alt="Screenshot 2025-01-28 101603" src="https://github.com/user-attachments/assets/8b218828-422b-470e-b3ba-dfd2fe47223b" />

Then go to `System` -> `Motherboard` then make boot order to look like this

<img width="570" alt="Screenshot 2025-01-28 102519" src="https://github.com/user-attachments/assets/0ea53054-3d9c-4ca7-be50-f7408ce4d8dc" />

Then go to `Network` -> Attached to: `Internal Network` -> Name: `LAN 1` -> Adapter Type: `Paravirtualized` -> `OK`

<img width="573" alt="Screenshot 2025-01-28 102732" src="https://github.com/user-attachments/assets/a32652df-16ba-4b09-af92-985c700712c0" />

Then go to start the VM, you will be asked for login credentials

<img width="403" alt="Screenshot 2025-01-28 103125" src="https://github.com/user-attachments/assets/7f6d69d6-a9db-4864-bd79-942e954fc08b" />

Since the login credentials are not known go back to the `Kali Linux VM` -> `Status` -> `DHCP Leases`

<img width="590" alt="Screenshot 2025-01-28 103332" src="https://github.com/user-attachments/assets/8009cf6c-99d6-41d3-9d8c-c89c7f979d2b" />

Here you can find the IP address for Chronos, to test connectivity with this info. Go into Kali Linux and ping your chronos ip: `ping 10.6.6.12 -c 5`

<img width="610" alt="Screenshot 2025-01-28 103429" src="https://github.com/user-attachments/assets/9abd1e0b-4272-4be6-8737-130e0e8132f5" />

It was successful

<img width="280" alt="Screenshot 2025-01-28 103622" src="https://github.com/user-attachments/assets/d229fa33-cb5e-4176-afb5-4c07f76899bc" />

# Active Directory Setup

Parts to Active Directory:
* VM_1 - Domain Controller (Windows Server 2019)
* VM_2 - client (Windows 10 Enterprise)
* VM_3 - client (Windows 10 Enterprise)

First downlaod `Windows Server 2019`: https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019

<img width="903" alt="Screenshot 2025-01-28 104625" src="https://github.com/user-attachments/assets/1c50074b-3404-4572-bdc4-944a3dcc3f03" />

Then download the `Windows 10 Enterprise`: https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise

<img width="957" alt="Screenshot 2025-01-28 133047" src="https://github.com/user-attachments/assets/3e03e15b-a9c8-4371-bce6-ee98bcc52382" />

# Installing Windows Server 2019 VM

Inside VirtualBox select `Tools` -> `New`

<img width="553" alt="Screenshot 2025-01-28 135627" src="https://github.com/user-attachments/assets/a7099925-1824-4a7e-89f6-323089ed6be6" />

Name: `Windows Server 2019` -> make sure to have the correct VM folder -> Select the `iso` image of the Windows Server 2019 -> Select `Skip unintended install`

<img width="592" alt="Screenshot 2025-01-28 140228" src="https://github.com/user-attachments/assets/cd466600-a7a1-43b0-9344-e38e3b1e1d16" />

Inside `Hardware` increase base memory to `4096 MB` (4 GB)

<img width="597" alt="Screenshot 2025-01-28 140248" src="https://github.com/user-attachments/assets/b28ac356-59cd-4ad2-ae11-9e8ab0ecc0a4" />

Then inside `Hard Disk` increase size to `100 GB` -> Select `Finish`

<img width="586" alt="Screenshot 2025-01-28 140412" src="https://github.com/user-attachments/assets/2398004c-5a96-4d42-adc1-d2c5d33c2dd2" />

Then I create and add this VM to a group call `Active Directory`

<img width="614" alt="Screenshot 2025-01-28 140534" src="https://github.com/user-attachments/assets/b2b752e3-396d-435d-86b9-7c2975b6a7f9" />

# Windows 10 Enterprise VM 1 Setup

To add the new VM, select `Tools` -> `New`

Then add a name: `Windows 10 Enterprise VM 1` -> correct `vm` folder -> `.iso` image of Windows 10 Enterprise that was downloaded -> Select `skip unintended install`

<img width="751" alt="Screenshot 2025-01-28 141104" src="https://github.com/user-attachments/assets/698764e8-c3d1-4912-88bf-763e6bec6405" />

Then for `Hardware` leave default -> inside `Hard Disk` increase size to `100 GB` -> `Finish`

# Windows 10 Enterprise VM 2 Setup

Same steps as last VM 

<img width="751" alt="Screenshot 2025-01-28 141211" src="https://github.com/user-attachments/assets/456eebda-0c54-455a-9237-4decc31387e7" />

<img width="753" alt="Screenshot 2025-01-28 141408" src="https://github.com/user-attachments/assets/27c853b1-6123-4180-9387-0ac40e419a24" />

# Windows Server 2019 Configuration

Select the `Windows Server VM` -> `Settings`

<img width="600" alt="Screenshot 2025-01-28 141621" src="https://github.com/user-attachments/assets/b48e8aa5-c40b-4fae-b4b9-d388345f6e30" />

Go to `System` -> `Motherboard` -> `Hard disk`, `Optical`, `Floppy`, `Network` like this:

<img width="568" alt="Screenshot 2025-01-28 141824" src="https://github.com/user-attachments/assets/1308afba-00ca-4794-9e72-9ad8823ad6bb" />

Then inside `Network` -> `Adapter 1` -> Attached to: `Internal Network` -> Name: `LAN 2` -> `ok`

# Windows 10 Enterprise VM 1 Configuration

Select `Wnidows 10 Enterprise VM 1` -> `Settings`

<img width="589" alt="Screenshot 2025-01-28 142234" src="https://github.com/user-attachments/assets/be5ab186-c374-4f3d-8c32-9e734f4cecd4" />

Go to `System` -> `Motherboard` -> `Hard disk`, `Optical`, `Floppy`, `Network` like this:

<img width="573" alt="Screenshot 2025-01-28 142337" src="https://github.com/user-attachments/assets/a83515bb-41f2-4c5f-8a35-93eac8fe48d5" />

Then inside `Network` -> `Adapter 1` -> Attached to: `Internal Network` -> Name: `LAN 2` -> `ok`

<img width="574" alt="Screenshot 2025-01-28 142426" src="https://github.com/user-attachments/assets/e0e6a6c5-dbd9-4819-9ef5-adc2a5a8f6d3" />

# Windows 10 Enterprise VM 2 Configuration

Select `Wnidows 10 Enterprise VM 2` -> `Settings`

<img width="516" alt="Screenshot 2025-01-28 142526" src="https://github.com/user-attachments/assets/916e46a1-848c-47b0-816c-196c5cb64a43" />

Go to `System` -> `Motherboard` -> `Hard disk`, `Optical`, `Floppy`, `Network` like this:

<img width="573" alt="Screenshot 2025-01-28 142606" src="https://github.com/user-attachments/assets/36a454fe-496d-4f03-8144-bf4f64172668" />

Then inside `Network` -> `Adapter 1` -> Attached to: `Internal Network` -> Name: `LAN 2` -> `ok`

<img width="580" alt="Screenshot 2025-01-28 142629" src="https://github.com/user-attachments/assets/25dc7d09-4dde-42e1-907c-9cefa7065439" />

# Windows 19 Server Setup

Select the `Windows Server` vm -> `start`

<img width="576" alt="Screenshot 2025-01-29 094548" src="https://github.com/user-attachments/assets/06740fea-5404-4262-925c-e4cf786cfe0c" />

Click `Next`

<img width="319" alt="Screenshot 2025-01-29 094934" src="https://github.com/user-attachments/assets/4d2a516c-e0b2-450b-9351-fba186dbd18c" />

`Install`

<img width="314" alt="Screenshot 2025-01-29 095010" src="https://github.com/user-attachments/assets/e54951a2-c67f-4881-bca7-1648eb78ac26" />

Select `Windows Server 2019 Standalone Evaluation (Desktop Experience)` and click on `Next`.

<img width="327" alt="Screenshot 2025-01-29 095138" src="https://github.com/user-attachments/assets/79bebb9c-2719-4186-9ebd-1a6ff5d482de" />

<img width="330" alt="Screenshot 2025-01-29 095213" src="https://github.com/user-attachments/assets/46f92c58-2618-4e11-b8c2-118f1c7d5968" />

Select `Custom: Install Windows only (Advanced).`

<img width="320" alt="Screenshot 2025-01-29 095237" src="https://github.com/user-attachments/assets/b2af2174-51ce-4f84-a7a0-9a3a31573886" />

`Next`

<img width="327" alt="Screenshot 2025-01-29 095324" src="https://github.com/user-attachments/assets/2acb1559-d39a-44ae-ad6c-ce7d06adc233" />

Once Instalation is complete, create a password for the admin account.

![dc-9](https://github.com/user-attachments/assets/776aedf6-4457-42af-8f34-bfa05d926877)

Then login

<img width="509" alt="Screenshot 2025-01-29 102158" src="https://github.com/user-attachments/assets/464fe0fc-98a7-428a-9947-f5fd47ba6683" />

Selct `Dont show again` -> `ok`

<img width="519" alt="Screenshot 2025-01-29 102359" src="https://github.com/user-attachments/assets/b57df89d-ae41-432a-9694-eae75c887d02" />

From the VM toolbar click on `Devices` -> `Optical Devices` -> `Remove disk from virtual drive`.

![dc-12](https://github.com/user-attachments/assets/c2770ff1-3341-4ab2-a9d0-633aec07eba3)

Then select `Devices` -> `Insert Guest Additions CD image`.

![dc-13](https://github.com/user-attachments/assets/3fd30295-b328-4003-847b-2d01980c08bf)

From the taskbar open `File Explorer`.

<img width="518" alt="Screenshot 2025-01-29 102747" src="https://github.com/user-attachments/assets/a8e2eed5-3057-436c-b303-3ac0ab0f4d48" />

Double-click on `VBoxWindowsAdditions` to start install.

<img width="520" alt="Screenshot 2025-01-29 102945" src="https://github.com/user-attachments/assets/8db49415-68c5-42d5-8f76-03adf7b8aa8e" />

`Next`

<img width="264" alt="Screenshot 2025-01-29 103042" src="https://github.com/user-attachments/assets/9f4f6448-ad85-4d86-8f5d-2df71f2f15f6" />

`Next`

<img width="255" alt="Screenshot 2025-01-29 103111" src="https://github.com/user-attachments/assets/775c0d18-3782-4728-81aa-107161c0d88d" />

`Install`

<img width="252" alt="Screenshot 2025-01-29 103145" src="https://github.com/user-attachments/assets/77efc00a-de4b-4525-a11c-212ae746b786" />

Select `Reboot Now` -> `Finish`

<img width="249" alt="Screenshot 2025-01-29 103244" src="https://github.com/user-attachments/assets/1ef9bd40-0193-4b5f-8241-ff9b9f98bf16" />

After restart, log into the system. From the VM toolbar click on `Devices` -> `Optical Drivers` -> `Remove disk from virtual drive` to remove the Guest Additions image.

Use the shortcut `Right Ctrl+F` to enter Fullscreen mode.

<img width="517" alt="Screenshot 2025-01-29 103757" src="https://github.com/user-attachments/assets/50609cf7-ff01-40a6-b62c-0aab206ebdb0" />

# Network Configuration

Inside the Windows Server VM, select the `Network Icon` in the bottom right. Then select `Open Network & Internet Settings`

<img width="202" alt="Screenshot 2025-01-29 104243" src="https://github.com/user-attachments/assets/df8dc39c-87e9-464d-a8d5-4a9fc10d527c" />

Select `Change Adapter Options`

<img width="508" alt="Screenshot 2025-01-29 104313" src="https://github.com/user-attachments/assets/f48a6392-2a4b-4f09-a5e8-163a614b15d9" />

Right click `Ethernet` -> `Properties`

<img width="298" alt="Screenshot 2025-01-29 104513" src="https://github.com/user-attachments/assets/f4a8621b-4e26-4e5c-a5d2-13d79ab7c5db" />

Select `Internet Protocol Version 4 (TCP/IPv4)` -> `click on Properties`

<img width="185" alt="Screenshot 2025-01-29 104616" src="https://github.com/user-attachments/assets/6ab7fff6-9f27-47a3-b987-0cece0d7e4ad" />

* IP address: `10.80.80.2`
* Subnet mask: `255.255.255.0`
* Default gateway: `10.80.80.1`
* Preferred DNS Server: `10.80.80.2`

<img width="196" alt="Screenshot 2025-01-29 104822" src="https://github.com/user-attachments/assets/3e91f88d-b1d1-4e71-97ff-6b2b512c80c2" />

<img width="765" alt="Screenshot 2025-01-29 104924" src="https://github.com/user-attachments/assets/d5391a1c-eaff-469e-927e-39c0fabc9574" />


In the settings `Home` select `System`

<img width="491" alt="Screenshot 2025-01-29 105035" src="https://github.com/user-attachments/assets/7a771e33-e9b3-481c-9fc7-ae4d2673e30d" />

Select `About`

<img width="254" alt="Screenshot 2025-01-29 105115" src="https://github.com/user-attachments/assets/3344a6c9-6373-429d-aa31-699102b55187" />

`Rename PC`: `DC1` -> `ok` -> `restart now`

<img width="499" alt="Screenshot 2025-01-29 105158" src="https://github.com/user-attachments/assets/c8aaf936-63ed-40e0-8422-b906d5943f6a" />

<img width="340" alt="Screenshot 2025-01-29 105216" src="https://github.com/user-attachments/assets/7a9d1c3f-231c-45ad-a021-d4f50126dba0" />

Once restart is complete, back in `Server Manager` -> Select `manage` -> `Add Roles and Features`

<img width="953" alt="Screenshot 2025-01-29 110040" src="https://github.com/user-attachments/assets/29182056-f5c8-40cf-957e-85baf4bf1872" />

Select `Next` then `Next again

<img width="391" alt="Screenshot 2025-01-29 110207" src="https://github.com/user-attachments/assets/f7b5fbf9-ae14-4ebc-b521-78fe41ad5b34" />

In `Server Roles` select  `Active Directory Domain Services` and `DNS Server`

When you enable a feature the `Add Roles and Features Wizard` will open click on `Add Features` to confirm the selection.

`Next` once complete

<img width="390" alt="Screenshot 2025-01-29 111027" src="https://github.com/user-attachments/assets/07f70891-1deb-4342-897a-a7b9ad71962a" />

Click `Confirmation Page` then `Install`

<img width="394" alt="Screenshot 2025-01-29 111107" src="https://github.com/user-attachments/assets/d68fabcd-c854-4032-8048-b968208d9b6f" />

<img width="392" alt="Screenshot 2025-01-29 111520" src="https://github.com/user-attachments/assets/4d84ff6d-b09d-400e-832e-ff26acf68b42" />

Next, select the flag in the top right with an explination mark. Then `promote to domain controller`

<img width="958" alt="Screenshot 2025-01-29 111632" src="https://github.com/user-attachments/assets/771842b1-4991-4263-906e-3c54015f23ea" />

For Deployment Configuration: Select `Add New Forest` -> Give name: `ad.lab`

Make sure if you are not naming this, to use this format [word_1.word_2]

Then clck `Next` -> then assign a password -> `Next`

<img width="376" alt="Screenshot 2025-01-29 112519" src="https://github.com/user-attachments/assets/8c9b1d21-25bb-488d-9f0e-dae0c4502df5" />

<img width="382" alt="Screenshot 2025-01-29 112605" src="https://github.com/user-attachments/assets/b7cf062a-cc10-4371-8ecd-0987951bd031" />

<img width="376" alt="Screenshot 2025-01-29 112921" src="https://github.com/user-attachments/assets/7dec916e-be21-42a3-b3be-31770dfb4883" />

<img width="376" alt="Screenshot 2025-01-29 112958" src="https://github.com/user-attachments/assets/f078b966-4664-4e19-bac8-a36feabd14df" />

<img width="375" alt="Screenshot 2025-01-29 113024" src="https://github.com/user-attachments/assets/c6fee7c3-9511-4715-b5b8-07bb525c5260" />

<img width="376" alt="Screenshot 2025-01-29 113136" src="https://github.com/user-attachments/assets/52cc774a-4554-439f-a6ed-4a0c53e274c7" />

You will see the `AD` before your Name now if successful.

<img width="378" alt="Screenshot 2025-01-29 113626" src="https://github.com/user-attachments/assets/87a4b741-4c2e-4ea5-a4b4-813004b07a49" />
















