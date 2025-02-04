![image](https://github.com/user-attachments/assets/2affe49b-7c89-42b8-a763-1987db3b358f)# Home-Lab


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

# DNS Configuration

Since we enabled DNS on the Domain Controller (DC), it will serve as the DNS server for devices in the ad.lab environment. To ensure proper functionality, we need to set up a Forwarder, which will send unresolved DNS queries to pfSense, allowing pfSense to complete the lookup.

Go to the windows logo and look for `Windows Administrative Tools`

<img width="313" alt="Screenshot 2025-01-29 133530" src="https://github.com/user-attachments/assets/87cc7604-fb9a-4841-8989-4e0685f80f6e" />

Then select `DNS`

<img width="315" alt="Screenshot 2025-01-29 133632" src="https://github.com/user-attachments/assets/b3582772-271b-441b-a103-fa85fe5ae5fd" />

Click `DC1` -> double click `Forwarders`

<img width="284" alt="Screenshot 2025-01-29 133757" src="https://github.com/user-attachments/assets/715464bb-bbf4-4709-b3f1-ddb53bf853d4" />

`Edit`

<img width="197" alt="Screenshot 2025-01-29 133831" src="https://github.com/user-attachments/assets/2e223a2b-924f-414f-bd14-e8ebe774e451" />

Enter the ip adress of the `AD_LAB`: `10.80.80.1` -> `Enter` -> `OK`

<img width="262" alt="Screenshot 2025-01-29 134131" src="https://github.com/user-attachments/assets/05b9ccdb-b891-4516-8755-1fb37fa94e3c" />

`Apply` -> `OK`

<img width="199" alt="Screenshot 2025-01-29 134254" src="https://github.com/user-attachments/assets/19c1b41f-4255-4d3f-bea4-bd48085c7240" />

# DHCP Configuration

Since DHCP is disabled on the `AD_LAB`, they arent being assigned an IP when connecting. To fix this we need to enable DHCP service.

Inside Windows Server 2019 vm go to `Manage` -> `Add Roles and Features`

<img width="198" alt="Screenshot 2025-01-29 134747" src="https://github.com/user-attachments/assets/16d8b249-b1e3-4d10-b857-9c1345df8e84" />

Click `Next` till you get to `Server Role` -> Enable `DHCP Server` -> `Add Features`

<img width="394" alt="Screenshot 2025-01-29 135000" src="https://github.com/user-attachments/assets/8770ee39-26e4-4758-bdd4-98d51ac80626" />

Click `Next` till you reach `Confirmation` -> then click `Install`

<img width="385" alt="Screenshot 2025-01-29 135303" src="https://github.com/user-attachments/assets/b07f1496-aa47-4711-8aca-ffc79cd2a2ca" />

Next click on the flag at the top -> select `Complete DHCP Configuration`

<img width="300" alt="Screenshot 2025-01-29 135958" src="https://github.com/user-attachments/assets/89113eb2-14bc-48b6-8bd6-544dfa6cb001" />

`Commit`

<img width="378" alt="Screenshot 2025-01-29 140117" src="https://github.com/user-attachments/assets/8849239b-cb1f-4fa2-a510-caab8dcdc3dd" />

After completion, go to the windows logo in the bottom left -> `Windows Administrative Tools` and then choose `DHCP`

<img width="325" alt="Screenshot 2025-01-29 140334" src="https://github.com/user-attachments/assets/6b72deb3-a572-46d7-8a74-7ad10838b4ab" />

Choose your DHCP server: `dc1.ad.lab`

<img width="296" alt="Screenshot 2025-01-29 140438" src="https://github.com/user-attachments/assets/61d7d6d1-7181-4525-8e4e-2abb850d49ca" />

Select `IPv4` -> `New Scope` this will give the scope of DHCP

<img width="295" alt="Screenshot 2025-01-29 140856" src="https://github.com/user-attachments/assets/e0c4cd2a-7601-43d9-bb94-43b912de26b0" />

<img width="262" alt="Screenshot 2025-01-29 140919" src="https://github.com/user-attachments/assets/8392780d-dcf0-474d-812b-9ab500945da6" />

* Name: `AD Lab` 
* Description: `Default DHCP for Ad Lab`

<img width="255" alt="Screenshot 2025-01-29 141000" src="https://github.com/user-attachments/assets/730b0cb9-027b-490c-9412-4f802bb1f6b8" />

* Start IP address: `10.80.80.11`
* End IP address: `10.80.80.253`
* Length: `24`
* Subnet mask: `255.255.255.0`

<img width="257" alt="Screenshot 2025-01-29 141317" src="https://github.com/user-attachments/assets/1d6d8546-40cf-4a22-a5e1-3576de5ac8c9" />

`Next`

<img width="261" alt="Screenshot 2025-01-29 141342" src="https://github.com/user-attachments/assets/61c86e3c-5fb6-45e2-8859-965e8ae301fd" />

Change to `365 Days`

<img width="259" alt="Screenshot 2025-01-29 141442" src="https://github.com/user-attachments/assets/05574de4-a9ee-4f5a-9678-d2a55dc16d24" />

`Yes, I want to configure these options now`

<img width="255" alt="Screenshot 2025-01-29 141521" src="https://github.com/user-attachments/assets/2b75d18b-7ef2-4fdd-bf87-37c782a228a3" />

In the IP address field enter the default gateway for the AD_LAB interface `10.80.80.1` and then click on `Add`. Once added click on `Next`.

![dc-57](https://github.com/user-attachments/assets/19475ad2-f87d-4205-8663-f78ff2d7cd09)

`Next`

<img width="254" alt="Screenshot 2025-01-29 141707" src="https://github.com/user-attachments/assets/eb75daa1-779f-4877-b768-059a560d45b3" />

`Next`

<img width="256" alt="Screenshot 2025-01-29 141803" src="https://github.com/user-attachments/assets/9c5faff5-d961-41fc-9707-a3f08eccdb14" />

`Yes, I want to activate this scope now`

<img width="256" alt="Screenshot 2025-01-29 141834" src="https://github.com/user-attachments/assets/3b6a73d8-190c-49e0-8197-1a84b9d5852c" />

<img width="256" alt="Screenshot 2025-01-29 141925" src="https://github.com/user-attachments/assets/41b8bf7c-279d-4c0a-a595-e9f7072362eb" />

# Domain Configuration

Select `Manage` from the top right corner of Server Manager and then select `Add Roles and Features`

<img width="178" alt="Screenshot 2025-01-29 143826" src="https://github.com/user-attachments/assets/e8ae058a-6d82-43ef-950c-62c95f18b262" />

Click `Next` till you get to `Server Roles` -> Enable `Active Directory Certificate Services`

<img width="391" alt="Screenshot 2025-01-29 144253" src="https://github.com/user-attachments/assets/da282a52-929e-43e0-97f0-0e723d06492b" />

<img width="389" alt="Screenshot 2025-01-29 144307" src="https://github.com/user-attachments/assets/42bbb388-a1d6-4a23-ba07-6aa8748794ea" />

<img width="392" alt="Screenshot 2025-01-29 144555" src="https://github.com/user-attachments/assets/a1f48a37-e120-4dda-97dd-15bb47884eaf" />

Click `Next` till you get to `Role Services`

<img width="392" alt="Screenshot 2025-01-29 144709" src="https://github.com/user-attachments/assets/5b08e4d6-ff45-44a9-afa8-06940572734d" />

<img width="388" alt="Screenshot 2025-01-29 144731" src="https://github.com/user-attachments/assets/3586a967-f993-4ec2-b387-ec017ce1f81d" />

Enable `Certificate Authority`

<img width="388" alt="Screenshot 2025-01-29 144754" src="https://github.com/user-attachments/assets/8a7384d9-eda0-4499-b322-b2559496607b" />

`Install`

<img width="394" alt="Screenshot 2025-01-29 144920" src="https://github.com/user-attachments/assets/72efd62b-e365-4348-b301-f5857e13c8cb" />

`Close`

<img width="393" alt="Screenshot 2025-01-29 145028" src="https://github.com/user-attachments/assets/80133499-fb00-4e26-92dd-401c130c6947" />

Then restart computer, click windows logo -> `Restart` -> `Continue`

<img width="198" alt="Screenshot 2025-01-29 145403" src="https://github.com/user-attachments/assets/2cfe9313-81e7-4113-acce-b16266e567bd" />

# Certificate Service Configuration

Once the restart is complete select the flag in the top right -> select `Configure Active Directory Certificate Services`

<img width="293" alt="Screenshot 2025-01-30 093606" src="https://github.com/user-attachments/assets/1f94ea44-3725-4dd0-aabd-57fa382322da" />

`Next`

<img width="379" alt="Screenshot 2025-01-30 093837" src="https://github.com/user-attachments/assets/b3001e41-3fe9-46ef-b2e0-42066b383703" />

Enable `Certification Authority`

<img width="376" alt="Screenshot 2025-01-30 093919" src="https://github.com/user-attachments/assets/efa16e5b-059f-4943-870d-f8a1f0c2e4a2" />

`Next`

<img width="379" alt="Screenshot 2025-01-30 093957" src="https://github.com/user-attachments/assets/ecb7f4b3-2033-4373-96e9-eb69e92637da" />

`Next`

<img width="379" alt="Screenshot 2025-01-30 094026" src="https://github.com/user-attachments/assets/1127ad6a-924d-4e16-a72e-ae4d6e36a02d" />

Click on `Next` till you reach the Confirmation page

<img width="377" alt="Screenshot 2025-01-30 094248" src="https://github.com/user-attachments/assets/53b1bf27-7c02-49d5-9135-0c33944bf4b8" />

`Close`

<img width="378" alt="Screenshot 2025-01-30 094315" src="https://github.com/user-attachments/assets/34beaf46-58c3-41df-a0e6-c934f29bd1fd" />

# User Configuration

Inside the `Start Menu` select `Administrative Tools` -> `Active Directory Users and Computers`

<img width="325" alt="Screenshot 2025-01-30 094645" src="https://github.com/user-attachments/assets/2b260ad2-617f-47a5-a1ce-19e1780a5223" />

right click `ad.lab` -> `New` -> `User`

<img width="380" alt="Screenshot 2025-01-30 095028" src="https://github.com/user-attachments/assets/281a51b0-346c-4d5d-8bfd-0d074252ce0e" />

This will be the administrator for the DC

Add a name and user login

<img width="216" alt="Screenshot 2025-01-30 095255" src="https://github.com/user-attachments/assets/d7d4aa5a-d94a-4fa4-93a9-bda65d956644" />

Enter a Password for the user 

Uncheck all options leaving `Password never expires` -> `Next`

<img width="216" alt="Screenshot 2025-01-30 095451" src="https://github.com/user-attachments/assets/e0bd9f82-ac76-4a11-a100-2d9996ccb848" />

`Finish`

<img width="216" alt="Screenshot 2025-01-30 095519" src="https://github.com/user-attachments/assets/59d08745-af4d-4a7b-a887-8120acd6d113" />

Expand the arrow next to `ad.lab` -> `Users` -> Double click `Domain Admins`

<img width="373" alt="Screenshot 2025-01-30 101110" src="https://github.com/user-attachments/assets/48e42841-c5f1-4274-b5ad-e5aa59b3ae1d" />

`Members` -> `Add`

<img width="201" alt="Screenshot 2025-01-30 101144" src="https://github.com/user-attachments/assets/4fb04768-3b2c-4a84-b8e5-b9e20e88dd75" />

Enter name -> `Check names`

<img width="234" alt="Screenshot 2025-01-30 101235" src="https://github.com/user-attachments/assets/f51ddc10-0f00-43c3-a304-146f6e8c880b" />

`OK`

<img width="229" alt="Screenshot 2025-01-30 101445" src="https://github.com/user-attachments/assets/e408b721-4862-42ea-af9f-d0725d960bcf" />

`Apply` -> `OK`

<img width="200" alt="Screenshot 2025-01-30 101523" src="https://github.com/user-attachments/assets/df0e73ca-6e6d-428d-84a4-a9a5daae199a" />

Next select the `User Icon` -> select `Sign out`

<img width="323" alt="Screenshot 2025-01-30 101627" src="https://github.com/user-attachments/assets/b66243f1-e53c-4cad-82a8-d6cb5b5d0961" />

Sign in wiht `other user` use credentials just made.

<img width="597" alt="Screenshot 2025-01-30 101708" src="https://github.com/user-attachments/assets/81f6bd88-44f3-4642-8279-d8986a61b5cf" />

# User 1 Setup

Open the `Start menu` -> Select `Windows Administrative Tools` -> `Active Directory Users and Computers`

<img width="333" alt="Screenshot 2025-01-30 102029" src="https://github.com/user-attachments/assets/403f6762-da17-4877-b619-dd027d633981" />

Right click `ad.lab` -> `New` -> `User`

<img width="376" alt="Screenshot 2025-01-30 102142" src="https://github.com/user-attachments/assets/5841ad2d-1c24-401f-b64c-70082d26fea5" />

Enter a name and login

<img width="211" alt="Screenshot 2025-01-30 102224" src="https://github.com/user-attachments/assets/4568a0c7-4ba9-4b43-b128-ce3e45f0f892" />

Enter a password and only select `User cannot change password` and `password never expires`

<img width="216" alt="Screenshot 2025-01-30 102442" src="https://github.com/user-attachments/assets/e9937843-8914-4191-a779-ab79d894ca6a" />

# User 2 Setup

Right click `ad.lab` -> `New` -> `User`

Fill in a name and login

<img width="214" alt="Screenshot 2025-01-30 102658" src="https://github.com/user-attachments/assets/7061eb1e-2f32-4eb6-bc9b-ccf8c82db61f" />

Enter a password and only select `User cannot change password` and `password never expires`

<img width="218" alt="Screenshot 2025-01-30 102742" src="https://github.com/user-attachments/assets/d5e1bb24-0070-4d93-afb7-567ce27a7daf" />

# Making AD Lab Exploitable

Right-click on the `Start menu` and select `Windows PowerShell (Admin)`

![dc-91](https://github.com/user-attachments/assets/1703c1bc-298c-4def-af8d-0d55a3c4a96e)

Run this command: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Force`

This command sets the PowerShell execution policy to Bypass, allowing all scripts to run without restrictions, and it does so without asking for confirmation.

<img width="269" alt="Screenshot 2025-01-30 103657" src="https://github.com/user-attachments/assets/89ed1bcd-ebe1-410a-9611-de06bf649651" />

Next use this command: 
`[System.Net.WebClient]::new().DownloadString('https://raw.githubusercontent.com/WaterExecution/vulnerable-AD-plus/master/vulnadplus.ps1') -replace 'change\.me', 'ad.lab' | Invoke-Expression`

What does this command do overall?

It downloads a PowerShell script (vulnadplus.ps1) from a GitHub repository.

It modifies the script by replacing the string change.me with ad.lab.

It executes the modified script directly in memory.

![dc-122](https://github.com/user-attachments/assets/9bb41b21-7e37-4981-98e3-b18e2529d27d)

Select `Start menu` and click on `Windows Administrative Tools` then choose `Group Policy Management`

<img width="318" alt="Screenshot 2025-01-30 110842" src="https://github.com/user-attachments/assets/0184a111-4fd5-4237-af1b-32b194d7a5b2" />

Right-click `ad.lab` -> Select `Create a GPO in the domain and link here`

<img width="478" alt="Screenshot 2025-01-30 111122" src="https://github.com/user-attachments/assets/aed24f80-bee6-4190-8831-20d98a3b444e" />

Name: `Disable Protections`

<img width="209" alt="Screenshot 2025-01-30 111232" src="https://github.com/user-attachments/assets/7187228f-3dc6-4a1e-bf41-483ec1a2f82c" />

Right click `Disable Protections` -> `Edit`

<img width="241" alt="Screenshot 2025-01-30 111609" src="https://github.com/user-attachments/assets/bdd7e9c8-b251-4db6-9cb7-f5ad2101a46d" />

Inside `Group Policy Management Editor` -> `Computer Configuration` -> `Policies` -> `Administrative Templates` -> `Windows Components` -> `Windows Defender Antivirus`

Select `Windows Defender Antivirus`

<img width="391" alt="Screenshot 2025-01-30 111841" src="https://github.com/user-attachments/assets/65152afc-a0ec-40dd-afe7-38171ab4e1b0" />

Select `Turn off Windows Defender Antivirus` -> `Edit policy setting`

<img width="390" alt="Screenshot 2025-01-30 112149" src="https://github.com/user-attachments/assets/6a63c630-f568-4391-bdd1-ab03bbfde951" />

Set to `Enabled` -> `Apply` -> `OK`

<img width="347" alt="Screenshot 2025-01-30 112240" src="https://github.com/user-attachments/assets/e79fd355-485e-4649-a397-d6f2a913a6f5" />

Double-click on `Real-time Protection`

<img width="389" alt="Screenshot 2025-01-30 112850" src="https://github.com/user-attachments/assets/c95b97b4-46ae-413d-83bf-07007c70ab33" />

Select `Turn off real-time protection` and then click on `Edit policy settings`

<img width="391" alt="Screenshot 2025-01-30 113202" src="https://github.com/user-attachments/assets/0f00a7d2-e36b-4c3c-86b2-040d159ad092" />

`Enable` -> `Apply` -> `OK`

<img width="348" alt="Screenshot 2025-01-30 113251" src="https://github.com/user-attachments/assets/e548af94-7b7b-4323-b990-048acd8ca795" />

Next in the sidebar `Computer Configuration` -> `Policies` -> `Administrative Templates` -> `Network` -> `Network Connections` -> `Windows Defender Firewall` -> `Domain Profile`

<img width="388" alt="Screenshot 2025-01-30 113530" src="https://github.com/user-attachments/assets/5b9f9bd8-bb42-4b84-a1d1-6ca212131a21" />

Select `Windows Defender Firewall: Protect all network connections` -> `Edit Policy`

<img width="440" alt="Screenshot 2025-01-30 113623" src="https://github.com/user-attachments/assets/a440862a-81b1-4802-a6d4-063ba299a7b7" />

`Disable` -> `Apply` -> `OK`

<img width="342" alt="Screenshot 2025-01-30 113725" src="https://github.com/user-attachments/assets/84a33671-2269-4d09-aa43-b71639903fe3" />

Close Group Policy Management Editor.

From the sidebar of `Group Policy Management` right-click on `Disable Protections` and choose `Enforced`.

<img width="376" alt="Screenshot 2025-01-30 113900" src="https://github.com/user-attachments/assets/9396ab01-e640-4cf8-8350-1acf4c61bb55" />

Next is enabling remote login for Local Admins

Right click `ad.lab` -> Select `Create a GPO in the domain and link here`

<img width="228" alt="Screenshot 2025-01-30 114232" src="https://github.com/user-attachments/assets/59a0956d-03ee-4113-be9e-a326ae15d272" />

Name: `Local Admin Remote Login`

<img width="208" alt="Screenshot 2025-01-30 114339" src="https://github.com/user-attachments/assets/70d58789-c3b7-4ef2-b7e6-f2f911d7edca" />

Right-click `Local Admin Remote Login` and choose `Edit`

<img width="245" alt="Screenshot 2025-01-30 114642" src="https://github.com/user-attachments/assets/bec9ec60-5257-47f7-9106-6395f47748d5" />

In the sidebar select `Computer Configuration` -> `Preferences` -> `Windows Settings` -> `Registry`

Then right click `Registry`-> `New` -> `Registry Item`

<img width="397" alt="Screenshot 2025-01-30 114837" src="https://github.com/user-attachments/assets/9428abae-a768-42f8-970a-cd4713fc3604" />

Hive: `HKEY_LOCAL_MACHINE` -> Key Path select `...` -> `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` -> `Select`

<img width="207" alt="Screenshot 2025-01-30 115222" src="https://github.com/user-attachments/assets/237ede83-85f6-4611-b4f4-9d5980014a10" />

* Value name: `LocalAccountTokenFilterPolicy`
* Value type: `REG_DWORD`
* Value data: `1`

<img width="198" alt="Screenshot 2025-01-30 115346" src="https://github.com/user-attachments/assets/99601270-3866-48a2-ae02-7ffee6897154" />

Right click `ad.lab` Select `Create a GPO in the domain and link here`

<img width="235" alt="Screenshot 2025-01-30 134833" src="https://github.com/user-attachments/assets/1512a3d5-2d95-46b9-872f-5c372b710b7f" />

Name: `Enable WinRM Server`

<img width="196" alt="Screenshot 2025-01-30 134910" src="https://github.com/user-attachments/assets/6d7a789c-0af0-4f8a-a294-9a74cecde73c" />

Right-click `Enable WinRM Server` -> `Edit`

<img width="214" alt="Screenshot 2025-01-30 135011" src="https://github.com/user-attachments/assets/1b4642f4-5edf-49e3-ae73-928fb6d7c595" />

In the sidebar go to `Computer Configuration` -> `Policies` -> `Administrative Templates` -> `Windows Components` -> `Windows Remote Management (WinRM)` -> `WinRM Service`

<img width="393" alt="Screenshot 2025-01-30 135251" src="https://github.com/user-attachments/assets/f5e1fc10-b347-4a4b-89f9-f8a204a1085c" />

Select `Allow remote server management through WinRM` -> `Edit policy settings`

<img width="397" alt="Screenshot 2025-01-30 140117" src="https://github.com/user-attachments/assets/31e0d9f8-32ee-411a-b52d-9f595a431cd7" />

* Select `Enable` -> IPv4: `*` -> `Apply` -> `OK`

<img width="351" alt="Screenshot 2025-01-30 140248" src="https://github.com/user-attachments/assets/e93222fd-7eed-488e-a209-00c5289910d6" />

`Allow Basic authentication` -> `Edit policy settings`

<img width="388" alt="Screenshot 2025-01-30 140401" src="https://github.com/user-attachments/assets/91906102-9c69-49e4-a8f1-a7b443161848" />

`Enable` -> `Apply` -> `OK`

<img width="347" alt="Screenshot 2025-01-30 140436" src="https://github.com/user-attachments/assets/430258a1-75e9-47e9-8e7e-5839f2997d4c" />

`Allow unencrypted traffic` -> `Edit policy settings`

<img width="391" alt="Screenshot 2025-01-30 140535" src="https://github.com/user-attachments/assets/2a0837f6-2701-43c8-ae39-4cc8801a9d9a" />

`Enable` -> `Apply` -> `OK`

<img width="344" alt="Screenshot 2025-01-30 140604" src="https://github.com/user-attachments/assets/4dfd876f-7f96-4c16-8efc-6a2bf9ee9fff" />

`Computer Configuration` -> `Preferences` -> `Control Panel Settings` -> Right-click `Services` -> `New` -> `Service`

<img width="392" alt="Screenshot 2025-01-30 140751" src="https://github.com/user-attachments/assets/0a30f9f1-032f-48ba-a119-09e34c80a9d6" />

Startup: `Automatic` -> Select `...`

<img width="199" alt="Screenshot 2025-01-30 140919" src="https://github.com/user-attachments/assets/9f030a4a-855e-436b-9787-a98668bce48c" />

Select `Windows Remote Management (WS-Management)`

<img width="230" alt="Screenshot 2025-01-30 141105" src="https://github.com/user-attachments/assets/0b7e6e67-8359-4f37-93af-6a61ff9ca705" />

Service action: `Start servic` -> `Apply` -> `OK`

<img width="199" alt="Screenshot 2025-01-30 141150" src="https://github.com/user-attachments/assets/bfb4f64b-be12-44ad-bf03-52c4fe1724a6" />

In the sidebar `Computer Configuration` -> `Policies` -> `Administrative Templates` -> `Windows Components` -> `Windows Remote Shell`

`Allow Remote Shell Access` -> `Edit policy setting`

<img width="391" alt="Screenshot 2025-01-30 141714" src="https://github.com/user-attachments/assets/c10dd657-aae4-46c2-b6a5-5226b6cb761f" />

`Enable` -> `Apply` -> `OK`

<img width="346" alt="Screenshot 2025-01-30 141747" src="https://github.com/user-attachments/assets/bba38f13-6e29-45e4-9d8b-ca455d09f65c" />

Right click `ad.lab` -> `Create a GPO in the domain and link here`

<img width="216" alt="Screenshot 2025-01-30 141848" src="https://github.com/user-attachments/assets/414c73d2-c5a2-49b9-a0c3-0b5a2ea7c67f" />

`Enable` -> `OK`

<img width="197" alt="Screenshot 2025-01-30 141943" src="https://github.com/user-attachments/assets/28b06284-f5f0-492d-a5b5-b6a1f1322e29" />

Right click `Enable RDP` -> `Edit`

<img width="286" alt="Screenshot 2025-01-30 142013" src="https://github.com/user-attachments/assets/30dae32e-ec5b-4c99-973b-fcc93672dd63" />

`Computer Configuration` -> `Policies` -> `Administrative Templates` -> `Windows Components` -> `Remote Desktop Services` -> `Remote Desktop Session Host` -> `Connections`

`Allow users to connect remotely using Remote Desktop Services` -> `Edit policy settings`

<img width="390" alt="Screenshot 2025-01-30 142414" src="https://github.com/user-attachments/assets/0a37f018-d462-41df-b101-aeb14c2f62c1" />

`Enable` -> `Apply` -> `OK`

<img width="351" alt="Screenshot 2025-01-30 142446" src="https://github.com/user-attachments/assets/38356bf3-1640-41f5-ace6-6b86f07eb5fa" />

Enable RPC (Remote Procedure Call)

Right click `ad.lab` -> `Create a GPO in the domain and link here`

<img width="241" alt="Screenshot 2025-01-30 142554" src="https://github.com/user-attachments/assets/6bf4918c-0466-4bfb-bf48-94eb161474f4" />

Name: `Enable RPC`

<img width="197" alt="Screenshot 2025-01-30 142640" src="https://github.com/user-attachments/assets/9bbeac35-6780-431c-a694-f2c01e9d5352" />

Right click `Enable RPC` -> `Edit`

<img width="205" alt="Screenshot 2025-01-30 142717" src="https://github.com/user-attachments/assets/1c05f3ad-cfd8-472c-9a6c-463eada78cba" />

`Computer Configuration` -> `Policies` -> `Administrative Templates` -> `System` -> `Remote Procedure Call`

`Enable RPC Endpoint Mapper Client Authentication` -> `Edit policy settings`

<img width="390" alt="Screenshot 2025-01-30 142955" src="https://github.com/user-attachments/assets/ba31dcd5-7f74-4260-97f0-c7382373e025" />

`Enable` -> `Apply` -> `OK`

<img width="343" alt="Screenshot 2025-01-30 143040" src="https://github.com/user-attachments/assets/f4f4dede-6ed8-494b-acf9-0cb0b5343a3d" />

You can exit the group managment editor -> right click the `Start menu` -> `Windows PowerShell (Admin)`

<img width="163" alt="Screenshot 2025-01-30 143222" src="https://github.com/user-attachments/assets/76288579-a334-4fef-a6ae-ab7b5229a536" />

Inside the powershell run this command: `gpupdate /force`

Now, whenever a new device joins our AD environment, the applicable Group Policies will be automatically applied. With this, the Domain Controller setup is complete.

<img width="222" alt="Screenshot 2025-01-30 143453" src="https://github.com/user-attachments/assets/c7595d21-3aff-4d92-9987-f02e723e1305" />

For the future you must start the DC vm before any other AD users vm's.

# Windows 10 Enterprise VM 1 Setup

From Oracle VirtualBox select the `Windows 10 Enterprise VM 1`

<img width="605" alt="Screenshot 2025-01-31 091308" src="https://github.com/user-attachments/assets/381f72ee-f14e-4a62-b717-ee2aa0c969a3" />

`Next`

<img width="321" alt="Screenshot 2025-01-31 091418" src="https://github.com/user-attachments/assets/b348d687-b0b9-4a34-b26e-e90932889526" />

`Install`

<img width="307" alt="Screenshot 2025-01-31 091438" src="https://github.com/user-attachments/assets/ef1f90cc-9177-4978-84d6-00819cdbe46d" />

`Next`

<img width="337" alt="Screenshot 2025-01-31 091524" src="https://github.com/user-attachments/assets/89cc3c41-ef27-4dee-8cbb-8e02af188107" />

`Custom: Install Windows only (advanced)`

<img width="350" alt="Screenshot 2025-01-31 091547" src="https://github.com/user-attachments/assets/518e92da-d991-4b06-9a32-3cd2b0f9ec66" />

`Next`

<img width="337" alt="Screenshot 2025-01-31 091623" src="https://github.com/user-attachments/assets/9803f3e9-5ca5-4624-b644-b3462f8aef6e" />

After the rebooting of the system for install select your region and layout.

<img width="508" alt="Screenshot 2025-01-31 150838" src="https://github.com/user-attachments/assets/9e0cabc1-eaf6-4335-ad86-3179c560ebbe" />

<img width="505" alt="Screenshot 2025-01-31 150929" src="https://github.com/user-attachments/assets/cc21aa44-9e22-402b-8b61-2de297342b8f" />

To configure a local account select `Domain join instead` -> Enter a `username` I used `John` Since that was the user name I chose for VM 1

<img width="515" alt="Screenshot 2025-01-31 151538" src="https://github.com/user-attachments/assets/2e93f1fc-8d26-4000-8105-b7037b1678dd" />

Create a `Password`

<img width="517" alt="Screenshot 2025-01-31 151649" src="https://github.com/user-attachments/assets/e0ac8077-397f-41d2-a33f-4af3dbd6fdf1" />

Enter security questions and save somewhere safe.

De select all options

<img width="515" alt="Screenshot 2025-01-31 152946" src="https://github.com/user-attachments/assets/e80ddec4-e29e-4dde-926f-3a6de5524e1f" />

`Not now`

<img width="505" alt="Screenshot 2025-01-31 153019" src="https://github.com/user-attachments/assets/534d8a37-0cf9-4b07-8328-770e4d901844" />

Once finished select `yes` to allow internet access.

<img width="501" alt="Screenshot 2025-01-31 153345" src="https://github.com/user-attachments/assets/0ce8269e-b38a-406d-a8b5-1190c91b9564" />


Next is to install `Guess Additions` to enable fullscreen mode. 

`Devices` -> `Remove disk for virtual drive` this will remove the Windows 10 image.

![user-17](https://github.com/user-attachments/assets/4877b6b5-86f3-466b-af55-3fb635f9db63)

`Devices` -> `Insert Guest Additions CD image`

![user-18](https://github.com/user-attachments/assets/a2e403fb-d697-42d0-b1f4-da08eb5978ba)

Select `VBoxWindowsAdditions` to start install

<img width="241" alt="Screenshot 2025-02-01 132130" src="https://github.com/user-attachments/assets/9a63e7be-7e18-4bc0-a7fc-816b6670fd2f" />

`Next`

<img width="256" alt="Screenshot 2025-02-01 132228" src="https://github.com/user-attachments/assets/2fc0e6de-4c09-4bb1-b764-5ff7a83ea5d6" />

`Next` 

<img width="250" alt="Screenshot 2025-02-01 132728" src="https://github.com/user-attachments/assets/99dda151-0d10-4d8a-9639-9b6a4e2c0055" />

`Install`

<img width="250" alt="Screenshot 2025-02-01 132955" src="https://github.com/user-attachments/assets/d1ee1b47-211d-4ee0-aa42-2b5513246878" />

`Reboot Now`

<img width="253" alt="Screenshot 2025-02-01 134340" src="https://github.com/user-attachments/assets/b3fb961e-bf27-4d06-9a04-78360044d88c" />

I had an error that looked like this.

<img width="216" alt="Screenshot 2025-02-01 135749" src="https://github.com/user-attachments/assets/33f5acf4-bcc4-4948-8d95-4295d426e5ad" />

To work around this when it asks, `Reboot Now` or `manually` select `Manually`

![Screenshot 2025-02-01 134336](https://github.com/user-attachments/assets/b75385e6-24b5-4617-897d-b1380cde17f6)

Then press `right ctrl` + `q` -> select `Power off Machine` -> Then just boot up and login normally from VirtualBox

From the toolbar `Optical Devices` -> `Remove disk from virtual drive`

![user-25](https://github.com/user-attachments/assets/ba5da873-9bbe-4874-9b88-3701692889df)

Now you have the ability to enter fullscreen mode using `Right Ctrl+F`

# Adding VM1 to Domain

This section will allow us as an AD user to join the AD domain.

Select the search bar in the bottom right of the desktop. -> search `This PC` -> Right click -> `Properties`

<img width="476" alt="Screenshot 2025-02-01 142329" src="https://github.com/user-attachments/assets/6260beab-accc-4fb5-8346-f711500db84a" />

`Advanced system settings`

<img width="130" alt="Screenshot 2025-02-01 142719" src="https://github.com/user-attachments/assets/073c6369-0b15-422b-af2a-e6199771bbf5" />

`Computer Name` -> `Change`

<img width="208" alt="Screenshot 2025-02-01 142831" src="https://github.com/user-attachments/assets/58d47c5d-d10a-4ef3-b72f-c1ce6c88bc63" />

Name: `WIn10_VM1` Feel free to name anything youd like.

In the Member of select `Domain` -> enter in `ad.lab` -> `more`

<img width="167" alt="Screenshot 2025-02-01 143032" src="https://github.com/user-attachments/assets/8ba76904-6902-4f9c-aa58-a3730bbebe1a" />

Enter domain name: `ad.lab`

<img width="196" alt="Screenshot 2025-02-01 143247" src="https://github.com/user-attachments/assets/14e078ac-d5a5-4951-8a25-b02e5c3d01fa" />

'ok`

<img width="161" alt="Screenshot 2025-02-01 143307" src="https://github.com/user-attachments/assets/e76607e2-ac94-4199-bbc4-07a6bcea8574" />

<img width="178" alt="Screenshot 2025-02-01 143330" src="https://github.com/user-attachments/assets/01555174-fe53-4ee6-babb-e305882b5b28" />

<img width="229" alt="Screenshot 2025-02-01 143620" src="https://github.com/user-attachments/assets/01711535-6a31-4735-8d79-e2c1f923a3f1" />

<img width="124" alt="Screenshot 2025-02-01 143641" src="https://github.com/user-attachments/assets/01d26762-0ce5-4f14-b58e-d72bcf6f6774" />

<img width="175" alt="Screenshot 2025-02-01 143658" src="https://github.com/user-attachments/assets/76ded3e9-8433-42d3-9b33-9490f2b528ad" />

For me I took a snapshot, then select `File` -> `Close` -> `Power Off Machine` -> Then reboot from OracleBox

Once rebooted select `Other user` login using the `john.doe` login

<img width="371" alt="Screenshot 2025-02-01 144614" src="https://github.com/user-attachments/assets/c024c892-2230-4a05-a261-b7eba044a3eb" />

Once inside open `PowerShell` and run the command: `whoami` and `ipconfig` to confirm

<img width="267" alt="Screenshot 2025-02-01 145221" src="https://github.com/user-attachments/assets/06605276-4b11-4f44-8594-0b5f16b23c1d" />

# Windows 10 Enterprise VM2 Setup

Select the vm in OracleBox -> select `Start`

Same as VM 1

<img width="592" alt="Screenshot 2025-02-01 145442" src="https://github.com/user-attachments/assets/13993a85-7b8f-4346-9347-298690f70bf8" />

<img width="311" alt="Screenshot 2025-02-01 145718" src="https://github.com/user-attachments/assets/7048de5c-cf98-4c0b-a7ef-e6139ec49086" />

<img width="310" alt="Screenshot 2025-02-01 145747" src="https://github.com/user-attachments/assets/35136699-dd92-4aea-a28a-805612010718" />

<img width="326" alt="Screenshot 2025-02-01 145907" src="https://github.com/user-attachments/assets/32436d96-42ba-49e5-8eb1-18ed15ba0769" />

<img width="316" alt="Screenshot 2025-02-01 145924" src="https://github.com/user-attachments/assets/54225734-391f-4cbc-8b2d-7718f53a4095" />

<img width="322" alt="Screenshot 2025-02-01 150000" src="https://github.com/user-attachments/assets/af2017f2-049e-49f7-9aa2-3395fd1e1fe6" />

<img width="509" alt="Screenshot 2025-02-01 153622" src="https://github.com/user-attachments/assets/f2fe5dc7-4502-4eaa-a56f-bcfbfd09e2c8" />

Use same name as Vm 2: `Jane`

<img width="506" alt="Screenshot 2025-02-01 154731" src="https://github.com/user-attachments/assets/e590a7fa-f3d0-48c3-8b0b-87479ff5f8b8" />

<img width="422" alt="Screenshot 2025-02-01 154759" src="https://github.com/user-attachments/assets/f3674ac9-5af8-4d9c-8571-2aaf314d9462" />

<img width="489" alt="Screenshot 2025-02-01 154846" src="https://github.com/user-attachments/assets/c3b6577d-8e83-4cc8-8783-e7d7e6128ed3" />

<img width="509" alt="Screenshot 2025-02-01 154942" src="https://github.com/user-attachments/assets/c660cdd4-1e3a-48c5-aa23-f14b31ca3dda" />

<img width="476" alt="Screenshot 2025-02-01 155153" src="https://github.com/user-attachments/assets/86b69f68-bcc8-4386-82f3-6fb5589f69cf" />

<img width="175" alt="Screenshot 2025-02-01 155503" src="https://github.com/user-attachments/assets/cc8056cc-834b-48d8-8d5a-22bad3a1ec28" />

Guest Additions Installation (Same as before)

![user-17](https://github.com/user-attachments/assets/8560579c-a932-47b9-9a3e-f0c068b12fc7)

![user-18](https://github.com/user-attachments/assets/f8012930-e6b5-4671-a2cc-aa2509f4e20e)

<img width="400" alt="Screenshot 2025-02-01 155904" src="https://github.com/user-attachments/assets/0003d8ab-1f41-4fd3-9e0c-ed9969c4732e" />

<img width="234" alt="Screenshot 2025-02-01 155942" src="https://github.com/user-attachments/assets/2c8fba73-a92b-475e-9ab2-4804a043fc33" />

<img width="247" alt="Screenshot 2025-02-01 160137" src="https://github.com/user-attachments/assets/b23ab435-0d2e-4d2f-b30b-748c28938e15" />

<img width="244" alt="Screenshot 2025-02-01 160152" src="https://github.com/user-attachments/assets/a0d5b908-d1c5-4a05-902e-83ac520439ef" />

<img width="253" alt="Screenshot 2025-02-01 160206" src="https://github.com/user-attachments/assets/361a32e1-4e54-49b4-825b-339de1af674f" />

<img width="248" alt="Screenshot 2025-02-01 160327" src="https://github.com/user-attachments/assets/cb3659a0-43e5-4171-8740-f4a22244f9fd" />

<img width="262" alt="Screenshot 2025-02-01 160501" src="https://github.com/user-attachments/assets/8760f1f7-fd2f-423d-9b39-d9fb58513379" />

Reboot from VirtualBox 

Ignore my dumb dumb saves I couldnt remember.

<img width="579" alt="Screenshot 2025-02-01 160644" src="https://github.com/user-attachments/assets/324454e5-de46-4e07-a031-3ccfe046682a" />

<img width="213" alt="Screenshot 2025-02-01 160918" src="https://github.com/user-attachments/assets/6079437f-3bd8-4ba7-a0e8-1e6f8aaaa9ef" />

![user-25](https://github.com/user-attachments/assets/71b2ad27-bf83-42d8-846d-7fa41c3d189a)

# Adding VM2 to Domain

Same as VM 1

<img width="384" alt="Screenshot 2025-02-01 161208" src="https://github.com/user-attachments/assets/32b8cc6b-4184-4166-b0ab-76a7e7c55de8" />

<img width="399" alt="Screenshot 2025-02-01 161407" src="https://github.com/user-attachments/assets/d5f77dd1-b0df-44c2-b463-55b78715bb03" />

<img width="208" alt="Screenshot 2025-02-01 161558" src="https://github.com/user-attachments/assets/915e37d7-b835-4678-a927-653afb7c36af" />

<img width="165" alt="Screenshot 2025-02-01 161658" src="https://github.com/user-attachments/assets/7e952308-87d1-4f79-9df8-b1723038d98f" />

<img width="197" alt="Screenshot 2025-02-01 161808" src="https://github.com/user-attachments/assets/7cd4b2bf-7239-4b09-b1ba-706b56004f60" />

<img width="189" alt="Screenshot 2025-02-01 161828" src="https://github.com/user-attachments/assets/5d114fd1-e6c4-4e64-8fe9-c7cc3fc27a56" />

<img width="133" alt="Screenshot 2025-02-01 161941" src="https://github.com/user-attachments/assets/683476bb-6389-46ce-be83-13647a6f8693" />

<img width="178" alt="Screenshot 2025-02-01 162008" src="https://github.com/user-attachments/assets/7118682d-6f56-4472-adf0-68d06baa43de" />

<img width="238" alt="Screenshot 2025-02-01 162050" src="https://github.com/user-attachments/assets/24dd2c16-3c0b-41f4-b0c0-0a3dd4773f98" />

<img width="502" alt="Screenshot 2025-02-01 162345" src="https://github.com/user-attachments/assets/a0200ad5-4807-475f-9a43-d756d797eb3f" />

# DNS & DHCP Verification

Inside `DHCP Manager` inside of the `DC` vm -> `IPv4` -> `Address leases` -> Here we can see our AD lab vms

<img width="286" alt="Screenshot 2025-02-02 142546" src="https://github.com/user-attachments/assets/8fb6ca4a-ca14-447e-b27a-7f8efe861b30" />

Inside `DNS Manager` you can see our DNS entries

<img width="376" alt="Screenshot 2025-02-02 142901" src="https://github.com/user-attachments/assets/2b39af15-f6d7-46fb-94dd-53393c84a93a" />

This will conclude the building of the Domain Controller and Active Directory Lab. Next will be the setup of the Malware Analysist Lab.

# Malware Analysis Lab Setup

In this section I will set up 2 Vms, 1 for Windows Malware analysis, 1 for Linux Malware Analysis.

Im needing to add a new interface to pfSense, but they are full at 4. The way to get up to 8 is through the command line interface or CLI.

Inside of the `host computer` -> select `C` drive -> `Program Files` -> `Oracle` -> Select `VBoxManage.exe` -> Copy the path at the top `C:\Program Files\Oracle\VirtualBox`

The VirtualBox CLI binary is `VBoxManage.exe`

<img width="588" alt="Screenshot 2025-02-02 150111" src="https://github.com/user-attachments/assets/6becb511-d71e-4760-82e0-6a7c5bc5b54b" />

Next in the search bar type  and select `Edit environment variables for your account` -> select `Path`

<img width="438" alt="Screenshot 2025-02-02 150706" src="https://github.com/user-attachments/assets/7914d3b6-ec6f-40b3-b037-6502d0e4411d" />

Select `New` and paste `C:\Program Files\Oracle\VirtualBox` -> `OK`

<img width="367" alt="Screenshot 2025-02-02 150956" src="https://github.com/user-attachments/assets/dda103cd-5576-488c-a1c9-eabbfff3da7d" />

<img width="370" alt="Screenshot 2025-02-02 151041" src="https://github.com/user-attachments/assets/fb055439-9e8f-47e3-93fe-379a708f1478" />

Next to check if that worked, open `Powershell` and get into the Virtual Box file by entering this command: `cd /` to get to your "home" -> `cd ./ProgramFiles/Oracle/VirtualBox` -> `VBoxManage list vms`

<img width="550" alt="Screenshot 2025-02-02 152031" src="https://github.com/user-attachments/assets/404d4f00-fce4-4e4d-b6c5-31c3b3da6b95" />

I just have some clones for testing, if your following you wouldnt have those.

# Creating an Interface

First note down the name of the `pfsense VM` mine is `pfSense`

Also make sure the vm is offline.

<img width="595" alt="Screenshot 2025-02-03 100040" src="https://github.com/user-attachments/assets/2480b305-34f2-4a9d-9f34-5bbfae20788b" />

Inside `PowerShell` run these commands.

To create an Internet Network: `VBoxManage modifyvm "pfSense" --nic5 intnet`

Paravirtualized Adapter: `VBoxManage modifyvm "pfSense" --nictype5 virtio`

Give it a name of LAN 3: `VBoxManage modifyvm "pfSense" --intnet5 "LAN 3"`

<img width="499" alt="Screenshot 2025-02-03 101710" src="https://github.com/user-attachments/assets/5e5d2d09-ff63-49ca-96d1-ef7b037faab2" />

<img width="535" alt="Screenshot 2025-02-03 101723" src="https://github.com/user-attachments/assets/07f7e464-cd4d-446a-8f98-0bbb9c47ce2b" />

Now to see if the new Interface has been added look in VirtualBox

<img width="593" alt="Screenshot 2025-02-03 101810" src="https://github.com/user-attachments/assets/0cda4e4b-1cca-4faa-9873-dc758f8d020b" />

Any further editting of this interface has to be done through the CLI.

# Enabling the New Interface

Start up the `pfSense vm`

On boot it wont show the new interface to fix this enter in `1` to the menu.

<img width="355" alt="Screenshot 2025-02-03 102230" src="https://github.com/user-attachments/assets/13770602-6260-46c2-b7ef-79bae3a15d7a" />

Should VLANs be set up now? `n`

<img width="360" alt="Screenshot 2025-02-03 102632" src="https://github.com/user-attachments/assets/dfff3225-1071-4d8d-9053-cd49adb3701e" />

Enter the WAN interface name: `vtnet0`
Enter the LAN interface name: `vtnet1`
Enter the Optional 1 interface name: `vtnet2`
Enter the Optional 2 interface name: `vtnet3`
Enter the Optional 3 interface name: `vtnet4`
Do you want to proceed?: `y`

<img width="322" alt="Screenshot 2025-02-03 102844" src="https://github.com/user-attachments/assets/82e8c8b8-4230-4066-a0ab-daa2c63c4df2" />

We can see the interface now, but it needs an IP assigned.

<img width="361" alt="Screenshot 2025-02-03 102927" src="https://github.com/user-attachments/assets/b4ece991-c936-499f-af41-1a8e2fb290f5" />

Enter `2` to select `Set interface(s) IP address`

<img width="358" alt="Screenshot 2025-02-03 103347" src="https://github.com/user-attachments/assets/0f2b557a-631f-4ca8-841e-a0ef282ad0bc" />

Enter `5` to select the `OPT3 interface`

<img width="360" alt="Screenshot 2025-02-03 103451" src="https://github.com/user-attachments/assets/89a65718-1bdc-4c70-9189-2782d02ae201" />

* Configure IPv4 address OPT3 interface via DHCP?: `n`
* Enter the new OPT3 IPv4 address: `10.99.99.1`
* Enter the new OPT3 IPv4 subnet bit count: `24`

<img width="364" alt="Screenshot 2025-02-03 103547" src="https://github.com/user-attachments/assets/98d4eb6c-d6a9-43f2-9655-4077ecef7db7" />

`Enter` no need for upstream gateway

<img width="362" alt="Screenshot 2025-02-03 103700" src="https://github.com/user-attachments/assets/9268a73d-ca51-4e4f-95a5-33be8af1b6b1" />

* Configure IPv6 address OPT3 interface via DHCP6: `n`
* For the new OPT3 IPv6 address question press `Enter`
* Do you want to enable the DHCP server on OPT3?: `y`
* Enter the start address of the IPv4 client address range: `10.99.99.11`
* Enter the end address of the IPv4 client address range: `10.99.99.243`
* Do you want to revert to HTTP as the webConfigurator protocol?: `n`

<img width="361" alt="Screenshot 2025-02-03 103832" src="https://github.com/user-attachments/assets/4ba3c39a-31e2-46bc-899d-f41acbba944f" />

Should look like this

<img width="362" alt="Screenshot 2025-02-03 103928" src="https://github.com/user-attachments/assets/3e663519-e699-450a-b200-186ac0f5bb64" />

Rename New Interface

Open `Kali Linux VM` 

From the tool bar at the top select `Interfaces -> OPT3`

<img width="337" alt="Screenshot 2025-02-04 133539" src="https://github.com/user-attachments/assets/e3ddfc28-a6af-4861-8c5d-89e89f841c95" />

In the description field enter `ISOLATED` -> `save`

<img width="437" alt="Screenshot 2025-02-04 133630" src="https://github.com/user-attachments/assets/f1ee280b-2e0e-4893-8f4b-6a8a3bf2cd9e" />

<img width="590" alt="Screenshot 2025-02-04 133650" src="https://github.com/user-attachments/assets/a8bc1049-ef02-40db-8446-ac2a4f2dd81d" />

# Interface Firewall Configuration

The reason for this firewall configuration is since their will be malicous data I dont want it spreading to the rest of the network.

From the top tool bar select `Firewall` -> `Rules`

<img width="307" alt="Screenshot 2025-02-04 133835" src="https://github.com/user-attachments/assets/8eca96b7-3708-4a9b-89de-aa97c3b0c7b3" />

Select `ISOLATED` -> `ADD`

<img width="611" alt="Screenshot 2025-02-04 133916" src="https://github.com/user-attachments/assets/2ebd3f7d-1c9d-4eef-b69b-f085187749a4" />

* Action: `Block`
* Address `Family: IPv4+IPv6`
* Protocol: `Any`
* Source: `ISOLATED subnets`
* Description: `Block access to everything`
* Scroll to the bottom and click on `Save`

<img width="607" alt="Screenshot 2025-02-04 134134" src="https://github.com/user-attachments/assets/3d66eb8e-91b8-492f-909a-74668f0b90f9" />

<img width="594" alt="Screenshot 2025-02-04 134209" src="https://github.com/user-attachments/assets/f44ad7a9-06fd-4a01-aeee-a54fa84fb5e6" />

Next is to reboot to have these changes take effect.

In the top tool bar select `Diagnostics` -> `Reboot`

<img width="594" alt="Screenshot 2025-02-04 134429" src="https://github.com/user-attachments/assets/83778837-53b8-423f-8594-e992d51010ba" />

<img width="600" alt="Screenshot 2025-02-04 134457" src="https://github.com/user-attachments/assets/8a75bd52-1c02-4003-bd85-45ed793ffac5" />

# Flare VM Setup

To complete the flare VM setup we need a windows machine. And since I still have the windows 

If you need to download Windows again find it here: https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise

<img width="766" alt="Screenshot 2025-02-04 134851" src="https://github.com/user-attachments/assets/51dc3cd4-4a99-4761-8d7f-65f04e341916" />

From VirtualBox select `Tools` -> `New`

<img width="447" alt="Screenshot 2025-02-04 134952" src="https://github.com/user-attachments/assets/5d2792bf-9547-4948-b83e-dec6c4eb7503" />

* Name: `Flare VM`
* File: `vm folder`
* ISO Image: `Windows ISO`
* Select `Skip Unattened Installtion

<img width="760" alt="Screenshot 2025-02-04 135148" src="https://github.com/user-attachments/assets/2879abde-cebd-48ff-992d-dc21ff3b03f8" />

In the `Hardware` tab increase base memory to `4096MB`

<img width="634" alt="Screenshot 2025-02-04 135435" src="https://github.com/user-attachments/assets/bb11b62a-b363-4c7e-b02f-e783bb6b9bae" />

In ther Hard Disk tab increase disk space to `100GB`

<img width="750" alt="Screenshot 2025-02-04 135542" src="https://github.com/user-attachments/assets/175da734-f533-4bf2-a96a-9ba32ebbd945" />

Moving the FLare VM into a new group

Select `Flare VM` -> `Machine` -> `Move to Group` -> `New` -> Select the new group -> `Group` -> `Rename Group` to `Malware Analyst`

<img width="431" alt="Screenshot 2025-02-04 135938" src="https://github.com/user-attachments/assets/3a8ec1c1-68f3-44ab-89a4-7741d2b6d71e" />

# Configuring Flare VM

Select the VM -> `settings`

<img width="438" alt="Screenshot 2025-02-04 140124" src="https://github.com/user-attachments/assets/0bc04eaa-0b0d-4f7e-9882-9d11ff212a1b" />

Select `System` -> `Motherboard` -> `Boot Order` -> make sure its selected `Hard Disk` -> selcted `Optical` -> unchecked `Flobby` -> unchecked `Network`

<img width="577" alt="Screenshot 2025-02-04 140404" src="https://github.com/user-attachments/assets/3040cf19-3ba3-4adc-a21a-43ffd5bb8a56" />

In the `Network` tab, make sure to have NAT selected. This will be changed once Flare is setup. 

<img width="569" alt="Screenshot 2025-02-04 140453" src="https://github.com/user-attachments/assets/f67f1419-0295-4afc-b9f4-91db1bf77031" />


