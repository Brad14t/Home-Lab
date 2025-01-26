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




















































