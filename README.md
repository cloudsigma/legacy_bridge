# CloudSigma Legacy Bridge

**If you are starting from scratch with your integration, please do not use this tool. It's much better to integrate with the new API directly, as this script only exposes a section of the new API.**

The objective of this project is to bridge the old and the new API. Many of our early customers heavily utilized a script called `cloudsigma.sh` that enabled easy management of their resources from the command line or by integrating directly into another script.

Our new API however is very different and improved in many ways. As a programmer, you will be very pleased. Unfortunately this means that the old tool `cloudsigma.sh` won't work anymore. To help streamline the migration to the new cloud, we've created this tool. The goal was to be a drop-in replacement for `cloudsigma.sh`, but it instead interacts with the new API.

There was also a script named `cs-upload.sh` that allowed easy uploading of image files to the system. This repository also includes a port of this script.

## Installation

Before starting, you need to have Python (2.7 or later), Git and Python-pip installed. Depending on the operating system, the instructions will differ. On Ubuntu and Debian, you should be able to fulfill these requirements by running `sudo apt-get install python-pip git-core`.

    $ git clone git://github.com/cloudsigma/legacy_bridge.git
    $ cd legacy_bridge
    $ sudo pip install -r requirements.txt

With the dependencies installed, you can now run

    $ ./cloudsigma.py <your variables>

or

    $ ./cs-upload.py /path/to/file.iso

In order to fully be compatible, the repository also includes a symlink for `cloudsigma.sh` that points to `cloudsigma.py`. You could even integrate this further by adding cloudsigma.sh to your PATH.

## Usage

### Passing data from stdin

    $ echo -e "variable0 value0\nvariable1 value1" | ./cloudsigma.py -c <your variables>

### Passing data from file

    $ ./cloudsigma.py -f /path/to/file some command

### Create a drive

    $ echo -e "name test_5GB\nsize 5368709120" | ./cloudsigma.py -c drives create

### List drives

    $ ./cloudsigma.py drives list
    8f411e98-364e-4a98-bce1-0cd8b1d973ce
    7e249527-7321-4b9f-a4be-cff319fa85f2
    aab1a61a-355e-4830-81a5-a3f14b86b796
    38624cb9-2d17-4ce7-a516-023e00fad8e9

### Create a server

    $ echo -e "name Foobar\nmem 2048\ncpu 2000\nblock:0 084a3f23-01d4-4b88-9792-730082f3167c" | ./cloudsigma.py -c servers create

### Get server info

    $ ./cloudsigma.py servers 709cd785-83c6-420c-abf9-eaaf656c584e info
    status stopped
    name foobar
    mem 2048
    vnc:password 7X8Z2
    server 709cd785-83c6-420c-abf9-eaaf656c584e
    user b4b96539-ba52-4ad0-9837-a267265294b6
    cpu 2000
    ide:0:0 38624cb9-2d17-4ce7-a516-023e00fad8e9
    block:0 7e249527-7321-4b9f-a4be-cff319fa85f2
    nic:1:model virtio
    nic:1:vlan b32450ba-dd98-4bac-b799-9d2ce95a4444
    nic:1:mac 22:f9:4d:0f:8f:ee

### List servers

    $ ./cloudsigma.py servers list
    eb50c930-d25d-46e1-a85f-c3993f96c3a0
    d895aa3c-619b-4702-ae86-52035b108101
    709cd785-83c6-420c-abf9-eaaf656c584e

### Create a VLAN

Since the back-end works differently in the new API, you cannot create a VLAN the same way as you could in the old cloud, since VLANs get created automatically when you purchase them, but they have no name assigned. So what the above command does in the back-end is to look for unnamed VLANs and then assign a name to one of them.

    $ echo -e "name foobar" | ./cloudsigma.sh -c resources vlan create

If you want to re-use a VLAN that has already been created, you would need to clear the name for a given VLAN for it to be considered a 'new' VLAN and be picked up by the 'create' command.

### Get VLAN info

    $ ./cloudsigma.py resources vlan info
    type vlan
    resource 3b4545a1-85d1-4fc3-bfea-ac965efe27d5
    name foolan
    user 8941b616-ac23-4733-9139-123fefc951ad

### Uploading an image

To upload an image to your cloud infrastructure, you can use `cs-upload.py`. This will take any file as an input and upload it.

By default, all images are treated as a disk images, but you can easily change this after uploading the image under 'Properties' of the disk image (valid options are Disk and CD-ROM).

    $ ./cs-upload.py /path/to/file.img
