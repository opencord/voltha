# Voltha

## What is Voltha?

Voltha aims to provide a layer of abstraction on top of legacy and next generation access network equipment for the purpose of control and management. Its initial focus is on PON (GPON, EPON, NG PON 2), but it aims to go beyond to eventually cover other access technologies (xDSL, DOCSIS, G.FAST, dedicated Ethernet, fixed wireless).

Key concepts of Voltha:

* **Network as a Switch**: It makes a set of connected access network devices to look like a(n abstract) programmable flow device, a L2/L3/L4 switch. Examples:
    * PON as a Switch
    * PON + access backhaul as a Switch
    * xDSL service as a Switch
* **Evolution to virtualization**: It can work with a variety of (access) network technologies and devices, including legacy, fully virtualized (in the sense of separation of hardware and software), and in between. Voltha can run on a decice, on general purpose servers in the central office, or in data centers.
* **Unified OAM abstraction**: It provides unified, vendor- and technology agnostic handling of device management tasks, such as service lifecycle, device lifecycle (including discovery, upgrade), system monitoring, alarms, troubleshooting, security, etc.
* **Cloud/DevOps bridge to modernization**: It does all above while also treating the abstracted network functions as software services manageable much like other software components in the cloud, i.e., containers.

## Why Voltha?

Control and management in the access network space is a mess. Each access technology brings its own bag of protocols, and on top of that vendors have their own interpretation/extension of the same standards. Compounding the problem is that these vendor- and technology specific differences ooze way up into the centralized OSS systems of the service provider, creating a lot of inefficiencies.

Ideally, all vendor equipment for the same access technology should provide an identical interface for control and management. Moreover, there shall be much higher synergies across technologies. While we wait for vendors to unite, Voltha provides an increment to that direction, by confining the differences to the locality of access and hiding them from the upper layers of the OSS stack.


## How can you work with Voltha?

While we are still at the early phase of development, you can check out the BUILD.md file in the project's root directory to see how you can build it, run it, test it, etc.

## How can you help?

Contributions, small and large, are welcome. Minor contributions and bug fixes are always welcome in form of pull requests. For larger work, the best is to check in with the existing developers to see where help is most needed and to make sure your solution is compatible with the general philosophy of Voltha.
