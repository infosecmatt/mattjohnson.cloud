+++
authors = ["Matt Johnson"]
title = 'Kali Containerized'
date = '2021-01-13'
description = "Here's my solution to make Kali more portable, convenient, and performant."
draft = false
tags = ["security"]
summary = "Here's my solution to make Kali more portable, convenient, and performant."
+++

Before the holiday break last month, I was in the process of setting up a dropbox that would be deployed onto a client's internal network. This involved taking an ISO of a standard enterprise-grade Linux distribution, configuring the device with it, and loading in all necessary tools and dependencies as well as custom scripts. It wasn't the first time I'd done it, but for whatever reason this time I had the realization that this process was not only tedious, it was inefficient. I was spending valuable time doing tasks that could, for the most part, be automated away. I couldn't simply skip any of this either. Building from scratch is a necessity between engagements due to the fact that sensitive client data could be stored not only in expected places, but also unexpectedly in logs or other areas of the operating system with lower visibility. From there, I reasoned that there has to be a better way to approach this problem than what we'd always done. Virtual Machines were never an option in my eyes. Yes, they are easy to image, deploy, and kill; they leave no sensitive data behind once destroyed. The principal issue that I have with Virtual Machines is that when computing resources are limited and the engagement is being performed remotely, their performance is underwhelming at best and obstructive at worst. Given that, I decided to look to something not commonly used in the pentesting world: containers. Specifically, Docker. My hypothesis was that I could deploy a penetration testing dropbox once, install any necessary tools for administering the assessment (such as remote access scripts), and then deploy a preconfigured Kali image as a Docker container that would allow me to perform work for a client, save any necessary artifacts for reporting, and then delete everything else. When a container is destroyed, it takes with it all logs and other incidental information collected during the assessment. The result of this exercise is that I am now able to do in minutes what used to take hours. Below, I've outlined the vision, implementation details, and security considerations of this project.

{{< toc >}}

# Vision

In the introductory paragraph, I outlined why a Docker container would solve the specific problem of the inefficiency of our current dropbox deployment process. While that may have been the inspiration for this project and one of its main goals, I had other goals that became increasingly important as the initial goal came into shape. Specifically, I envisioned a solution that was highly performant, was capable of doing things that one would expect to be able to achieve on a GUI-based Kali machine, and, above all, secure.

Many penetration testers, have experienced the pain and frustration of trying to use a hacking OS within a virtual machine, whether that is trying to crack a password while not having the luxury of using a dedicated cracking rig, dealing with lag in the GUI, or battling against resource constraints. One of the benefits of containerization most often touted by its evangelists is the fact that you are eliminating much of the overhead associated with traditional virtualization solutions. Containers operate on the same kernel as the host OS, and consequently perform as if it were the host OS. I wanted to ensure that my solution lived up to those proclaimed benefits.

In performing various tests related to common penetration testing engagements, I determined that my solution had done so. Hashcat performance was identical in the container as it was on the host OS, and as much as 25% faster than the same tests performed within a Kali VM on VMWare Workstation. Similarly, applications such as Burpsuite were significantly smoother and faster running from within the container than those running from within the VM. Due to shared host networking, I faced no degredation of network performance. All in all, the container performs as if it were just another terminal window on the host operating system.

Another feature that I sought to have in this solution was access to GUI-based applications running from within the container. As alluded to in the previous paragraph, I was able to achieve that and can run applications such as Burpsuite without any signficant issues. Additionally, the shared host networking meant that one could access browser-based services, such as Bloodhound, from your host-based web browser. More discussion on that topic to come.

Lastly, I wanted to ensure that the container solution was equally secure as a VM-based solution. The use-case for this, whether it be for actual penetration testing or just CTF challenges, probably implies that the risk of any sort of incident is low, but for myself and many others in security it's about the principle (and the potential for edge cases). All configurations utilized in deployment scripts were done so with consideration for the security implications. The principle of least privilege was utilized, and the only interactivity that the container has with the host system is related to the display (with configuration files being read only where possible), a mounted volume for saving artifacts and keeping notes, read-only access to some configuration files (such as `~/.tmux.conf`, and the host-based networking stack. Further discussion regarding host-based networking is included later in this blog post. Generally speaking, access to the host networking stack as opposed to the default NATted network for running Docker containers is recommended for some purposes and outright required for others. An instance in which it may be recommended is [in the context of vulnerability scanning](https://docs.tenable.com/nessus/Content/DeploymentConsiderations.htm). For performing testing such as LLMNR/NBT-NS poisoning, it is absolutely required due to the need to listen for broadcast traffic.

I'm sure that over time, the vision for the project will change based on my experiences, knowledge gained, external input, and needed functionality. However, I wanted to ensure that my work was immediately useful and that the most important features were included. I feel as though I'm well on my way in that regard.

# Implementation Details

As far as implementation details are concerned, the best way I can explain is by showing the `Dockerfile` and `docker-compose` file and outlining what's going on. For those who are unfamiliar with Docker and/or Docker Compose, these files serve as the foundation on which the image and resultant containers are built. The `Dockerfile` is a set of instructions that are used in order to build a base image. The `docker-compose` file is a set of instructions that a different but related application called Docker Compose uses in order to take an image and deploy it as a container with specific runtime configurations applied. Now that we've established what these files are, let's take a look at them.

First up, the Dockerfile:

```docker
FROM kalilinux/kali-rolling:latest
#kali-linux-default is a metapackage with all tools distributed on the base kali OS
# xauth is needed for gui apps
RUN apt-get update -y && apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y kali-linux-default xauth iputils-ping gobuster python3-pip binutils
RUN cd /opt
RUN git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git /opt/PEASS
RUN git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/PayloadsAllTheThings
#this is required for Burpsuite to effectively run
RUN echo 'alias burp="java -jar /usr/bin/burpsuite --user-config-file=/pentest/config/burpsuite-user-options.json --use-defaults --config-file=/pentest/config/burpsuite-project-options.json"' >> /root/.bashrc
#support UTF encoding in tmux
RUN echo 'alias tmux="tmux -u"' >> /root/.bashrc
#hush kali login
RUN touch /root/.hushlogin
```

This file starts off by defining which base image it will build its image off of. In order to ensure that the custom container uses the most up-to-date version of Kali, it pulls from the base Kali Docker image. Worth noting that the Kali image maintained by Offensive Security is so minimal that it is borderline useless (which is what necessitated this project). Importantly, though, it has the Kali repository available by default. The first thing that's done during the build process is update the repository and upgrade any outdated default packages. After that, the `kali-linux-default` metapackage, which contains all of the most useful penetration testing tools, is installed. `Xauth`\> is installed in order to use GUI applications. `iputils-ping, python3-pip, and binutils` are installed in order to have access to common Bash commands. Lastly, `gobuster` is installed. Over time, I expect the list of apt packages to grow, but I wanted to keep it pretty minimal at this point in order to ensure that the image didn't become unnecessarily bloated.

A couple of wonderful open-source tools are also installed in the `/opt` folder. `PEASS` is a suite of scripts used for enumerating privilege escalation vectors. `PayloadsAllTheThings` is an assortment of very handy tools.

I've added a couple of aliases to the image as well. Running `burp` will start up Burpsuite using custom user and project options configured to my liking. Obviously, anyone who wants to use their own configuration files can do that as well. I added a `tmux` shortcut to automatically use UTF encoding.

The last thing I did was hush the Kali login message. If any Kali developers are out there, I'm sorry. It's just somewhat annoying to have the same message pop up each time I open a new `tmux` window. That's pretty much it for the Dockerfile. It basically just takes the base Kali image, tweaks it slightly, and installs useful tools.

Next up, the Docker Compose file:

```
version: '3.3'
services:
pentesting:
hostname: kali
environment:
- DISPLAY
volumes:
- "${XAUTHORITY}:/root/.Xauthority:ro"
- /tmp/.X11-unix
- /pentest:/pentest
- "${HOME}/.tmux.conf:/root/.tmux.conf:ro"
network_mode: host
image: infosecmatt/kali-pentesting
stdin_open: true
tty: true
```

This file is also simple. You can see that the the compose version file is 3.3. That line is there simply to tell Docker Compose how to interpret the file. I set the hostname to `kali` for aesthetic purposes. In order to get the GUI ability to work, I had to do a few things. First, I made it so that the host `DISPLAY` environment variable so that the container would inherit it. Likewise, I mounted the file location stored within the `XAUTHORITY` environment variable to `/root/.Xauthority` as read only. This gives `Xauth` on the container the necessary access key to interact with the display. Lastly, access to `/tmp/.X11-unix` gives `Xauth` access to the host sockets needed to display applications.

For mounted volumes and files, there are two worth noting. First, I mapped a folder called `~/pentest` from my host machine to the container. This is where artifacts and evidence can be stored for reporting purposes. This is the only data from the container that will continue to exist once the container is killed. The second thing worth noting is that the `.tmux.conf` file is mapped as read only. This allows me to use my preferred configurations while ensuring that it can't be modified or deleted.

The last four lines are fundamental to the operation of the container. The `network_mode` is defined as `host`. This is what tells Docker Compose to use the host-based networking stack. `image` is what tells Docker Compose to use my custom Docker image. The final two lines are what spawns a shell upon deploying the container.

Docker is graceful in its simplicity, and I ultimately want to keep it as clean as possible while still having all the functionality I need.

# Security Considerations

As with all things in IT, functionality should be carefully balanced against security. Everyone's threat model and risk tolerance will be different, but I'd like to discuss some best practices when using my penetration testing container:

```plaintext
1. Host network hardening: Given that the container shares a common networking stack with the host OS, it is critical that the host OS itself is sufficiently hardened. While it's unlikely that a malicious actor would be able to compromise the container, it is a possibility that should be accounted for. This means that there should be as few services running on the host as is necessary. On my host OS, the only running service I have that is accessible by the container is DNS.
2. Shared volumes: This probably goes without saying, but any shared volumes are a two way street. The host can read what the container writes and vice versa. The container operates within an entirely separate namespace except for what access you choose to give it.
3. Container privileges: It is possible to run containers with granular permissions. This is divergent from the typical perception that a process runs within either a privileged or unprivileged context. I have deliberately not assigned any special privileges, and thus far it has not caused any issues. I would caution against assigning privileges without fully understand the implications, as they can expose attack vectors that may compromise the security of the host image. Special attention should be paid to any permissions related to the Docker socket. With access to this socket, a user could effectively take over the host system.
4. When in doubt, build from source. You don't have to trust me, I'm just a random guy on the internet. I've made the Dockerfile and docker-compose file freely available for auditing, modification, and building from source.
5. Some useful commands related to the note above:
    - Build from source: docker build -f PATH/TO/Dockerfile
    - Start a container: docker-compose -f PATH/TO/docker-compose.yml run pentesting bash
    - Remove a container: docker-compose -f PATH/TO/docker-compose.yml rm 
```

For additional reading refer to the following sources: [\[A\]](https://docs.docker.com/network/host/) [\[B\]](https://docs.docker.com/engine/security/)