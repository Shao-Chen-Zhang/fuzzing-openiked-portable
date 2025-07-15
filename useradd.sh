#!/bin/sh

# FUZZ: FreeBSD
pw groupadd _iked
pw useradd _iked -g _iked -s /sbin/nologin -d /var/empty -c 'IKEv2 Daemon'
