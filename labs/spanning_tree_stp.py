#!/usr/bin/env python

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel

if '__main__' == __name__:
    setLogLevel('info')  # Set log level for debugging

    # Create Mininet instance
    net = Mininet(switch=OVSKernelSwitch, autoSetMacs=True)

    # Add switches
    s1 = net.addSwitch('s1', stp=True, failMode='standalone')
    s2 = net.addSwitch('s2', stp=True, failMode='standalone')
    s3 = net.addSwitch('s3', stp=True, failMode='standalone')

    # Add hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')

    # Add links between hosts and switches
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(h3, s3)

    # Add links between switches (triangle topology)
    net.addLink(s1, s2)
    net.addLink(s3, s1)
    net.addLink(s2, s3)

    # Build the network
    net.build()

    # Start the switches in standalone mode (legacy mode)
    s1.start([])
    s2.start([])
    s3.start([])

    # Launch CLI
    CLI(net)

    # Stop the network
    net.stop()
