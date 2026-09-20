from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class DDoSTopo20(Topo):
    def build(self):
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Server
        self.addHost('h1', ip='10.0.0.1/24')

        for i in range(2, 16):
            self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')

        for i in range(16, 21):
            self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')

        self.addLink('h1', s1)

        for i in range(2, 9):
            self.addLink(f'h{i}', s1)
        for i in range(9, 16):
            self.addLink(f'h{i}', s2)

        for i in range(16, 21):
            self.addLink(f'h{i}', s3)

        # Switch links
        self.addLink(s1, s2)
        self.addLink(s2, s3)

if __name__ == '__main__':
    setLogLevel('info')
    topo = DDoSTopo20()
    net = Mininet(topo=topo,
                  controller=RemoteController('c0', ip='127.0.0.1', port=6653),
                  switch=OVSSwitch)
    net.start()
    print("*** 20-host topology started")
    CLI(net)
    net.stop()
