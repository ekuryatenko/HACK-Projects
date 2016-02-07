package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.io.IOException;
import java.util.List;

public class E03_Send_ARP {

    public static void main(String[] args) throws IOException {

        PcapNetworkInterface myDevice = Pcap.interfaces().get(0);
        String iface = myDevice.getName();
        String myIP = getIpFromInterface(myDevice);
        // Use the command bellow to see ARP traffic (works like Wireshark):
        // $ sudo tcpdump -ennqti en0 \( arp \)

        String sourceMac = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress());
        String sourceIp  = Convert.dec2hex(myIP);
        String targetMac = "ff:ff:ff ff:ff:ff";
        String targetIp  = Convert.dec2hex(myIP);

        byte[] packet = Convert.hex2bytes( // ----- Ethernet
                targetMac,                 // Destination: ff:ff:ff:ff:ff:ff
                sourceMac,                 // Source: __:__:__:__:__:__
                "08 06",                   // Type: ARP (0x0806)
                                           // ----- ARP
                "00 01",                   // Hardware type: Ethernet (1)
                "08 00",                   // Protocol type: IPv4 (0x0800)
                "06",                      // Hardware size: 6
                "04",                      // Protocol size: 4
                "00 01",                   // Opcode: request (1)
                sourceMac,                 // Sender MAC address: 6 bytes
                sourceIp,                  // Sender IP address:  4 bytes
                targetMac,                 // Target MAC address: 6 bytes
                targetIp                   // Target IP address:  4 bytes
        );

        System.out.println("Sending [" + Convert.bytes2hex(packet) + "]...");

        Pcap.send(iface, packet);

        System.out.println("Done.");
    }


    public static String getIpFromInterface(PcapNetworkInterface myDevice){
        List<PcapAddress> myCompAdresses = myDevice.getAddresses();
        String result = myCompAdresses.get(1).getAddress().toString();
        return result.substring(1);
    }

    public static String getMacFromInterface(PcapNetworkInterface myDevice){
        String result = Convert.bytes2hex(myDevice.getLinkLayerAddresses().get(0).getAddress());
        return result;
    }
}
