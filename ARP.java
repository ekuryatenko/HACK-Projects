package examples;

import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.util.Arrays;

public class ARP {
    public final String iface;
    public final String myIpBytes;
    public final String myMacBytes;

    public static final byte[] ARP_PROTOCOL_NUMBER = {0x08, 0x06};
    public static final byte[] ARP_OPCODE_REQUEST = {0x00, 0x01};
    public static final byte[] ARP_OPCODE_REPLY = {0x00, 0x02};

    public ARP(String _iface) {
        iface = _iface;
        myIpBytes = Convert.bytes2hex(Pcap.get(iface).getAddresses().get(1).getAddress().getAddress());
        myMacBytes = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress());
    }

    public void request (String targetIp) {
        String targetMac = "ff:ff:ff:ff:ff:ff";

        byte[] packet = Convert.hex2bytes( // ----- Ethernet
                targetMac,                 // Destination: ff:ff:ff:ff:ff:ff
                myMacBytes,                     // Source: __:__:__:__:__:__
                "08 06",                   // Type: ARP (0x0806)
                // ----- ARP
                "00 01",                   // Hardware type: Ethernet (1)
                "08 00",                   // Protocol type: IPv4 (0x0800)
                "06",                      // Hardware size: 6
                "04",                      // Protocol size: 4
                "00 01",                   // Opcode: request (1)
                myMacBytes,                     // Sender MAC address: 6 bytes
                myIpBytes,                      // Sender IP address:  4 bytes
                targetMac,                 // Target MAC address: 6 bytes
                targetIp                   // Target IP address:  4 bytes
        );

        Pcap.send(iface,packet);
        PcapNetworkInterface myInf = Pcap.get(iface);
        String myIPstring = MyARP.getIpFromInterface(myInf);
        System.out.println(myIPstring + " sended to " + targetMac);
    }

    public void request (byte[] targetIp) {
        request(Convert.bytes2hex(targetIp));
    }

    public void reply (byte[] targetMac, byte[] targetIp) {
        reply(Convert.bytes2hex(targetMac), Convert.bytes2hex(targetIp), myIpBytes);
    }

    public void reply (byte[] targetMac, byte[] targetIp, byte[] myFalseIp) {
        reply(Convert.bytes2hex(targetMac), Convert.bytes2hex(targetIp),  Convert.bytes2hex(myFalseIp));
    }

    public void reply (String targetMac, String targetIp) {
        reply(targetMac,targetIp, myIpBytes);
    }

    public void reply (String targetMac, String targetIp, String myFalseIp) {

        byte[] packet = Convert.hex2bytes( // ----- Ethernet
                targetMac,                 // Destination: ff:ff:ff:ff:ff:ff
                myMacBytes,                     // Source: __:__:__:__:__:__
                "08 06",                   // Type: ARP (0x0806)
                // ----- ARP
                "00 01",                   // Hardware type: Ethernet (1)
                "08 00",                   // Protocol type: IPv4 (0x0800)
                "06",                      // Hardware size: 6
                "04",                      // Protocol size: 4
                "00 02",                   // Opcode: reply (2)
                myMacBytes,                     // Sender MAC address: 6 bytes
                myFalseIp,                 // Sender IP address:  4 bytes
                targetMac,                 // Target MAC address: 6 bytes
                targetIp                   // Target IP address:  4 bytes
        );

        Pcap.send(iface,packet);
    }

    public static boolean isARPreply (byte[] packet) {
        // ARP packet has length of 42 bytes (this checking used for fast response on invalid packets)
        if (packet.length < 42)
            return false;

        // ARP protocol has type 0x0806
        if (!Arrays.equals(slicePacket(packet,12,13), ARP_PROTOCOL_NUMBER))
            return false;

        // ARP reply has opcode 0x0002
        if (!Arrays.equals(slicePacket(packet,20,21), ARP_OPCODE_REPLY))
            return false;

        return true;
    }

    public static byte[] slicePacket(byte[] sourcePacket, int startIndex, int endIndex) {
        byte[] slicedPacket = new byte[endIndex - startIndex + 1];
        for (int i = startIndex, j = 0; i <= endIndex; i++, j++)
            slicedPacket[j] = sourcePacket[i];
        return slicedPacket;
    }

    public static byte[] getMacFromARPreply(byte[] packet) {
        return slicePacket(packet,22,27);
    }

    public static byte[] getIpFromARPreply(byte[] packet) {
        return slicePacket(packet,28,31);
    }
}