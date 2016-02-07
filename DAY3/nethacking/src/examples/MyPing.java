package examples;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import pcap.Convert;
import pcap.IO;
import pcap.Pcap;
import pcap.Threads;

import java.io.Closeable;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class MyPing {
    public static final String ICMP_REPLY = "00 00";

    public static void main(String[] args) throws UnknownHostException {
        int myCurrentInterface = 0;
        MyARP myObj = new MyARP(myCurrentInterface);
        String myIface = myObj.myIface;
        String myIP = MyARP.convertByteToIP(myObj.myIpBytes);
        String myMAC = myObj.myMacBytes;

//        System.out.println("myIface: " + myIface + ",  myIP: " +  myIP);
//        System.out.println("myMAC: " + myObj.myMacBytes);
//        System.out.println("====================================");

        /** My request params */
        String myRequestTargetIP = "8.8.8.8";//Google
        int myRequestTTL = 128;
        //String myRequestTargetIP = "91.198.174.192";//ru.wikipedia.org
        byte[] sourceMac = Convert.hex2bytes(myMAC);
        byte[] sourceIp = Convert.dec2bytes("192.168.1.101");
        //byte[] targetMac = Convert.hex2bytes("08 81 f4 88 4b b0");//Juniper Networks
        byte[] targetMac = Convert.hex2bytes("00 50 56 c0 00 02");//VMware, Inc.
        byte[] targetIp = Convert.dec2bytes(myRequestTargetIP);
        byte[] payload = Convert.hex2bytes("61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75:76:77:61:62:63:64:65:66:67");

        System.out.println(payload.length);
        /** Main Ethernet packet building */
        // taken from https://github.com/kaitoy/pcap4j/blob/master/pcap4j-sample/src/main/java/org/pcap4j/sample/SendFragmentedEcho.java

        /** ICMP packet payload building */
        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder()
                .identifier((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload));

        /** ICMP packet building */
        IcmpV4CommonPacket.Builder icmpBuilder = new IcmpV4CommonPacket.Builder()
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .correctChecksumAtBuild(true)
                .payloadBuilder(echoBuilder);

        /** IP packet building */
        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) myRequestTTL)
                .protocol(IpNumber.ICMPV4)
                .srcAddr((Inet4Address) InetAddress.getByAddress(sourceIp))
                .dstAddr((Inet4Address) InetAddress.getByAddress(targetIp))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(icmpBuilder);

        /** Ethernet packet building */
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(MacAddress.getByAddress(targetMac))
                .srcAddr(MacAddress.getByAddress(sourceMac))
                .type(EtherType.IPV4)
                .paddingAtBuild(true)
                .payloadBuilder(ipBuilder);

        /** Listener running */
        Closeable c = null;
        try {
            c = Pcap.listen(myIface, "icmp", false, bytes -> {
                /** recived ICMP packets processing */
                String packetType = Convert.bytes2hex(getIcmpType(bytes));
                String packetSourceIp = MyARP.convertByteToIP(Convert.bytes2hex(getSourceIp(bytes)));
                String packetTargetIp = MyARP.convertByteToIP(Convert.bytes2hex(getDestinationIp(bytes)));
                String packetTTL = (Convert.bytes2hex(getPacketTTL(bytes)));
                int intPacketTTL = Integer.parseInt(packetTTL, 16);
                String packetPayload = (Convert.bytes2hex(getIcmpPayload(bytes)));
                int payloadSize = getIcmpPayload(bytes).length;


                /** If it's reply on my request */
                if((packetType.equals(ICMP_REPLY))
                    && (packetTargetIp.equals(myIP)
                    && (packetSourceIp.equals(myRequestTargetIP)))) {
                        System.out.println("    Reply from IP: " + packetSourceIp
                                            + ", TTL:" + intPacketTTL
                                            + ", Ping bytes qty recieved: " +  payloadSize);
                }
                // TODO parse packet: find time + bytes quantity in reply
                // TODO make statistics - check if whole payload is replyed
                // TODO make time statistics
                // TODO find strange device on my pcap file



            });


            /** Start of exchange sending */
            for (int i = 0; i < 5; i++) {
                echoBuilder.sequenceNumber((short) i);
                ipBuilder.identification((short) i);

                System.out.println("Sending " + i + "...");

                Pcap.send(myIface, etherBuilder.build().getRawData());

                /** Sleep to get reply */
                Threads.sleep(5000);
            }
        } finally {
            IO.close(c);
        }

    }

    public static byte[] slicePacket(byte[] sourcePacket, int startIndex, int endIndex) {
        byte[] slicedPacket = new byte[endIndex - startIndex + 1];
        for (int i = startIndex, j = 0; i <= endIndex; i++, j++)
            slicedPacket[j] = sourcePacket[i];
        return slicedPacket;
    }

    public static byte[] getIcmpType(byte[] packet) {
        return slicePacket(packet,34, 35);
    }

    public static byte[] getSourceIp(byte[] packet) {
        return slicePacket(packet,26, 29);
    }

    public static byte[] getDestinationIp(byte[] packet) {
        return slicePacket(packet,30, 33);
    }

    public static byte[] getPacketTTL(byte[] packet) {
        return slicePacket(packet,22, 22);
    }

    public static byte[] getIcmpPayload(byte[] packet) {
        int length = packet.length;
        return slicePacket(packet,42, (length - 1));
    }

}
