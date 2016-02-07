package examples;

import pcap.Convert;
import pcap.Pcap;
import pcap.Threads;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;

public class MyFing {

    public static void main(String[] args) throws IOException {
        int myCurrentInterface = 0;
        MyARP myObj = new MyARP(myCurrentInterface);

        Closeable c  = Pcap.listen(myObj.myDeviceName, new Pcap.Listener() {
            public void onPacket(byte[] bytes) {
                if(ARP.isARPreply(bytes)) {
                    String replyMAC = Convert.bytes2hex(ARP.getMacFromARPreply(bytes));
                    String replyIP = MyARP.convertByteToIP(ARP.getIpFromARPreply(bytes));

                    String macVendor = MyARP.getVendorFromBase(replyMAC);
                    System.out.println("    " + replyMAC + " -- " + replyIP + "    -- " + macVendor);
                }
            }
        });
        System.out.println("Listening...");

        Threads.sleep(1000);

        System.out.println("Sending...");
        //Is taken from anonymous/Fing.java
        byte[] myIpBytes = Convert.hex2bytes(myObj.myIpBytes);
        byte[] targetIP = myIpBytes;
        for (int i = 0; i < 3; i++) {
            targetIP[3] = (byte) i;
            myObj.sendArpRequestToIp(Convert.bytes2hex(targetIP));
        }

        //As request for my IP was gratuitous in WhireShark (without reply), here I print my device by hands
        String macVendor = MyARP.getVendorFromBase(myObj.myMacBytes);
        System.out.println("--> " + myObj.myMacBytes + " -- " +
                            myObj.getIpFromInterface(myObj.myDevice) + "    -- " + macVendor);

        Threads.sleep(5000);

        c.close();

        System.out.println("Done.");
    }
}
