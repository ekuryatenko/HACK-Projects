package examples;

import org.pcap4j.core.PcapNetworkInterface;
import pcap.Pcap;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class MyARP {
    public final PcapNetworkInterface myDevice;
    public final String myDeviceName;
    public static HashMap<String, String> vendorsBase;
    public final String myIface;
    public final String myIpBytes;
    public final String myMacBytes;

    public MyARP(int currentInterface) {
        vendorsBase = getBaseFromFile("oui.txt");
        myDevice = Pcap.interfaces().get(currentInterface);
        myDeviceName = myDevice.getName();
        myIface = myDevice.getName();
        myIpBytes = Convert.bytes2hex(Pcap.get(myIface).getAddresses().get(1).getAddress().getAddress());
        myMacBytes = Convert.bytes2hex(Pcap.get(myIface).getLinkLayerAddresses().get(0).getAddress());
    }

    public static String getIpFromInterface(PcapNetworkInterface myDevice) {
        List<PcapAddress> myCompAdresses = myDevice.getAddresses();
        String result = myCompAdresses.get(1).getAddress().toString();
        return result.substring(1);
    }

    public static String getMacFromInterface(PcapNetworkInterface myDevice) {
        String result = Convert.bytes2hex(myDevice.getLinkLayerAddresses().get(0).getAddress());
        return result;
    }

    public static int[] getIPdigits(String getIPdigits) {
        int[] resultArray = new int[4];
        ArrayList<String> list = new ArrayList();
        if (getIPdigits.charAt(0) == '/') {

            String digits = "";
            for (int i = 1; i < getIPdigits.length(); i++) {
                if (getIPdigits.charAt(i) != '.') {
                    digits += getIPdigits.charAt(i);
                } else {
                    list.add(digits);
                    digits = "";
                }
            }
            list.add(digits);
        }
        int u = 0;
        for (String i : list) {
            String num = list.get(u);
            resultArray[u] = Integer.parseInt(num);
            //System.out.println(resultArray[u]);
            u++;
        }
        return resultArray;
    }

    public static HashMap<String, String> getBaseFromFile(String filename) {
        HashMap<String, String> vendorsBase = new HashMap<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            String currentLine;
            while ((currentLine = br.readLine()) != null) {
                //Find lines like "2405F5   (base 16)		Integrated Device Technology (Malaysia)"
                if (currentLine.indexOf("(base 16)", 0) > 0) {
                    Scanner scanner = new Scanner(currentLine);
                    String hexNumber = scanner.next();
                    hexNumber = hexNumber.toLowerCase();

                    scanner.next();//ommit (hex) token for (hex) cases
                    scanner.next();//ommit 16) token for (base 16) cases
                    //Read Vendor name
                    String vendorName = scanner.next();
                    while (scanner.hasNext()) {
                        vendorName += " ";
                        vendorName += scanner.next();
                    }
                    vendorsBase.put(hexNumber, vendorName);
                }
            }
            br.close();

        } catch (Exception e) {
            System.out.println("File problems exception " + e.toString());
        }
        return vendorsBase;
    }

    public static String getVendorFromBase(String macAdress) {
        macAdress = macAdress.replace(" ", "");
        macAdress = macAdress.toLowerCase();
        macAdress = macAdress.substring(0, 6);

        if (vendorsBase.containsKey(macAdress)) {
            return vendorsBase.get(macAdress);
        } else {
            return "No vendor";
        }
    }
    public void sendArpRequestToIp(String targetIp){
        String sourceMac = myMacBytes;
        String sourceIp = myIpBytes;
        String targetMac = "ff:ff:ff ff:ff:ff";

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

        //System.out.println("Sending ["+Convert.bytes2hex(packet)+"]...");

        Pcap.send(myDevice.getName(),packet);
    }

    public static String convertByteToIP(byte[] ipByte) {
        String[] ipSlice = (Convert.bytes2hex(ipByte)).split(" ");
        String result = "";
        result += Integer.parseInt(ipSlice[0], 16);
        for(int i = 1; i <= 3; i++) {
            result += ".";
            result += Integer.parseInt(ipSlice[i], 16);
        }
        return result;
    }

    public static String convertByteToIP(String ipByte) {
        String[] ipSlice = (ipByte.split(" "));
        String result = "";
        result += Integer.parseInt(ipSlice[0], 16);
        for(int i = 1; i <= 3; i++) {
            result += ".";
            result += Integer.parseInt(ipSlice[i], 16);
        }
        return result;
    }

}
