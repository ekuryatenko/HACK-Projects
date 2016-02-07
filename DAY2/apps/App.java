package apps;

/**
 * Created by ibarakaiev on 01/17/2016.
 */

import pcap.Convert;
import pcap.Pcap;
import java.io.*;
import java.util.*;

public class App {

    final static String INTERFACE = "\\Device\\NPF_{BB4E8BB2-6309-4906-AB4F-BCB86DC0B554}"; //our working interface

    public static void main(String[] args) throws IOException, InterruptedException {
        runConsole();
    }

    public static void runConsole() throws IOException, InterruptedException {
        Thread detect = new Detect();
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("$ ");
        String command = br.readLine();

        if (command.equals("detect")) {
            detect.start(); //run thread which detects fing
        } else if (command.equals("fing")) {
            HashMap<String, String> hashMap = fing();
            System.out.println(hashMap);
        } else if (command.equals("close")) {
            detect.interrupt();
            return;
        } else {
            System.out.println("Unknown command!");
        }
        runConsole();
    }

    public static ArrayList<String> getIpFromHex(Set<String> hackers) {
        Iterator it = hackers.iterator();
        ArrayList<String> result = new ArrayList<String>();
        while (it.hasNext()) {
            String[] split = it.next().toString().split(" ");
            String temp = "";
            for (int i = 0; i < split.length; i++) {
                temp += Integer.parseInt(split[i], 16);
                if (i != split.length - 1)
                    temp += ".";
            }
            result.add(temp);
        }
        return result;
    }

    public static HashMap<String, String> fing() throws IOException {
        String sourceMac = Convert.bytes2hex(Pcap.get(INTERFACE).getLinkLayerAddresses().get(0).getAddress());
        String sourceIp  = Convert.dec2hex("192.168.43.12");
        String targetMac = "ff:ff:ff ff:ff:ff";
        String targetIp = "";
        HashMap<String, String> hashMap = new HashMap<>();

        Closeable c  = Pcap.listen(INTERFACE, (Pcap.Listener) bytes -> {
            if (bytes[12] == Convert.hex2bytes("08")[0] && bytes[13] == Convert.hex2bytes("06")[0]
                    && bytes[21] == Convert.hex2bytes("02")[0]) {
                byte[] ip = {bytes[28], bytes[29], bytes[30], bytes[31]};
                byte[] mac = {bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27]};
                String[] split = Convert.bytes2hex(ip).split(" ");
                String IP = "";
                for (int i = 0; i < split.length; i++) {
                    IP += Integer.parseInt(split[i], 16);
                    if (i != split.length - 1)
                        IP += ".";
                }
                split = Convert.bytes2hex(mac).split(" ");
                String MAC = "";
                for (int i = 0; i < split.length; i++) {
                    MAC += split[i];
                    if (i != split.length - 1)
                        MAC += ":";
                }
                hashMap.put(IP, MAC);
            }
        });

        for (int i = 0; i < 255; i++) {
            System.out.print(i + " ");
            targetIp = Convert.dec2hex("192.168.0." + i);

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
                    targetIp                // Target IP address:  4 bytes
            );

            System.out.println(Convert.bytes2hex(packet));
            Pcap.send(INTERFACE, packet);
        }

        c.close();

        return hashMap;
    }

    private static class Detect extends Thread {
        public void run() {
            while (!Thread.currentThread().isInterrupted()) {
                HashMap<String, Integer> ARP = new HashMap<>(); //all the ips who sent ARP packages and their counts
                Set<String> hacker = new HashSet<>(); //set of hackers
                ArrayList<Long> lastUnixTime = new ArrayList<>(); /*honestly it should be a long variable, but we made
                                                                    it ArrayList to prevent errors with Callback*/
                lastUnixTime.add(0L); //set "variable" to be equal to zero.

                Closeable c = Pcap.listen(INTERFACE, bytes -> {
                    long currentUnixTime = System.currentTimeMillis();
                    //check if it is ARP package and its frequency
                    if ((bytes[12] == Convert.hex2bytes("08")[0] && bytes[13] == Convert.hex2bytes("06")[0])
                            && currentUnixTime - lastUnixTime.get(0) < 100) {
                        byte[] ip = {bytes[28], bytes[29], bytes[30], bytes[31]}; //ip
                        //check if it is request
                        if (bytes[21] == Convert.hex2bytes("01")[0]) {
                            ARP.put(Convert.bytes2hex(ip), ARP.get(Convert.bytes2hex(ip)) == null ? 0 : ARP.get(Convert.bytes2hex(ip)) + 1);
                            if (ARP.get(Convert.bytes2hex(ip)) > 10) {
                                hacker.add(Convert.bytes2hex(ip));
                            }
                        }
                    }
                    lastUnixTime.set(0, currentUnixTime);
                });

                //wait for 7 seconds
                try {
                    Thread.sleep(7000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                //then close
                try {
                    c.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                ArrayList<String> result = getIpFromHex(hacker); //convert hex to decimal (i.e. to 192.168.0.1)
                if (!result.isEmpty())
                    System.out.print("\nDetected hackers: " + result + "\n$ ");
            }
        }
    }
}
