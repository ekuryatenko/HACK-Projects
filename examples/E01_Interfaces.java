package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

public class E01_Interfaces {
    public static void main(String[] args) throws IOException {
        // Use the command bellow to see available interfaces in your OS:
        // $ ifconfig -a
        //
        // On Windows, use:
        // $ ipconfig /all

        System.out.println("Found " + Pcap.interfaces().size() + " interfaces");
        System.out.println();
/*
        for (PcapNetworkInterface dev : Pcap.interfaces()) {
            System.out.println(
                    "Name: " + dev.getName() + "\n" +
                    "IPs:  " + dev.getAddresses() + "\n" +
                    "MACs: " + dev.getLinkLayerAddresses() + "\n");
        }
*/

        /** Smaga function */
//        List<PcapNetworkInterface> devices = Pcap.interfaces();
//        List<PcapAddress> adresses = devices.get(0).getAddresses();
//        String ipMaskString = adresses.get(1).getNetmask().toString();
//        int[]ipAdressDigits = getIPdigits(ipMaskString);
//        System.out.println(ipAdressDigits[0]);

        /** To find my IP */
        PcapNetworkInterface myDevice = Pcap.interfaces().get(0);
        System.out.println(getIpFromInterface(myDevice));
        System.out.println(getMacFromInterface(myDevice));
//
//        Closeable c  = Pcap.listen(myDevice.getName(), new Pcap.Listener() {
//            public void onPacket(byte[] bytes) {
//                System.out.println("<<< " + Convert.bytes2hex(bytes));
//            }
//        });
//
//        System.err.println("Press Enter to close");
//        System.in.read(); // blocks here until user presses Enter
//
//        c.close();

    }

    public static int[] getIPdigits(String myIP) {
        int[] resultArray = new int[4];
        ArrayList<String> list = new ArrayList();
        if(myIP.charAt(0) == '/') {

            String digits = "";
            for (int i = 1; i < myIP.length(); i++) {
                if(myIP.charAt(i) != '.'){
                    digits += myIP.charAt(i);
                }else{
                    list.add(digits);
                    digits = "";
                }
            }
            list.add(digits);
        }
        int u = 0;
        for(String i: list){
            String num = list.get(u);
            resultArray[u] = Integer.parseInt(num);
            //System.out.println(resultArray[u]);
            u++;
        }
        return resultArray;
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
