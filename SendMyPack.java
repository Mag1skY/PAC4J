package my.game;

import my.cat21.Cat21Packet;
import my.cat21.Send;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SendMyPack {

    private static final String READ_TIMEOUT_KEY = Send.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = Send.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    // 源 MAC地址为本机活跃网卡的MAC地址, 格式为: "-" 或 ":" 分隔开
    // D0-C6-37-3E-7A-fB, d0-c6-37-3e-7a-fb, d0:c6:37:3e:7a:fb 均可, 不区分大小写
    private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("70-32-17-D4-9A-27");
    private static final EtherType type = new EtherType((short) 0x8000, "CAT21"); // 自定义协议类型

    private SendMyPack() {
    }

    private static PcapNetworkInterface nif;

    public static Boolean OpenNif() {
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static String strSrcMacAddress;
    public static String strDstMacAddress;

    public static String strSrcIpAddress;
    public static String strDstIpAddress;

    public static String strSrcPort;
    public static String strDstPort;

    public static EthernetPacket.Builder MAC_BUILD() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("MAC协议构建:");
//        strSrcMacAddress="FF:FF:FF:FF:FF:FF";
//        strDstMacAddress ="FF:FF:FF:FF:FF:FF";
        System.out.println("请输入源MAC地址(70-32-17-D4-9A-27)");
        strSrcMacAddress = scanner.nextLine();
        System.out.println("请输入目的MAC地址(FF:FF:FF:FF:FF:FF)");
        strDstMacAddress = scanner.nextLine();
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(MacAddress.getByName(strDstMacAddress))
                .srcAddr(MacAddress.getByName(strSrcMacAddress))
                .type(type)
                .paddingAtBuild(true);
        return etherBuilder;

    }

    public static IpV4Packet.Builder IP_BUILD() throws UnknownHostException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("IP协议构建:");
//        strSrcIpAddress="255.255.255.255";
//        strDstIpAddress="255.255.255.255";
        System.out.println("请输入源IP地址(10.11.35.53)");
        strSrcIpAddress = scanner.nextLine();
        System.out.println("请输入目的IP地址(255.255.255.255)");
        strDstIpAddress = scanner.nextLine();
        IpV4Packet.Builder ipv4Builder = new IpV4Packet.Builder();
        ipv4Builder
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 100)
                .protocol(IpNumber.ICMPV4)
                .srcAddr((Inet4Address) InetAddress.getByName(strSrcIpAddress))
                .dstAddr((Inet4Address) InetAddress.getByName(strDstIpAddress))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
        ;
        return ipv4Builder;
    }

    public static ArpPacket.Builder ARP_BUILD() throws UnknownHostException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("ARP协议构建:");
//        strSrcMacAddress="00:ff:cc:29:4c:f2";
//        strDstMacAddress ="FF:FF:FF:FF:FF:FF";
//        strSrcIpAddress="10.8.76.157";
//        strDstIpAddress="255.255.255.255";
        System.out.println("请输入源IP地址(10.11.35.53)");
        strSrcIpAddress = scanner.nextLine();
        System.out.println("请输入目的IP地址(255.255.255.255)");
        strDstIpAddress = scanner.nextLine();
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .operation(ArpOperation.REQUEST)
                .protocolType(EtherType.IPV4)
                .hardwareType(ArpHardwareType.ETHERNET)
                .hardwareAddrLength((byte) 6)
                .protocolAddrLength((byte) 4)
                .srcProtocolAddr(InetAddress.getByName(strSrcIpAddress))
                .dstProtocolAddr(InetAddress.getByName(strDstIpAddress))
                .srcHardwareAddr(MacAddress.getByName(strSrcMacAddress))
                .dstHardwareAddr(MacAddress.getByName(strDstMacAddress))

        ;
        return arpBuilder;
    }

    public static UdpPacket.Builder UDP_BUILD() throws UnknownHostException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("UDP协议构建:");
//        strSrcPort="12344";
//        strDstPort="5678";
        System.out.println("请输入源端口(12344)");
        strSrcPort = scanner.nextLine();
        System.out.println("请输入目的端口(5678)");
        strDstPort = scanner.nextLine();
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .srcPort(new UdpPort(Short.valueOf(strSrcPort), "SRC"))
                .dstPort(new UdpPort(Short.valueOf(strDstPort), "DST"))
                .srcAddr(InetAddress.getByName(strSrcIpAddress))
                .dstAddr(InetAddress.getByName(strDstIpAddress))
                .correctLengthAtBuild(true)
                .correctChecksumAtBuild(true);
        return udpBuilder;
    }

    public static TcpPacket.Builder TCP_BUILD() throws UnknownHostException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("TCP协议构建:");
//        strSrcPort="12344";
//        strDstPort="5678";
        System.out.println("请输入源端口(12344)");
        strSrcPort = scanner.nextLine();
        System.out.println("请输入目的端口(5678)");
        strDstPort = scanner.nextLine();
        System.out.println("请输入序号(12)");
        int sequenceNumber = scanner.nextInt();
        System.out.println("请输入确认序号(12)");
        int acknowledgmentNumber = scanner.nextInt();
        System.out.println("请输入标识URG(0/1)");
        int urg = scanner.nextInt();
        System.out.println("请输入标识ACK(0/1)");
        int ack = scanner.nextInt();
        System.out.println("请输入标识PSH(0/1)");
        int psh = scanner.nextInt();
        System.out.println("请输入标识RST(0/1)");
        int rst = scanner.nextInt();
        System.out.println("请输入标识SYN(0/1)");
        int syn = scanner.nextInt();
        System.out.println("请输入标识FIN(0/1)");
        int fin = scanner.nextInt();
        System.out.println("请输入窗口大小(1000)");
        int window = scanner.nextInt();
        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
        tcpBuilder
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .srcPort(new TcpPort(Short.valueOf(strSrcPort), "SRC"))
                .dstPort(new TcpPort(Short.valueOf(strDstPort), "DST"))
                .srcAddr(InetAddress.getByName(strSrcIpAddress))
                .dstAddr(InetAddress.getByName(strDstIpAddress))
                .window((short) window)
                .sequenceNumber(sequenceNumber)
                .acknowledgmentNumber(acknowledgmentNumber)
                .urg(urg == 1)
                .ack(ack == 1)
                .psh(psh == 1)
                .rst(rst == 1)
                .syn(syn == 1)
                .fin(fin == 1);
        return tcpBuilder;
    }

    public static MyPacket.Builder  MY_BUILD() throws UnknownHostException{
        Scanner scanner = new Scanner(System.in);
        System.out.println("MyPacket协议构建:");
        System.out.println("请输入cat(1)");
        byte cat = scanner.nextByte();
        System.out.println("请输入length(2)");
        short length = scanner.nextShort();
        System.out.println("请输入fspec(3)");
        int fspec = scanner.nextInt();
        System.out.println("请输入e1(3)");
        int e1 = scanner.nextInt();
        System.out.println("请输入e2(3)");
        int e2 = scanner.nextInt();
        System.out.println("请输入e3(3)");
        int e3 = scanner.nextInt();
        System.out.println("请输入e4(3)");
        int e4 = scanner.nextInt();
        System.out.println("请输入e5(3)");
        int e5 = scanner.nextInt();
        MyPacket.Builder myBuilder=new MyPacket.Builder();
        myBuilder
                .fspec(fspec)
                .cat(cat)
                .length(length)
                .e1(e1)
                .e2(e2)
                .e3(e3)
                .e4(e4)
                .e5(e5);
        return myBuilder;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
        if (OpenNif() == false || nif == null) {
            System.out.println("打开网络接口失败!!");
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        PcapHandle sendHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        try {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            }

            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.println("1.MAC 2.ARP 3.IP 4.UDP 5.TCP 6.自定义协议CAT(0.退出)");

                int operators = scanner.nextInt();
                if(operators==0){
                    break;
                }
                EthernetPacket.Builder etherBuilder = MAC_BUILD();
                if (operators == 1) {

                } else if (operators == 2) {
                    ArpPacket.Builder arpBuilder = ARP_BUILD();
                    etherBuilder
                            .type(EtherType.ARP)
                            .payloadBuilder(arpBuilder);
                } else if (operators == 3) {
                    IpV4Packet.Builder ipv4Builder = IP_BUILD();
                    etherBuilder
                            .type(EtherType.IPV4)
                            .payloadBuilder(ipv4Builder);
                } else if (operators == 4) {
                    IpV4Packet.Builder ipv4Builder = IP_BUILD();
                    UdpPacket.Builder udpBuilder = UDP_BUILD();
                    ipv4Builder
                            .protocol(IpNumber.UDP)
                            .payloadBuilder(udpBuilder);
                    etherBuilder
                            .type(EtherType.IPV4)
                            .payloadBuilder(ipv4Builder);
                } else if (operators == 5) {
                    IpV4Packet.Builder ipv4Builder = IP_BUILD();
                    TcpPacket.Builder tcpBuilder = TCP_BUILD();
                    ipv4Builder
                            .protocol(IpNumber.TCP)
                            .payloadBuilder(tcpBuilder);
                    etherBuilder
                            .type(EtherType.IPV4)
                            .payloadBuilder(ipv4Builder);
                }else if(operators==6){
                    MyPacket.Builder myBuilder=MY_BUILD();
                    etherBuilder
                            .type(MyPacket.type)
                            .payloadBuilder(myBuilder);
                }
                System.out.println("请输出发送次数:");
                int COUNT = scanner.nextInt();

                for (int i = 0; i < COUNT; i++) {
                    Packet p = etherBuilder.build();
                    System.out.println(p);
                    sendHandle.sendPacket(p);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }// 最后, 回收资源
            }
        } finally {
            if (sendHandle != null && sendHandle.isOpen()) {
                sendHandle.close();
            }
        }
    }
}
