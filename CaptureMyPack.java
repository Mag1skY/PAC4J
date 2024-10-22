package my.game;

import com.sun.jna.Platform;
import my.cat21.Capture;
import my.cat21.Cat21Packet;
import my.cat21.Send;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Scanner;

public class CaptureMyPack {
    private static final String READ_TIMEOUT_KEY = Send.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = Send.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
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

    public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {

        if (OpenNif() == false || nif == null) {
            System.out.println("打开网络接口失败!!");
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
        }

        Scanner scanner = new Scanner(System.in);
        System.out.println("捕获类型(icmp or icmp6 or ip or tcp or udp or arp)(ether proto 0x8000)");
        String filter = scanner.nextLine();
        System.out.println("捕获帧数");
        int COUNT = scanner.nextInt();
        if (filter.length() != 0) {
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        }

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(PcapPacket packet) {
                if (!packet.contains(EthernetPacket.class)) {
                    return;
                }
                if (packet.contains(EthernetPacket.class)) {
                    System.out.println("###[MAC]###");
                    System.out.println("----------------------------------");
                    EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
                    System.out.println("源地址：");
                    System.out.println(ethernetPacket.getHeader().getSrcAddr());
                    System.out.println("目标地址：");
                    System.out.println(ethernetPacket.getHeader().getDstAddr());
                    System.out.println("类型：");
                    System.out.println(ethernetPacket.getHeader().getType());
                }
                if (packet.get(EthernetPacket.class).getHeader().getType().toString().substring(0,6).equals("0x8000")) {
                    byte[] rawData = packet.get(EthernetPacket.class).getPayload().getRawData();
                    MyPacket myPacket = null;
                    try {
                        myPacket = MyPacket.newPacket(rawData, 0, 7);
                    } catch (IllegalRawDataException e) {
                        e.printStackTrace();
                    }
                    System.out.println("###[MYPACKET]###");
                    System.out.println("----------------------------------");
                    System.out.println("cat:");
                    System.out.println(myPacket.getHeader().getCat());
                    System.out.println("length:");
                    System.out.println(myPacket.getHeader().getLength());
                    System.out.println("fspec:");
                    System.out.println(myPacket.getHeader().getFspec());
                    System.out.println("e1:");
                    System.out.println(myPacket.getHeader().gete1());
                    System.out.println("e2:");
                    System.out.println(myPacket.getHeader().gete2());
                    System.out.println("e3:");
                    System.out.println(myPacket.getHeader().gete3());
                    System.out.println("e4:");
                    System.out.println(myPacket.getHeader().gete4());
                    System.out.println("e5:");
                    System.out.println(myPacket.getHeader().gete5());
                }
                if (packet.contains(ArpPacket.class)) {
                    System.out.println("###[ARP]###");
                    System.out.println("----------------------------------");
                    ArpPacket arpPacket = packet.get(ArpPacket.class);
                    System.out.println("硬件类型:");
                    System.out.println(arpPacket.getHeader().getHardwareType());
                    System.out.println("协议类型:");
                    System.out.println(arpPacket.getHeader().getProtocolType());
                    System.out.println("硬件地址长度:");
                    System.out.println(arpPacket.getHeader().getHardwareAddrLength());
                    System.out.println("协议地址长度:");
                    System.out.println(arpPacket.getHeader().getProtocolAddrLength());
                    System.out.println("操作码:");
                    System.out.println(arpPacket.getHeader().getOperation());
                    System.out.println("源硬件地址:");
                    System.out.println(arpPacket.getHeader().getSrcHardwareAddr());
                    System.out.println("源协议地址:");
                    System.out.println(arpPacket.getHeader().getSrcProtocolAddr());
                    System.out.println("目标硬件地址:");
                    System.out.println(arpPacket.getHeader().getDstHardwareAddr());
                    System.out.println("目标协议地址:");
                    System.out.println(arpPacket.getHeader().getDstProtocolAddr());
                }
                if (packet.contains(IpV4Packet.class)) {
                    System.out.println("###[IPv4]###");
                    System.out.println("----------------------------------");
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    System.out.println("版本:");
                    System.out.println(ipV4Packet.getHeader().getVersion());
                    System.out.println("头部长度:");
                    System.out.println(ipV4Packet.getHeader().getIhl());
                    System.out.println("服务类型:");
                    System.out.println(ipV4Packet.getHeader().getTos());
                    System.out.println("总长度:");
                    System.out.println(ipV4Packet.getHeader().getTotalLength());
                    System.out.println("标识:");
                    System.out.println(ipV4Packet.getHeader().getIdentification());
                    System.out.println("标志:");
                    System.out.println("不分片标志: " + ipV4Packet.getHeader().getDontFragmentFlag());
                    System.out.println("保留标志: " + ipV4Packet.getHeader().getReservedFlag());
                    System.out.println("更多分片标志: " + ipV4Packet.getHeader().getMoreFragmentFlag());
                    System.out.println("片偏移:");
                    System.out.println(ipV4Packet.getHeader().getFragmentOffset());
                    System.out.println("生存时间(TTL):");
                    System.out.println(ipV4Packet.getHeader().getTtl());
                    System.out.println("协议:");
                    System.out.println(ipV4Packet.getHeader().getProtocol());
                    System.out.println("校验和:");
                    System.out.println(ipV4Packet.getHeader().getHeaderChecksum());
                    System.out.println("源地址:");
                    System.out.println(ipV4Packet.getHeader().getSrcAddr());
                    System.out.println("目标地址:");
                    System.out.println(ipV4Packet.getHeader().getDstAddr());
                }
                if (packet.contains(UdpPacket.class)) {
                    System.out.println("###[UDP]###");
                    System.out.println("----------------------------------");
                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    System.out.println("源端口:");
                    System.out.println(udpPacket.getHeader().getSrcPort());
                    System.out.println("目标端口:");
                    System.out.println(udpPacket.getHeader().getDstPort());
                    System.out.println("长度:");
                    System.out.println(udpPacket.getHeader().getLength());
                    System.out.println("校验和:");
                    System.out.println(udpPacket.getHeader().getChecksum()& 0xFFFF);
                }
                if (packet.contains(TcpPacket.class)) {
                    System.out.println("###[TCP]###");
                    System.out.println("----------------------------------");
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    System.out.println("源端口:");
                    System.out.println(tcpPacket.getHeader().getSrcPort());
                    System.out.println("目标端口:");
                    System.out.println(tcpPacket.getHeader().getDstPort());
                    System.out.println("序列号:");
                    System.out.println(tcpPacket.getHeader().getSequenceNumber());
                    System.out.println("确认号:");
                    System.out.println(tcpPacket.getHeader().getAcknowledgmentNumber());
                    System.out.println("数据偏移:");
                    System.out.println(tcpPacket.getHeader().getDataOffset());
                    System.out.println("保留:");
                    System.out.println(tcpPacket.getHeader().getReserved());
                    System.out.println("标志:");
                    System.out.println("紧急指针(Urg):");
                    System.out.println(tcpPacket.getHeader().getUrg());
                    System.out.println("确认(Ack):");
                    System.out.println(tcpPacket.getHeader().getAck());
                    System.out.println("推送(Psh):");
                    System.out.println(tcpPacket.getHeader().getPsh());
                    System.out.println("重置(Rst):");
                    System.out.println(tcpPacket.getHeader().getRst());
                    System.out.println("同步(Syn):");
                    System.out.println(tcpPacket.getHeader().getSyn());
                    System.out.println("结束(Fin):");
                    System.out.println(tcpPacket.getHeader().getFin());
                    System.out.println("窗口大小:");
                    System.out.println(tcpPacket.getHeader().getWindowAsInt());
                    System.out.println("校验和:");
                    System.out.println(tcpPacket.getHeader().getChecksum());
                    System.out.println("紧急指针:");
                    System.out.println(tcpPacket.getHeader().getUrgentPointerAsInt());
                }
            }
        };


        try {
            handle.loop(COUNT, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        PcapStat ps = handle.getStats();

        System.out.println("----------------------------------");
        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
            System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
        }

        // 关闭网卡
        handle.close();
    }
}
