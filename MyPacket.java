package my.game;

import my.cat21.Cat21Packet;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MyPacket extends AbstractPacket {
    public static final EtherType type = new EtherType((short)0x8000, "CAT21"); // 自定义协议类型

    private final MyPacket.Header header;

    MyPacket(Builder builder) {
        if (builder == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("builder: ")
                    .append(builder);
            throw new NullPointerException(sb.toString());
        }
        builder.length=11;
        this.header = new MyPacket.Header(builder);
    }

    public static MyPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new MyPacket(rawData, offset, length);
    }

    private MyPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new Header(rawData, offset, length);
    }


    public static final class Builder extends AbstractBuilder {

        private byte cat;
        private short length;
        private int fspec;
        private int e1;
        private int e2;
        private int e3;
        private int e4;
        private int e5;

        /**
         *
         */
        public Builder() {
        }

        public Builder(MyPacket packet) {
            this.cat = packet.header.cat;


            this.length = packet.header.length;
            this.fspec = packet.header.fspec;
            this.e1=packet.header.e1;
            this.e2=packet.header.e2;
            this.e3=packet.header.e3;
            this.e4=packet.header.e4;
            this.e5=packet.header.e5;
        }

        public MyPacket.Builder cat(byte cat) {
            this.cat = cat;
            return this;
        }

        public MyPacket.Builder length(short length) {
            this.length = length;
            return this;
        }

        public MyPacket.Builder fspec(int fspec) {
            this.fspec = fspec;
            return this;
        }

        public MyPacket.Builder e1(int e1) {
            this.e1 = e1;
            return this;
        }

        public MyPacket.Builder e2(int e2) {
            this.e2 = e2;
            return this;
        }
        public MyPacket.Builder e3(int e3) {
            this.e3 = e3;
            return this;
        }
        public MyPacket.Builder e4(int e4) {
            this.e4 = e4;
            return this;
        }
        public MyPacket.Builder e5(int e5) {
            this.e5 = e5;
            return this;
        }


        @Override
        public MyPacket build() {
            return new MyPacket(this);
        }
    }

    @Override
    public Header getHeader() {
        return header;
    }

    @Override
    public Builder getBuilder() {
        return new Builder(this);
    }


    public static final class Header extends AbstractHeader {
        private static final long serialVersionUID = -3402714274558629209L;

        private static final int CAT_OFFSET = 0;
        private static final int CAT_SIZE = 1;
        private static final int LENGTH_OFFSET = CAT_OFFSET + CAT_SIZE;
        private static final int LENGTH_SIZE = 2;
        private static final int FSPEC_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
        private static final int FSPEC_SIZE = 4;
        private static final int CAT21_HEADER_SIZE = FSPEC_OFFSET + FSPEC_SIZE;

        private int[] a={0,1,2,4,4,4,4,4,4};
        private final byte cat;     // 数据类型
        private final short length; // 总长度
        private final int fspec;   // 数据字段描述
        private final int e1;
        private final int e2;
        private final int e3;
        private final int e4;
        private final int e5;

        Header(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            for(int i=1;i<9;i++){
                a[i]+=a[i-1];
            }
            this.cat = ByteArrays.getByte(rawData, a[0] + offset);
            this.length = ByteArrays.getShort(rawData, a[1] + offset);
            this.fspec = ByteArrays.getInt(rawData, a[2] + offset);
            this.e1=ByteArrays.getInt(rawData,a[3] + offset);
            this.e2=ByteArrays.getInt(rawData,a[4] + offset);
            this.e3=ByteArrays.getInt(rawData,a[5] + offset);
            this.e4=ByteArrays.getInt(rawData,a[6] + offset);
            this.e5=ByteArrays.getInt(rawData,a[7] + offset);
        }


        public Header(Builder builder) {
            this.cat = builder.cat;
            this.length = builder.length;
            this.fspec = builder.fspec;
            this.e1=builder.e1;
            this.e2=builder.e2;
            this.e3=builder.e3;
            this.e4=builder.e4;
            this.e5=builder.e5;
        }

        public byte getCat() {
            return cat;
        }

        public short getLength() {
            return length;
        }

        public int getFspec() {
            return fspec;
        }

        public int gete1() {
            return e1;
        }

        public int gete2() {
            return e2;
        }

        public int gete3() {
            return e3;
        }

        public int gete4() {
            return e4;
        }

        public int gete5() {
            return e5;
        }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(cat));
            rawFields.add(ByteArrays.toByteArray(length));
            rawFields.add(ByteArrays.toByteArray(fspec));
            rawFields.add(ByteArrays.toByteArray(e1));
            rawFields.add(ByteArrays.toByteArray(e2));
            rawFields.add(ByteArrays.toByteArray(e3));
            rawFields.add(ByteArrays.toByteArray(e4));
            rawFields.add(ByteArrays.toByteArray(e5));
            return rawFields;
        }
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder=new StringBuilder();
        stringBuilder.append("[MyPacket Header (27 bytes)]\n");
        stringBuilder.append("  cat: "+this.header.cat+"\n");
        stringBuilder.append("  length: "+this.header.length+"\n");
        stringBuilder.append("  fspec: "+this.header.fspec+"\n");
        stringBuilder.append("  e1: "+this.header.e1+"\n");
        stringBuilder.append("  e2: "+this.header.e2+"\n");
        stringBuilder.append("  e3: "+this.header.e3+"\n");
        stringBuilder.append("  e4: "+this.header.e4+"\n");
        stringBuilder.append("  e5: "+this.header.e5+"\n");
        return stringBuilder.toString();
    }
}
