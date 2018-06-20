package com.pdfcrowd;

class Base64Utils
{
    private final static byte EQUALS_SIGN = (byte)'=';
    private final static String PREFERRED_ENCODING = "US-ASCII";

    private final static byte[] _STANDARD_ALPHABET = {
        (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
        (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
        (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
        (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
        (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
        (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
        (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
        (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5',
        (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'+', (byte)'/'
    };

    private Base64Utils() {}

    private static byte[] encode3to4(byte[] source, int srcOffset, int numSigBytes, byte[] destination, int destOffset) {
        int inBuff = ( numSigBytes > 0 ? ((source[srcOffset] << 24) >>> 8) : 0)
            | ( numSigBytes > 1 ? ((source[srcOffset + 1] << 24) >>> 16) : 0)
            | ( numSigBytes > 2 ? ((source[srcOffset + 2] << 24) >>> 24) : 0);

        switch( numSigBytes)
            {
            case 3:
                destination[destOffset] = _STANDARD_ALPHABET[(inBuff >>> 18)];
                destination[destOffset + 1] = _STANDARD_ALPHABET[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = _STANDARD_ALPHABET[(inBuff >>> 6) & 0x3f];
                destination[destOffset + 3] = _STANDARD_ALPHABET[(inBuff) & 0x3f];
                return destination;

            case 2:
                destination[destOffset] = _STANDARD_ALPHABET[(inBuff >>> 18)];
                destination[destOffset + 1] = _STANDARD_ALPHABET[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = _STANDARD_ALPHABET[(inBuff >>> 6) & 0x3f];
                destination[destOffset + 3] = EQUALS_SIGN;
                return destination;

            case 1:
                destination[destOffset] = _STANDARD_ALPHABET[(inBuff >>> 18)];
                destination[destOffset + 1] = _STANDARD_ALPHABET[(inBuff >>> 12) & 0x3f];
                destination[destOffset + 2] = EQUALS_SIGN;
                destination[destOffset + 3] = EQUALS_SIGN;
                return destination;

            default:
                return destination;
            }
    }

    public static String encodeBytes(byte[] source) {
        if( source == null){
            throw new NullPointerException( "Cannot serialize a null array.");
        }

        String encoded = null;
        try {
            encoded = encodeBytes(source, source.length);
        } catch (java.io.IOException ex) {
            assert false : ex.getMessage();
        }
        assert encoded != null;
        return encoded;
    }

    private static String encodeBytes(byte[] source, int len) throws java.io.IOException {
        byte[] encoded = encodeBytesToBytes(source, len);

        try {
            return new String( encoded, PREFERRED_ENCODING);
        }
        catch (java.io.UnsupportedEncodingException uue) {
            return new String(encoded);
        }
    }

    private static byte[] encodeBytesToBytes(byte[] source, int len) throws java.io.IOException {
        int encLen = (len / 3) * 4 + (len % 3 > 0 ? 4 : 0);
        byte[] outBuff = new byte[encLen];

        int d = 0;
        int e = 0;
        int len2 = len - 2;
        int lineLength = 0;
        for(; d < len2; d+=3, e+=4) {
            encode3to4(source, d, 3, outBuff, e);
            lineLength += 4;
        }

        if(d < len) {
            encode3to4(source, d, len - d, outBuff, e);
            e += 4;
        }

        if(e <= outBuff.length - 1) {
            byte[] finalOut = new byte[e];
            System.arraycopy(outBuff,0, finalOut,0,e);
            return finalOut;
        } else {
            return outBuff;
        }
    }
}
