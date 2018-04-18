package hmac;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

public class Hmac {
    private enum SHA {
        SHA1, SHA256, SHA512
    };

    private static final int BLOCKSIZE_SHA1 = 64;
    private static final int BLOCKSIZE_SHA256 = 64;
    private static final int BLOCKSIZE_SHA512 = 128;

    private int outputSize;
    private String output;

    private void hmacSha(byte[] chave, byte[] mensagem, SHA funcaoHash) {
        int blocksize = funcaoHash == SHA.SHA1 ? BLOCKSIZE_SHA1 : funcaoHash == SHA.SHA256 ? BLOCKSIZE_SHA256 : BLOCKSIZE_SHA512;
        String funcaoSHA = funcaoHash == SHA.SHA1 ? "SHA-1" : funcaoHash == SHA.SHA256 ? "SHA-256" : "SHA-512";

        MessageDigest crypto = null;
        try {
            crypto = MessageDigest.getInstance(funcaoSHA);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if (chave.length > blocksize) {
            chave = crypto.digest(chave);
        }

        if (chave.length < blocksize) {
            byte[] tmp = new byte[blocksize];
            System.arraycopy(chave, 0, tmp, 0, chave.length);
            chave = tmp;
        }

        byte[] okp = new byte[blocksize];
        for (int i = 0; i < blocksize; i++) {
            okp[i] = (byte) (chave[i] ^ 0x5c);
        }

        byte[] ikp = new byte[blocksize];
        for (int i = 0; i < blocksize; i++) {
            ikp[i] = (byte) (chave[i] ^ 0x36);
        }

        crypto.reset();
        byte[] p1 = crypto.digest(concatenar(ikp, mensagem));

        crypto.reset();
        byte[] p2 = crypto.digest(concatenar(okp, p1));

        outputSize = p2.length;

        output = DatatypeConverter.printHexBinary(p2);
    }

    private byte[] concatenar(byte[] esq, byte[] dir) {
        byte[] tmp = new byte[esq.length + dir.length];
        System.arraycopy(esq, 0, tmp, 0, esq.length);
        System.arraycopy(dir, 0, tmp, esq.length, dir.length);
        return tmp;
    }

    public int getOutputSize() {
        return outputSize;
    }

    public String getOutput() {
        return output;
    }

    public static void main(String[] args) {
        Hmac hmac = new Hmac();

        try {
            hmac.hmacSha("key".getBytes("UTF-8"), "The quick brown fox jumps over the lazy dog".getBytes("UTF-8"), SHA.SHA1);
            System.out.println(hmac.getOutput());

            hmac.hmacSha("key".getBytes("UTF-8"), "The quick brown fox jumps over the lazy dog".getBytes("UTF-8"), SHA.SHA256);
            System.out.println(hmac.getOutput());

            hmac.hmacSha("key".getBytes("UTF-8"), "The quick brown fox jumps over the lazy dog".getBytes("UTF-8"), SHA.SHA512);
            System.out.println(hmac.getOutput());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
