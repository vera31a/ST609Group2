package ECC_DigitalSignature;

import RSA_DIgitalSignature.GenerateDegree;
import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.parser.PdfReaderContentParser;
import com.itextpdf.text.pdf.parser.SimpleTextExtractionStrategy;
import com.itextpdf.text.pdf.parser.TextExtractionStrategy;

import javax.crypto.Cipher;
import javax.imageio.ImageIO;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Scanner;

public class ECCDegree {
    /**
     * @see org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi
     *
     */
    private final static int KEY_SIZE = 256;//bit
    private final static String SIGNATURE = "SHA256withECDSA";

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static void printProvider() {
        Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        for (Provider.Service service : provider.getServices()) {
            System.out.println(service.getType() + ": "
                    + service.getAlgorithm());
        }
    }

    public static void main(String[] args) throws Exception {

        int i0=1;
        KeyPair keyPair = getKeyPair();

        while (i0==1)
        try {
            Document document = new Document();
            Document document2 = new Document();
            File file = new File("/Users/vera387/Desktop/ECCMessage.pdf");
            File file2 = new File("/Users/vera387/Desktop/ECCPublicKey.pdf");
            file.createNewFile();
            file2.createNewFile();

            //测试文本
            Scanner input = new Scanner(System.in);
            System.out.println("ECC version. Please input message(name degree)");
            String content = input.nextLine();
            FileOutputStream fos1 = new FileOutputStream("/Users/vera387/Desktop/ECCMessage.txt");
            FileOutputStream fos2 = new FileOutputStream("/Users/vera387/Desktop/ECCPublicKey.txt");
            FileOutputStream fos3 = new FileOutputStream("/Users/vera387/Desktop/ECCPrivateKey.txt");
            FileOutputStream fos4 = new FileOutputStream("/Users/vera387/Desktop/ECCSignature.txt");
            fos1.write(content.getBytes());
            System.out.println("message:" + content);
            System.out.println("message saved");

            //生成密钥对
            System.out.println("-------------------");
            System.out.print("Generate now? ");
            pressAnyKeyToContinue();
            ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
            fos2.write(getPublicKey(keyPair).getBytes());
            fos3.write(getPrivateKey(keyPair).getBytes());
            System.out.println("[pubKey]:\n" + getPublicKey(keyPair));
            System.out.println("[priKey]:\n" + getPrivateKey(keyPair));
            System.out.println("public key saved");
            System.out.println("private key saved");

            //加密
            System.out.println("-------------------");
            System.out.print("Encrypt now? ");
            pressAnyKeyToContinue();
            byte[] cipherTxt = encrypt(content.getBytes(), pubKey);
            System.out.println("cipher:" + cipherTxt);

            //解密
            System.out.print("Decrypt now? ");
            pressAnyKeyToContinue();
            byte[] clearTxt = decrypt(cipherTxt, priKey);
            System.out.println("decrypted message:" + new String(clearTxt));

            //PdfWrite
            PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(file));
            PdfWriter writer2 = PdfWriter.getInstance(document2, new FileOutputStream(file2));
            document.open();
            document2.open();
            document.add(new Paragraph(content));
            document2.add(new Paragraph(getPublicKey(keyPair)));
            document.close();
            document2.close();

            //签名
            System.out.println("-------------------");
            System.out.print("Sign now? ");
            pressAnyKeyToContinue();
            byte[] sign = sign(content, priKey);
            fos4.write(sign);
            System.out.println("sign[" + sign.length + "]:" + sign);
            System.out.println("Signature was written and saved");
            System.out.println();
            System.out.println("Automatically written to pdf");
            System.out.println("Digital degree totally saved");

            //画图部分
            System.out.println("-------------------");
            System.out.println("Do you need picture degree? 1 means need, 0 means no need");
            int i2 = input.nextInt();
            if (i2 == 1) {
                GenerateDegree g = new GenerateDegree();
                Font font = new Font("微软雅黑", Font.PLAIN, 30);
                Image image = ImageIO.read(new File("/Users/vera387/Desktop/3.png"));
                String[][] str = {{content, "BJUT Dean’s Office"}};
                g.generateImage("/Users/vera387/Desktop/2.png", "/Users/vera387/Desktop/ECC.png", str, image, font, 90, 150);//第二个参数是输出位置
            }

            //验签
            System.out.println("-------------------");
            System.out.println("Do you need verification? 1 means need, 0 means no need");
            int i = input.nextInt();
            boolean ret = true;
            if (i == 1) {
                System.out.println("CMU officer, please select verification mode. 1 means input, 2 means read");
                int i3 = input.nextInt();
                ret = verify(content, sign, pubKey);
                System.out.println("verified_:" + ret);
            } else {
                System.out.println("not verified");
            }
            System.out.println("digital degrees saved");


            //是否切换申请人学校
            System.out.println("Still BJUT's applicant? 1 means BJUT, 0 means another university");
            i0=input.nextInt();
            if (i0==0){
                System.out.println("Please restart in order to get a new pair of keys");
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("[main]-Exception:" + e.toString());
        }

    }



    //生成秘钥对
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");//BouncyCastle
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    //获取公钥(Base64编码)
    public static String getPublicKey(KeyPair keyPair) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    //获取私钥(Base64编码)
    public static String getPrivateKey(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(bytes);
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, ECPublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(content);
    }

    /*public static String encrypt(String content, ECPublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return new String(cipher.doFinal(content.getBytes())) ;
    }*/

    //私钥解密
    public static byte[] decrypt(byte[] content, ECPrivateKey priKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return cipher.doFinal(content);
    }

    //私钥签名
    public static byte[] sign(String content, ECPrivateKey priKey) throws Exception {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(pubCert));
        Signature signature = Signature.getInstance(SIGNATURE);//"SHA256withECDSA"
        signature.initSign(priKey);
        signature.update(content.getBytes());
        return signature.sign();
    }

    //公钥验签
    public static boolean verify(String content, byte[] sign, ECPublicKey pubKey) throws Exception {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(priCert));
        Signature signature = Signature.getInstance(SIGNATURE);//"SHA256withECDSA"
        signature.initVerify(pubKey);
        signature.update(content.getBytes());
        return signature.verify(sign);
    }

    //readPdfToTxt方法
    private static String readPdfToTxt(String pdfPath) {
        PdfReader reader = null;
        StringBuffer buff = new StringBuffer();
        try {
            reader = new PdfReader(pdfPath);
            PdfReaderContentParser parser = new PdfReaderContentParser(reader);
            int num = reader.getNumberOfPages();// 获得页数
            TextExtractionStrategy strategy;
            for (int i = 1; i <= num; i++) {
                strategy = parser.processContent(i, new SimpleTextExtractionStrategy());
                buff.append(strategy.getResultantText());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return buff.toString();
    }

    //pressAnyKeyToContinue方法
    public static void pressAnyKeyToContinue(){
        System.out.println("Press Enter key to continue");
        try {
            System.in.read();
        }catch (Exception e){

        }
    }

    /**
     * 解析证书的签名算法，单独一本公钥或者私钥是无法解析的，证书的内容远不止公钥或者私钥
     */
    private static String getSigAlgName(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
        return x509Certificate.getSigAlgName();
    }
}
