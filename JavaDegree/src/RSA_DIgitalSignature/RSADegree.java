package RSA_DIgitalSignature;


import java.awt.*;
import java.io.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.imageio.ImageIO;

import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.parser.PdfReaderContentParser;
import com.itextpdf.text.pdf.parser.SimpleTextExtractionStrategy;
import com.itextpdf.text.pdf.parser.TextExtractionStrategy;
import org.apache.commons.codec.binary.Base64;


public class RSADegree {
    // 数字签名，密钥算法
    private static final String RSA_KEY_ALGORITHM = "RSA";

    // 数字签名签名/验证算法
    private static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    // RSA密钥长度
    private static final int KEY_SIZE = 1024;

    private static final String PUBLIC_KEY = "publicKey";
    private static final String PRIVATE_KEY = "privateKey";

    static String datastr = "";

    /*
     * 初始化RSA密钥对
     *
     * @return RSA密钥对
     * @throws Exception 抛出异常
     */
    public static Map<String, String> initKey() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator
                .getInstance(RSA_KEY_ALGORITHM);
        SecureRandom secrand = new SecureRandom();
        secrand.setSeed("hahaha".getBytes());// 初始化随机产生器
        keygen.initialize(KEY_SIZE, secrand); // 初始化密钥生成器
        KeyPair keys = keygen.genKeyPair();
        String pub_key = Base64.encodeBase64String(keys.getPublic().getEncoded());
        String pri_key = Base64.encodeBase64String(keys.getPrivate().getEncoded());
        Map<String, String> keyMap = new HashMap<String, String>();
        keyMap.put(PUBLIC_KEY, pub_key);
        keyMap.put(PRIVATE_KEY, pri_key);
        return keyMap;
    }

    /**
     * 得到公钥
     *
     * @param keyMap RSA密钥对
     * @return 公钥
     * @throws Exception 抛出异常
     */
    public static String getPublicKey(Map<String, String> keyMap) throws Exception {
        return keyMap.get(PUBLIC_KEY);
    }

    /**
     * 得到私钥
     *
     * @param keyMap RSA密钥对
     * @return 私钥
     * @throws Exception 抛出异常
     */
    public static String getPrivateKey(Map<String, String> keyMap) throws Exception {
        return keyMap.get(PRIVATE_KEY);
    }

    /**
     * 数字签名
     *
     * @param data    待签名数据
     * @param pri_key 私钥
     * @return 签名
     * @throws Exception 抛出异常
     */
    public static String sign(byte[] data, String pri_key) throws Exception {
        /*Sign: Takes input SK and M. Outputs σ.SK==PrivateKey*/
        // 取得私钥
        byte[] pri_key_bytes = Base64.decodeBase64(pri_key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pri_key_bytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY_ALGORITHM);
        // 生成私钥
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);//
        // 实例化Signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        // 初始化Signature
        signature.initSign(priKey);
        // 更新
        signature.update(data);

        return Base64.encodeBase64String(signature.sign());
    }

    /**
     * RSA校验数字签名
     *
     * @param data    数据
     * @param sign    签名
     * @param pub_key 公钥
     * @return 校验结果，成功为true，失败为false
     * @throws Exception 抛出异常
     */
    public boolean verify(byte[] data, byte[] sign, String pub_key) throws Exception {
        /*Verify: Takes input (M, σ, VK). Outputs 0/1. σ is signature, VK is Public Key.*/
        // 转换公钥材料
        // 实例化密钥工厂
        byte[] pub_key_bytes = Base64.decodeBase64(pub_key);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY_ALGORITHM);
        // 初始化公钥
        // 密钥材料转换
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pub_key_bytes);
        // 产生公钥
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
        // 实例化Signature
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        // 初始化Signature
        signature.initVerify(pubKey);
        // 更新
        signature.update(data);
        // 验证
        return signature.verify(sign);
    }

    /**
     * 公钥加密
     *
     * @param data    待加密数据
     * @param pub_key 公钥
     * @return 密文
     * @throws Exception 抛出异常
     */
    private static byte[] encryptByPubKey(byte[] data, byte[] pub_key) throws Exception {
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pub_key);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥加密
     *
     * @param data    待加密数据
     * @param pub_key 公钥
     * @return 密文
     * @throws Exception 抛出异常
     */
    public static String encryptByPubKey(String data, String pub_key) throws Exception {
        // 私匙加密
        byte[] pub_key_bytes = Base64.decodeBase64(pub_key);
        byte[] enSign = encryptByPubKey(data.getBytes(), pub_key_bytes);
        return Base64.encodeBase64String(enSign);
    }

    /**
     * 私钥加密
     *
     * @param data    待加密数据
     * @param pri_key 私钥
     * @return 密文
     * @throws Exception 抛出异常
     */
    private static byte[] encryptByPriKey(byte[] data, byte[] pri_key) throws Exception {
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pri_key);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥加密
     *
     * @param data    待加密数据
     * @param pri_key 私钥
     * @return 密文
     * @throws Exception 抛出异常
     */
    public static String encryptByPriKey(String data, String pri_key) throws Exception {
        // 私匙加密
        byte[] pri_key_bytes = Base64.decodeBase64(pri_key);
        byte[] enSign = encryptByPriKey(data.getBytes(), pri_key_bytes);
        return Base64.encodeBase64String(enSign);
    }

    /**
     * 公钥解密
     *
     * @param data    待解密数据
     * @param pub_key 公钥
     * @return 明文
     * @throws Exception 抛出异常
     */
    private static byte[] decryptByPubKey(byte[] data, byte[] pub_key) throws Exception {
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pub_key);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data    待解密数据
     * @param pub_key 公钥
     * @return 明文
     * @throws Exception 抛出异常
     */
    public static String decryptByPubKey(String data, String pub_key) throws Exception {
        // 公匙解密
        byte[] pub_key_bytes = Base64.decodeBase64(pub_key);
        byte[] design = decryptByPubKey(Base64.decodeBase64(data), pub_key_bytes);
        return new String(design);
    }

    /**
     * 私钥解密
     *
     * @param data    待解密数据
     * @param pri_key 私钥
     * @return 明文
     * @throws Exception 抛出异常
     */
    private static byte[] decryptByPriKey(byte[] data, byte[] pri_key) throws Exception {
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pri_key);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥解密
     *
     * @param data    待解密数据
     * @param pri_key 私钥
     * @return 明文
     * @throws Exception 抛出异常
     */
    public static String decryptByPriKey(String data, String pri_key) throws Exception {
        // 私匙解密
        byte[] pri_key_bytes = Base64.decodeBase64(pri_key);
        byte[] design = decryptByPriKey(Base64.decodeBase64(data), pri_key_bytes);
        return new String(design);
    }

    private static String readPdf(String pdfPath) {
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

    public static void pressAnyKeyToContinue(){
        System.out.println("Press Enter key to continue");
        try {
            System.in.read();
        }catch (Exception e){

        }
    }

    /**
     * @param args
     */
    @SuppressWarnings("static-access")
    public static void main(String[] args) throws Exception {

        int i0 = 1;
        RSADegree das = new RSADegree();
        Map<String, String> keyMap = new HashMap<String, String>();
        keyMap = das.initKey();


        while (i0 == 1) {
            //写明文
            Document document = new Document();
            Document document2 = new Document();
            File file = new File("/Users/vera387/Desktop/RSAMessage.pdf");
            File file2 = new File("/Users/vera387/Desktop/RSAPublicKey.pdf");
            file.createNewFile();
            file2.createNewFile();

            Scanner input = new Scanner(System.in);
            System.out.println("RSA version. Please input message(name degree)");
            datastr = input.nextLine();
            FileOutputStream fos = new FileOutputStream("/Users/vera387/Desktop/RSA.txt");
            FileOutputStream fos4 = new FileOutputStream("/Users/vera387/Desktop/RSAMessage.txt");
            GenerateDegree g = new GenerateDegree();
            Font font = new Font("微软雅黑", Font.PLAIN, 30);
            Image image = ImageIO.read(new File("/Users/vera387/Desktop/3.png"));
            fos.write(datastr.getBytes());
            fos4.write(datastr.getBytes());
            fos.close();
            fos4.close();
            System.out.println("message：" + datastr);
            System.out.println("message saved");

            //获取密钥对
            System.out.println("-------------------");
            System.out.print("Generate now? ");
            pressAnyKeyToContinue();
            String pub_key = (String) keyMap.get(PUBLIC_KEY);
            String pri_key = (String) keyMap.get(PRIVATE_KEY);
            System.out.println("public key：" + pub_key);
            System.out.println("private key：" + pri_key);
            System.out.println("public key saved");
            System.out.println("private key saved");


            // 公匙加密
            System.out.println("-------------------");
            System.out.print("Encrypt now? ");
            pressAnyKeyToContinue();
            String pubKeyStr = RSADegree.encryptByPubKey(datastr, pub_key);
            System.out.println("cipher：" + pubKeyStr);
            FileOutputStream fos1 = new FileOutputStream("/Users/vera387/Desktop/RSAUntitled.txt", true);
            FileOutputStream fos5 = new FileOutputStream("/Users/vera387/Desktop/RSAPublicKey.txt");
            fos1.write(("PublicKey\n\n" + getPublicKey(keyMap) + "\n\n").getBytes());
            fos5.write(getPublicKey(keyMap).getBytes());
            fos1.close();
            fos5.close();


            // 私匙解密
            System.out.print("Decrypt now? ");
            pressAnyKeyToContinue();
            String priKeyStr = RSADegree.decryptByPriKey(pubKeyStr, pri_key);
            System.out.println("decrypted message：" + priKeyStr);
            FileOutputStream fos2 = new FileOutputStream("/Users/vera387/Desktop/RSAPrivateKey.txt");
            fos2.write(("PrivateKey\n\n" + getPrivateKey(keyMap) + "\n\n").getBytes());//只是写入形式是字节而已，打开看会是字符的

            // 数字签名，str1是message，私钥加密message变成密文，公钥加密message变成证书
            System.out.println("-------------------");
            System.out.print("Sign now? ");
            pressAnyKeyToContinue();
            String str1 = datastr;
            String sign = RSADegree.sign(str1.getBytes(), pri_key);//私钥签名
            FileOutputStream fos3 = new FileOutputStream("/Users/vera387/Desktop/RSAUntitled.txt", true);
            FileOutputStream fos6 = new FileOutputStream("/Users/vera387/Desktop/RSASignature.txt");
            fos3.write(("Signature\n\n" + sign + "\n\n").getBytes());
            fos6.write(sign.getBytes());
            fos3.close();
            fos6.close();
            System.out.println("Signature：" + sign);
            System.out.println("Signature was written and saved");

            //PdfWrite
            PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(file));
            PdfWriter writer2 = PdfWriter.getInstance(document2, new FileOutputStream(file2));
            document.open();
            document2.open();
            document.add(new Paragraph(datastr));
            document2.add(new Paragraph(pub_key));
            document.close();
            document2.close();
            System.out.println("Automatically written to pdf");
            System.out.println();
            System.out.println("Digital degree totally saved");

            //图片证书
            System.out.println("-------------------");
            System.out.println("Do you need picture degree? 1 means need, 0 means no need");
            int i2 = input.nextInt();
            if (i2 == 1) {
                String[][] content = {{datastr, "BJUT Dean’s Office"}};
                g.generateImage("/Users/vera387/Desktop/2.png", "/Users/vera387/Desktop/RSA.png", content, image, font, 90, 150);//第二个参数是输出位置
            }//picture degrees saved

            //认证
            System.out.println("-------------------");
            System.out.println("Do you need verification? 1 means need, 0 means no need");
            int i = input.nextInt();
            boolean vflag1 = true;
            if (i == 1) {
                String pub_key2 = "";
                System.out.println("CMU officer, please select verification mode. 1 means input, 2 means read");
                int i3 = input.nextInt();
                if (i3 == 1) {
                    System.out.println("CMU officer, please enter its public key");
                    pub_key2 = input.next();
                    vflag1 = das.verify(str1.getBytes(), Base64.decodeBase64(sign), pub_key2);
                    System.out.println("verified_" + vflag1);
                } else if (i3 == 2) {
                    pub_key2 = readPdf("/Users/vera387/Desktop/RSAPublicKey.pdf");
                    vflag1 = das.verify(str1.getBytes(), Base64.decodeBase64(sign), pub_key2);
                    System.out.println("verified_" + vflag1);
                } else {
                    System.out.println("not verified");
                }

            } else {
                System.out.println("not verified");
            }

            //是否切换申请人学校
            System.out.println("-------------------");
            System.out.println("Still BJUT's applicant? 1 means BJUT, 0 means another university");
            i0 = input.nextInt();
            if (i0 == 0) {
                System.out.println("Please restart in order to get a new pair of keys");
            }

        }
    }
}
