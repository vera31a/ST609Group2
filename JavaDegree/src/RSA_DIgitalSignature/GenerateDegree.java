package RSA_DIgitalSignature;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class GenerateDegree {

//    Log log = LogFactory.getLog(GenerateDynamicHealthImage.class);

    /**
     * 生成图片方法
     * @author WQ
     * @param inPath
     * @param outPath
     * @param content
     * @param img
     * @param font
     * @param start_point_x
     * @param start_point_y
     */
    public void generateImage(String inPath, String outPath,
                              String[][] content, Image img, Font font, int start_point_x,
                              int start_point_y) {
        try {
            File file = new File(inPath);
            Image image = ImageIO.read(file);
            int height = image.getHeight(null);
            int width = image.getWidth(null);
            int text_x = 0;
            int text_y = 0;
            int img_x = 0;
            int img_y = 520;
            int line_y = 498;
            Color color = new Color(89, 89, 89);
            BufferedImage bufferedImage = new BufferedImage(width, height,
                    BufferedImage.TYPE_INT_RGB);
            Graphics2D graphics = bufferedImage.createGraphics();
            //文字去锯齿
            graphics.drawImage(image, 0, 0, width, height, null);
            graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON);
            graphics.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL,
                    RenderingHints.VALUE_STROKE_NORMALIZE);
            graphics.setRenderingHint(RenderingHints.KEY_RENDERING,
                    RenderingHints.VALUE_RENDER_QUALITY);
            if (img != null) {
                graphics.setFont(font);
                text_x = start_point_x;
                text_y = start_point_y;
                for (int i = 0; i < content.length; i++) {
                    String[] tempData = content[i];
                    color = new Color(89, 89, 89);
                    text_x = start_point_x;
                    if (i == 1){
                        text_y += 110;
                        img_y += 140;
                    } else if (i != 0 && i > 1){
                        text_y += 100;
                        img_y += 130;
                    }
                    line_y += 132;
                    for (int j = 0; j < tempData.length; j++) {
                        if (j == 1) {
                            text_y += 50;
                            color = new Color(171, 171, 171);
                            graphics.drawLine(12, line_y, 750 - 12, line_y);
                        } else if (j == 2) {
                            text_x = width - 124;
                            text_y -= 20;
                            img_x = 50;
                            if (tempData[2].equals("过高")){
                                color = new Color(255, 80, 80);
                            } else {
                                color = new Color(71, 207, 162);
                            }
                            graphics.drawImage(img, img_x, img_y, null);
                        }
                        graphics.setColor(color);
                        graphics.drawString(tempData[j], text_x, text_y);
                    }
                }

            } else {
                System.out.println("构建数据的图片对象为空...");
            }
            FileOutputStream fileOutputStream = new FileOutputStream(outPath);
            ImageIO.write(bufferedImage, "png", fileOutputStream);
            System.out.println("picture degree saved\n");
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (IOException e) {
//            log.info("io exception :" + e);
        }
    }

    public static void main(String[] args) {
        Font font = new Font("微软雅黑", Font.PLAIN, 30);
        String inPath = "";
        String outPath = "/Users/vera387/Desktop/2.png";
		/*String inPath = "D:/TestGenerateImage/DynamicImage/Test.jpg";
		String outPath = "D:/TestGenerateImage/DynamicImage/Test1.jpg";*/
        String [][]textContent = {{RSADegree.datastr,"\n"}};
        int x = 150;
        int y = 540;
        try {
            new GenerateDegree().generateImage(inPath, outPath,
                    textContent, ImageIO.read(new File(
                            "/Users/vera387/Desktop/1.png")), font, x, y);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}