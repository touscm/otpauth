package com.touscm.otpauth;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

public class QRCodeUtils {
    private static final Logger logger = LoggerFactory.getLogger(QRCodeUtils.class);

    private static final int BLACK = 0xFF000000;
    private static final int WHITE = 0xFFFFFFFF;

    public static final String QRCODE_IMAGE_FORMAT = "png";

    /**
     * 保存二维码文件
     *
     * @param text     二维码内容
     * @param filePath 保存地址
     * @param width    图片宽度
     * @param height   图片高度
     * @return 保存结果
     */
    public static boolean saveQRCodeFile(@NotBlank String text, @NotBlank String filePath, int width, int height) {
        if (text == null || text.length() == 0) throw new IllegalArgumentException("QR code text can't be empty");
        if (filePath == null || filePath.length() == 0) throw new IllegalArgumentException("QR code file path can't be empty");

        Map<EncodeHintType, String> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

        BitMatrix bitMatrix;
        try {
            bitMatrix = new MultiFormatWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints);
        } catch (WriterException e) {
            logger.error("encode text with exception", e);
            return false;
        }

        File file = new File(filePath);
        if (file.exists()) {
            logger.error("QR code file is exist, path:{}", file.getAbsolutePath());
            return false;
        }

        try {
            return writeFile(bitMatrix, file);
        } catch (IOException e) {
            logger.error("save QR code file with exception, path:{}", file.getAbsolutePath(), e);
            return false;
        }
    }

    /**
     * 写二维码到输出流
     *
     * @param text   二维码内容
     * @param stream 输出流
     * @param width  图片宽度
     * @param height 图片高度
     * @return 处理结果
     */
    public static boolean writeQRCodeStream(@NotBlank String text, @NotNull OutputStream stream, int width, int height) {
        if (text == null || text.length() == 0) throw new IllegalArgumentException("QR code text can't be empty");
        if (stream == null) throw new IllegalArgumentException("QR code OutputStream can't be null");

        Map<EncodeHintType, String> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

        BitMatrix bitMatrix;
        try {
            bitMatrix = new MultiFormatWriter().encode(text, BarcodeFormat.QR_CODE, width, height, hints);
        } catch (WriterException e) {
            logger.error("encode text with exception", e);
            return false;
        }

        try {
            return writeStream(bitMatrix, stream);
        } catch (IOException e) {
            logger.error("write QR code stream with exception", e);
            return false;
        }
    }

    /* ...... */

    private static BufferedImage toBufferedImage(BitMatrix matrix) {
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                image.setRGB(x, y, matrix.get(x, y) ? BLACK : WHITE);
            }
        }
        return image;
    }

    private static boolean writeFile(BitMatrix matrix, File file) throws IOException {
        BufferedImage image = toBufferedImage(matrix);
        return ImageIO.write(image, QRCODE_IMAGE_FORMAT, file);
    }

    private static boolean writeStream(BitMatrix matrix, OutputStream stream) throws IOException {
        BufferedImage image = toBufferedImage(matrix);
        return ImageIO.write(image, QRCODE_IMAGE_FORMAT, stream);
    }
}
