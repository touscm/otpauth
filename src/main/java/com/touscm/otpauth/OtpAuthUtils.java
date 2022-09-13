package com.touscm.otpauth;

import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

/**
 * HOTP: An HMAC-Based One-Time Password Algorithm, specified in <a href="https://www.rfc-editor.org/rfc/rfc4226">RFC4226</a>
 */
public class OtpAuthUtils {
    private static final Logger logger = LoggerFactory.getLogger(OtpAuthUtils.class);

    public static final int SECRET_SIZE = 20;
    public static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
    public static final String HASH_ALGORITHM = "HmacSHA1";
    public static final long TIME_STEP_SIZE = 30000;
    public static final int KEY_MODULUS = 1000000;

    public static final String OTP_AUTH_URL = "otpauth://totp/%s?secret=%s";
    public static final String QR_SERVER_URL = "https://api.qrserver.com/v1/create-qr-code/?data=%s&size=200x200&ecc=M&margin=0";

    private static final Base32 codec;
    private static final SecureRandom random;

    static {
        codec = new Base32();
        try {
            random = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(RANDOM_NUMBER_ALGORITHM + " RNG algorithm not found", e);
        }
    }

    /**
     * 创建密钥
     *
     * @return 密钥
     */
    public static String createSecret() {
        byte[] buffer = new byte[SECRET_SIZE];
        random.nextBytes(buffer);
        return codec.encodeToString(buffer);
    }

    /**
     * 取得OTPAUTH地址
     *
     * @param name   名称
     * @param secret 密钥
     * @return OTPAUTH地址
     */
    public static String getOtpAuthUrl(@NotBlank String name, @NotBlank String secret) {
        return String.format(OTP_AUTH_URL, name, secret);
    }

    /**
     * 取得OTPAUTH二维码地址
     *
     * @param name   名称
     * @param secret 密钥
     * @return 二维码地址
     */
    public static String getOtpQrCodeUrl(@NotBlank String name, @NotBlank String secret) {
        return String.format(QR_SERVER_URL, getOtpAuthUrl(name, secret));
    }

    /**
     * 保存OTPAUTH二维码图片
     *
     * @param name     名称
     * @param secret   密钥
     * @param filePath 保存文件地址
     * @param width    图片宽度
     * @param height   图片高度
     * @return 保存结果
     */
    public static boolean saveOtpQRCodeFile(@NotBlank String name, @NotBlank String secret, @NotBlank String filePath, int width, int height) {
        return QRCodeUtils.saveQRCodeFile(getOtpAuthUrl(name, secret), filePath, width, height);
    }

    /**
     * 写OTPAUTH二维码到输出流
     *
     * @param name   名称
     * @param secret 密钥
     * @param stream 输出流
     * @param width  图片宽度
     * @param height 图片高度
     * @return 操作结果
     */
    public static boolean writeOtpQRCodeStream(@NotBlank String name, @NotBlank String secret, @NotNull OutputStream stream, int width, int height) {
        return QRCodeUtils.writeQRCodeStream(getOtpAuthUrl(name, secret), stream, width, height);
    }

    /* ...... */

    /**
     * 验证验证码
     *
     * @param secret 密钥
     * @param code   验证码
     * @return 验证结果
     */
    public static boolean validateCode(@NotBlank String secret, long code) {
        return validateCode(secret, code, new Date().getTime());
    }

    /**
     * 验证验证码
     *
     * @param secret    密钥
     * @param code      验证码
     * @param timestamp 时间戳
     * @return 验证结果
     */
    public static boolean validateCode(@NotBlank String secret, long code, long timestamp) {
        if (secret == null || secret.length() == 0) throw new IllegalArgumentException("secret is empty");
        if (code <= 0 || code >= KEY_MODULUS) return false;

        byte[] decodedKey = codec.decode(secret);
        long timeWindow = timestamp / TIME_STEP_SIZE;

        return code == calculateCode(decodedKey, timeWindow);
    }

    /* ...... */

    /**
     * Calculates the verification code of the provided key at the specified instant of time using the algorithm specified in <a href="https://www.rfc-editor.org/rfc/rfc4226">RFC6238</a>.
     *
     * @param keyData    the secret key in binary format.
     * @param timeWindow the instant of time.
     * @return the validation code for the provided key at the specified instant of time.
     */
    private static int calculateCode(byte[] keyData, long timeWindow) {
        byte[] data = new byte[8];
        long value = timeWindow;

        // Converting the instant of time from the long representation to a big-endian array of bytes (RFC4226, 5.2. Description).
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        Mac mac;
        try {
            mac = Mac.getInstance(HASH_ALGORITHM);
            mac.init(new SecretKeySpec(keyData, HASH_ALGORITHM));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            logger.error("MAC algorithm exception, {} not found", HASH_ALGORITHM, e);
            return -1;
        }

        byte[] hmacResult;
        try {
            hmacResult = mac.doFinal(data);
        } catch (IllegalStateException e) {
            logger.error("MAC operation exception", e);
            return -1;
        }

        // https://www.rfc-editor.org/rfc/rfc4226#section-5.4
        int offset = hmacResult[hmacResult.length - 1] & 0xF;
        int binCode = (hmacResult[offset] & 0x7f) << 24 | (hmacResult[offset + 1] & 0xff) << 16 | (hmacResult[offset + 2] & 0xff) << 8 | (hmacResult[offset + 3] & 0xff);

        return binCode % KEY_MODULUS;
    }
}