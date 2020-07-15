package br.com.damsete.security.ciphers;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Component
public class SecurityCipher {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    public String encrypt(String strToEncrypt) {
        if (strToEncrypt == null) {
            return null;
        }

        try {
            var iv = new byte[GCM_IV_LENGTH];
            (new SecureRandom()).nextBytes(iv);

            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            var ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), ivSpec);

            var ciphertext = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
            var encrypted = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, encrypted, 0, iv.length);
            System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new SecurityCipherException(e);
        }
    }

    public String decrypt(String strToDecrypt) {
        if (strToDecrypt == null) {
            return null;
        }

        try {
            var decoded = Base64.getDecoder().decode(strToDecrypt);
            var iv = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec ivSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), ivSpec);

            var ciphertext = cipher.doFinal(decoded, GCM_IV_LENGTH, decoded.length - GCM_IV_LENGTH);

            return new String(ciphertext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityCipherException(e);
        }
    }

    private SecretKey getSecretKey() {
        return new SecretKeySpec(new byte[16], "AES");
    }
}
