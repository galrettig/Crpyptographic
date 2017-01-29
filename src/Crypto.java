import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Random;


public class Crypto {

    private final String algorithm_used_for_aes_key_encryption = "RSA";

     Crypto() throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {

    }

    private byte[] decrypt(String algorithm, byte[] encrypted_message, Key keySpec) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher decipher;
        if(algorithm.equals(algorithm_used_for_aes_key_encryption)){
            decipher = Cipher.getInstance(algorithm_used_for_aes_key_encryption);
            decipher.init(Cipher.DECRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec("AAAAAAAAAAAAAAAA".getBytes("UTF-8"));
            decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        }

        return decipher.doFinal(encrypted_message);

    }

    private byte[] encrypt(byte[] message, Key keySpec, String algorithm ) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        if(algorithm.equals("RSA")){
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else {
            IvParameterSpec ivParameterSpec = new IvParameterSpec("AAAAAAAAAAAAAAAA".getBytes("UTF-8"));
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        }

        return cipher.doFinal(message);
    }


    byte[] make_key() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keygen.generateKey();
        byte[] aesKey = secretKey.getEncoded();
        return aesKey;

    }

     PublicKey get_public_key (String keyStore_location, char[] keyStore_password, String alias) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream fis = new FileInputStream(keyStore_location);
        keyStore.load(fis, keyStore_password);

        Certificate public_cert = keyStore.getCertificate(alias);
        PublicKey public_key = public_cert.getPublicKey();
        return public_key;
    }

     PrivateKey get_private_key(String keyStore_location, char[] keyStore_password, String alias, char[] password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream fis = new FileInputStream(keyStore_location);
        keyStore.load(fis, keyStore_password);
        return (PrivateKey)keyStore.getKey(alias, password);
    }

    private byte[] encrypt_key_rsa(byte[] message, PublicKey key) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        byte[] encrypted_key = encrypt(message, key, "RSA");
        return encrypted_key;
    }

    private byte[] decrypt_key_rsa(String config_file, PrivateKey key_spec) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] encrypted_aes_key = read_key_from_file(config_file);
        // returns a decrypted_aes_key
        return decrypt("RSA", encrypted_aes_key, key_spec);
    }

    byte[] decrypt_file(String file_location, String config_file, PrivateKey private_key) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] aes_key = decrypt_key_rsa(config_file, private_key);
        // returns a decrypted_file
        return read_file(file_location, aes_key);
    }

    void encrypt_file(String file, String config_file, byte[] encrypted_message, PublicKey public_key, PrivateKey my_private_key, String signature_file, byte[] aes_key) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, SignatureException {
        write_signature(file, my_private_key, signature_file);
        byte[] key_encrypted;
        FileOutputStream fos;


        write_file(file,encrypted_message, aes_key);

        key_encrypted = encrypt_key_rsa(aes_key, public_key);

        fos = new FileOutputStream(config_file);
        fos.write(key_encrypted);
        fos.close();
    }

    private void write_signature(String file, PrivateKey private_key, String signature_file) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        byte[] hash = sign_file(file, private_key);
        FileOutputStream sign_fos = new FileOutputStream(signature_file);
        sign_fos.write(hash);
        sign_fos.close();

    }

    private byte[] read_file(String fileLocation, byte[] key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key aes = new SecretKeySpec(key, "AES");
        File file = new File(fileLocation);
        FileInputStream fis = new FileInputStream(file);

        byte[] encrypted_text = new byte[fis.available()];

        fis.read(encrypted_text);
        fis.close();

        Cipher decrypts = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec("AAAAAAAAAAAAAAAA".getBytes("UTF-8"));
        decrypts.init(Cipher.DECRYPT_MODE, aes, ivParameterSpec);

        return decrypts.doFinal(encrypted_text);
    }


     private byte[] write_file(String file, byte[] encMessage, byte[] aesKey) throws InvalidAlgorithmParameterException, InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException {
         SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
         IvParameterSpec ivParameterSpec = new IvParameterSpec("AAAAAAAAAAAAAAAA".getBytes("UTF-8"));
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, ivParameterSpec);
         CipherOutputStream cip = new CipherOutputStream(new FileOutputStream(file), cipher);
         cip.write(encMessage);
         cip.flush();
         cip.close();
         return aesKeySpec.getEncoded();

    }

    private byte[] read_hash_from_file(String fileLocation) throws IOException {
        FileInputStream fis = new FileInputStream(fileLocation);
        byte[] hash = new byte[fis.available()];
        fis.read(hash);
        fis.close();
        return hash;
    }

     byte[] read_key_from_file(String fileLocation) throws IOException {

            FileInputStream fis = new FileInputStream(fileLocation);
            byte[] key = new byte[fis.available()];
            fis.read(key);
            fis.close();
            return key;


    }

    public boolean verify_signature(String signature_file_location, byte[] decrypted_message, PublicKey public_key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] encrypted_hash = read_hash_from_file(signature_file_location);
        byte[] message_hash = digest(new ByteArrayInputStream(decrypted_message));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(public_key);
        signature.update(message_hash);
        return signature.verify(encrypted_hash);

    }

    public byte[] sign_file (String file_to_sign, PrivateKey private_key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        FileInputStream fis = new FileInputStream(file_to_sign);
        byte[] digested = digest(fis);
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(private_key);
        sign.update(digested);
        fis.close();
        return sign.sign();
    }

    private byte[] digest (InputStream in) throws NoSuchAlgorithmException, IOException {
        byte[] bytes = new byte[1024];
        int b;
        MessageDigest message_digest = MessageDigest.getInstance("SHA-256");
        message_digest.reset();

        while((b = in.read(bytes)) != -1){
            message_digest.update(bytes, 0, b);

        }
        return message_digest.digest();

    }


    private byte[] generate_random_string(int n) {
        Random rand = new SecureRandom();
        byte[] randBytes = new byte[n];
        rand.nextBytes(randBytes);
        return randBytes;

    }



}
