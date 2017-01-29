import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.util.Arrays;

public class main {



    public static byte[] readFile(String fileLocation){
        try {
            File file = new File(fileLocation);
            FileInputStream fis = new FileInputStream(file);
            byte[] text = new byte[fis.available()];
            fis.read(text);
            fis.close();
            return text;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static void writeFile(byte[] buffer, String file){

        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(buffer);
            fos.close();
        } catch (Exception e) {e.printStackTrace();}
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException {
        String mode = args[0];
        Crypto crypto = new Crypto();
        byte[] aes_key = crypto.make_key();
        if(mode.equals("0")){
            encrypt(Arrays.copyOfRange(args, 1, args.length),crypto, aes_key);
        } else if (mode.equals("1")){
            decrypt(Arrays.copyOfRange(args,1,args.length),crypto);
        } else {
            System.out.println("encrypt : 0 file_to_encrypt config_file key_store_path key_store_password alias my_alias my_password signature_file_location");
            System.out.println("decrypt : 1 file_to_decrypt config_file key_store_path key_store_password alias alias_password other_alias signature_file_location output_dest");
        }
    }




    private static void encrypt(String[] args, Crypto crypto, byte[] aes_key){
        String file_to_encrypt = args[0],
                config_file = args[1],
                key_store_path = args[2],
                key_store_password = args[3],
                alias = args[4],
                my_alias = args[5],
                my_password = args[6],
                signature_file = args[7];
        try {

            byte[] message_to_encrypt = readFile(file_to_encrypt);
            PublicKey public_key = crypto.get_public_key(key_store_path, key_store_password.toCharArray(), alias);
            PrivateKey my_private_key = crypto.get_private_key(key_store_path, key_store_password.toCharArray(), my_alias, my_password.toCharArray());

            crypto.encrypt_file(file_to_encrypt, config_file, message_to_encrypt, public_key, my_private_key, signature_file, aes_key);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static void decrypt(String[] args, Crypto crypto){
        String file_to_decrypt = args[0],
                config_file = args[1],
                key_store_path = args[2],
                key_store_password = args[3],
                alias = args[4],
                alias_password = args[5],
                other_alias = args[6],
                signature_file_location = args[7],
        outFile = args[8];

        try {
            PrivateKey private_key = crypto.get_private_key(key_store_path, key_store_password.toCharArray(), alias, alias_password.toCharArray());
            PublicKey his_public_key = crypto.get_public_key(key_store_path, key_store_password.toCharArray(), other_alias);
            byte[] decrypted_file = crypto.decrypt_file(file_to_decrypt, config_file, private_key);
            boolean verify = crypto.verify_signature(signature_file_location,decrypted_file,his_public_key);
            String outputString = verify ? "File is verified." : "File isn't verified, signature isn't correct";
            System.out.println(outputString);
            if(verify){
                writeFile(decrypted_file, outFile);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



}
