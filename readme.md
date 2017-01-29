This is AES encryption of files while the AES password being encrypted in RSA usage is by Creating the correct KeyStore keys.

$ In Encrypt mode, a given file will be encrypted using an random AES key(IVperemeter currently isn't random) the aes-key will be encrypted via RSA using a public key of the given alias into a given configFile, a digital signature (sha256RSA) will be placed in the signature.txt path given to the program for later verification when decrypting

$ in Decrypt mode

Exampe for keystore generation - 

$keytool -genkeypair -keyalg RSA -keysize 2048 -dname "cn=first_name last_name, ou=organizational_unit, o=org, c=country" -alias keyA -keypass password -keystore keystore_a -storepass store_password_a -validity 180
$keytool -genkeypair -keyalg RSA -keysize 2048 -dname "cn=first_name last_name, ou=organizational_unit, o=org, c=country" -alias keyB -keypass password -keystore keystore_b -storepass store_password_b -validity 180

$keytool -exportcert -alias keyA -file keyA.cer -keystore keystore_a -storepass store_password_a
$keytool -exportcert -alias keyB -file keyB.cer -keystore keystore_b -storepass store_password_b

$keytool -importcert -alias keyA -file keyA.cer -keypass password -trustcacerts -keystore keystore_b -storepass store_password_a
$keytool -importcert -alias keyB -file keyB.cer -keypass password -trustcacerts -keystore keystore_a -storepass store_password_b


Usage - mode ..[args]
mode - { 0 : Encrypt-Mode, 1 : Decrypt-Mode }
$Encrypt-Mode usage : 0 file_to_encrypt(path) config_file(path) key_store_path key_store_password alias my_alias my_password signature_file_path
$Decrypt-Mode usage : 1 file_to_decrypt(path) config_file(path) key_store_path key_store_password alias alias_password other_alias signature_file_location

Usage Examples:
example encrypt -  0 etc/file_to_encrypt.txt etc/configFile.txt etc/keystore_a_path key_store_a_password keyB keyA keyA_password etc/sign.txt
example decrypt - 1 etc/file_to_decrypt.txt etc/configFile.txt etc/keystore_b_path key_store_b_password keyB keyB_password keyA etc/sign.txt decrypted.txt





