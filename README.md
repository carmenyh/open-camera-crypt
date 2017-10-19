# Open Camera Crypt

Open Camera Crypt attempts to provide strong protection for sensitive photographs taken in potentially dangerous situations.

Our system offers an improvement over the default encryption features of Android by making it impossible for anyone to decrypt the encrypted photos without using a private key stored on a separate (and hopefully more secure) computer.

Additionally, since cameras could be confiscated and reviewed by authorities, our application endeavors to hide the presence of encrypted photos on the smartphone.

This system consists of a Android smart phone, our modified version of the open camera application, a key generation program on the user’s computer, and a decryption program on the user’s computer. When pictures are taken on the camera they will be encrypted and stored in the camera’s internal storage or on SD card from which they can later be decrypted on the user’s computer. As long as the computer is secure, it is the only device able to decrypt all of the photos as only it will have the necessary cryptographic secrets.

## Running the project
To run the project, you will need to have an Android phone that can run Open Camera or emulate one on your computer.

Pull the project from gitlab and import it into Android Studio as a Gradle project.

### To run on a phone

From the Build menu select generate APK and click the bubble which will pop up to go to the location of the APK in your computer’s file system.

Transfer the APK to your phone and install it. You will have to enable developer mode and allow installation of non-Play Store applications to do this.

Run the key generation program (KeyGen) on your computer with three location/filename arguments: that of the public key for the computer, that of the private key, and that of the public key to store on the SD card. If did not do so through the third argument, transfer the public key generated to your phone.

In the OpenCamera settings, select “More camera controls…” and scroll to the “Encryption” heading.

Turn on “Encrypt photos” and select the public key file on the phone.

If desired, set the “Encrypted save location” to change the output directory for encrypted photos.

Take some pictures.

Transfer the “.encrypted” files from the encrypted save directory to your computer.

Run the decryption program (Decryptor) with three arguments: the filepath of the private key, the encrypted file to decrypt, and the output filepath.
