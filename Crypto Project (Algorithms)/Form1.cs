using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace Crypto_Project__Algorithms_
{
    public partial class Form1 : Form
    {
        private RSACryptoServiceProvider rsa;
        private byte[] aesKey;
        private byte[] desKey;
        private byte[] TripledesKey;

        public Form1()
        {
            InitializeComponent();
            rsa = new RSACryptoServiceProvider();
            aesKey = GenerateRandomKey();
            desKey = DesGenerateRandomKey();
            TripledesKey = TripleDESGenerateRandomKey();


        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void label2_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void label2_MouseHover(object sender, EventArgs e)
        {
            label2.ForeColor = Color.Red;
        }

        private void label2_MouseLeave(object sender, EventArgs e)
        {
            label2.ForeColor= Color.MistyRose;
        }

        private void button1_Click(object sender, EventArgs e)    //---------RSA encrypt
        {
          
            textBox4.Text = textBox1.Text;
            // Convert the message to a byte array
            string message = textBox1.Text;
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // Encrypt the message using the public key
            byte[] encrypted = RSAEncrypt(messageBytes, rsa.ExportParameters(false));
            // Convert the RSA public key to a string representation
            string publicKeyString = ConvertPublicKeyToString(rsa.ExportParameters(false));

            // Display the public key in textbox5
            textBox5.Text = publicKeyString;

            // Display the encrypted message
            textBox2.Text = Convert.ToBase64String(encrypted);
        }

        // Helper method to convert RSA public key to string representation
        static string ConvertPublicKeyToString(RSAParameters publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                string publicKeyString = rsa.ToXmlString(false);
                return publicKeyString;
            }
        }
        static byte[] RSAEncrypt(byte[] data, RSAParameters publicKey)     //------------------------------RSA Encrypt function
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(data, true);
            }
        }



        private void button2_Click(object sender, EventArgs e)            //--------->RSA Decrypt button
        {


            textBox4.Text = textBox1.Text;

            // Get the encrypted message from the text box
            string encryptedMessage = textBox2.Text;

            // Convert the encrypted message from Base64 to byte array
            byte[] encryptedBytes = Convert.FromBase64String(encryptedMessage);

            // Decrypt the message using the private key
            byte[] decrypted = RSADecrypt(encryptedBytes, rsa.ExportParameters(true));

            // Display the RSA private key components
            DisplayPrivateKey(rsa.ExportParameters(true));

            // Convert the decrypted message back to a string
            string decryptedMessage = Encoding.UTF8.GetString(decrypted);

            // Display the decrypted message
            textBox3.Text = decryptedMessage;

        }
        // Display the RSA private key components in textbox6
        private void DisplayPrivateKey(RSAParameters privateKey)
        {
            string privateKeyString = "Private Key:\n\n";
            privateKeyString += $"Modulus: {Convert.ToBase64String(privateKey.Modulus)}\n";
            privateKeyString += $"Exponent: {Convert.ToBase64String(privateKey.Exponent)}\n";
            privateKeyString += $"P: {Convert.ToBase64String(privateKey.P)}\n";
            privateKeyString += $"Q: {Convert.ToBase64String(privateKey.Q)}\n";
            privateKeyString += $"DP: {Convert.ToBase64String(privateKey.DP)}\n";
            privateKeyString += $"DQ: {Convert.ToBase64String(privateKey.DQ)}\n";
            privateKeyString += $"InverseQ: {Convert.ToBase64String(privateKey.InverseQ)}\n";
            privateKeyString += $"D: {Convert.ToBase64String(privateKey.D)}";

            textBox5.Text = privateKeyString;
        }


        static byte[] RSADecrypt(byte[] data, RSAParameters privateKey)   //--------->RSA Decrypt func
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(data, true);
            }
        }

        private void button5_Click(object sender, EventArgs e)     //--------Encrypt button for AES
        {
           
            
            textBox4.Text = textBox1.Text;
            // Convert the message to a byte array
            string message = textBox1.Text;
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            

            // Encrypt the message using AES encryption
            byte[] encrypted = AESEncrypt(messageBytes, aesKey);

            // Convert the AES key to a Base64 string
            string aesKeyString = Convert.ToBase64String(aesKey);

            // Display the AES key in textBox5
            textBox5.Text = aesKeyString;   //----------------------------- Printing the key to textbox5 on GUI.


            // Display the encrypted message
            textBox2.Text = Convert.ToBase64String(encrypted);
        }
        // AES Encrypt Mechanism-------------------------------------------------------------------------------------
        static byte[] GenerateRandomKey()
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;    //--AES taking keysize
                aes.GenerateKey();
                return aes.Key;
            }
        }

        // Encrypt a byte array using AES encryption
        static byte[] AESEncrypt(byte[] data, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
        // AES Encrypt Mechanism-------------------------------------------------------------------------------------

        //----------------------------------------------AES Decryption Mechanism-------------
        private void button4_Click(object sender, EventArgs e)  //---------AES Decrypt Button
        {
            textBox4.Text = textBox1.Text;

            // Get the encrypted message from the text box
            string encryptedMessage = textBox2.Text;

            // Convert the encrypted message from Base64 to byte array
            byte[] encryptedBytes = Convert.FromBase64String(encryptedMessage);

            // Decrypt the message using AES decryption
            byte[] decryptedBytes = AESDecrypt(encryptedBytes, aesKey);


            // Convert the AES key to a Base64 string
            string aesKeyString = Convert.ToBase64String(aesKey);

            // Display the AES key in textBox5
            textBox5.Text = aesKeyString;   //----------------------------- Printing the key to textbox5 on GUI.

            // Convert the decrypted bytes to a string
            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

            // Display the decrypted message
            textBox3.Text = decryptedMessage;



        }
        // Decrypt a byte array using AES decryption
        // Decrypt a byte array using AES decryption
        static byte[] AESDecrypt(byte[] data, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[aes.IV.Length];
                Array.Copy(data, iv, iv.Length);

                byte[] encryptedData = new byte[data.Length - iv.Length];
                Array.Copy(data, iv.Length, encryptedData, 0, encryptedData.Length);

                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream(encryptedData))
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream decryptedMs = new MemoryStream())
                        {
                            cs.CopyTo(decryptedMs);
                            return decryptedMs.ToArray();
                        }
                    }
                }
            }
        }

        //----------------------------------------------AES Decryption Mechanism-------------



        //--------------------------------------------------------------------DES Mechanism ------------------->>>>>>>>>

        private void button7_Click(object sender, EventArgs e)   //----------------------------DES Encypt button
        {
           
            textBox4.Text = textBox1.Text;
            string message = textBox1.Text;

            // Convert the message to a byte array
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // Generate a new DES key
           

            // Encrypt the message using DES encryption
            byte[] encrypted = DESEncrypt(messageBytes,desKey);
            // Convert the AES key to a Base64 string
            string desKeyString = Convert.ToBase64String(desKey);

            // Display the AES key in textBox5
            textBox5.Text = desKeyString;   //----------------------------- Printing the key to textbox5 on GUI.

            // Convert the encrypted message to Base64 and display
            textBox2.Text = Convert.ToBase64String(encrypted);

        }
        // Generate a random 128-bit DES key
        // Generate a random 64-bit DES key
        static byte[] DesGenerateRandomKey()         //-------------Generating Random key of 64 bit for DES--->>
        {
            using (DES des = DES.Create())
            {
                des.KeySize = 64;          //--------------DES min keysize should be 64bits.
                des.GenerateKey();
                return des.Key;
            }
        }


        static byte[] DESEncrypt(byte[] data, byte[] key)   //---------------------------DES key generation & Encryption
        {
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;
                des.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(des.IV, 0, des.IV.Length);
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }



        private void button6_Click(object sender, EventArgs e)    //------------------DES decryption button
        {
          
            textBox4.Text = textBox1.Text;
            string encryptedMessage = textBox2.Text;

            // Convert the encrypted message from Base64 to byte array
            byte[] encryptedBytes = Convert.FromBase64String(encryptedMessage);

           

            // Decrypt the message using DES decryption
            byte[] decrypted = DESDecrypt(encryptedBytes, desKey);
            // Convert the AES key to a Base64 string
            string desKeyString = Convert.ToBase64String(desKey);

            // Display the AES key in textBox5
            textBox5.Text = desKeyString;   //----------------------------- Printing the key to textbox5 on GUI.

            // Convert the decrypted message back to a string and display
            textBox3.Text = Encoding.UTF8.GetString(decrypted);

        }
     

        static byte[] DESDecrypt(byte[] data, byte[] key)   //---------------------------DES Decryption Method
        {
            using (DES des = DES.Create())
            {
                des.Key = key;
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[des.IV.Length];
                Array.Copy(data, iv, iv.Length);

                byte[] encryptedData = new byte[data.Length - iv.Length];
                Array.Copy(data, iv.Length, encryptedData, 0, encryptedData.Length);

                des.IV = iv;

                using (MemoryStream ms = new MemoryStream(encryptedData))
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream decryptedMs = new MemoryStream())
                        {
                            cs.CopyTo(decryptedMs);
                            return decryptedMs.ToArray();
                        }
                    }
                }
            }
        }


        private void button9_Click(object sender, EventArgs e)    //--------------Triple DES encryption button
        {
            textBox4.Text = textBox1.Text;
            
            string message = textBox1.Text;

            // Convert the message to a byte array
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

          

            // Encrypt the message using Triple DES encryption
            byte[] encrypted = TripleDESEncrypt(messageBytes, TripledesKey);

            // Convert the AES key to a Base64 string
            string TripledesKeyString = Convert.ToBase64String(TripledesKey);

            // Display the AES key in textBox5
            textBox5.Text = TripledesKeyString;   //----------------------------- Printing the key to textbox5 on GUI.

            // Convert the encrypted message to Base64 and display
            textBox2.Text = Convert.ToBase64String(encrypted);

        }

        private void button8_Click(object sender, EventArgs e) //--------------Triple decryption button
        {
                    
            textBox4.Text = textBox1.Text;
           
            // Get the encrypted message from the text box
            string encryptedMessage = textBox2.Text;

            // Convert the encrypted message from Base64 to byte array
            byte[] encryptedBytes = Convert.FromBase64String(encryptedMessage);


            // Decrypt the message using Triple DES decryption
            byte[] decrypted = TripleDESDecrypt(encryptedBytes, TripledesKey);

            // Convert the AES key to a Base64 string
            string TripledesKeyString = Convert.ToBase64String(TripledesKey);

            // Display the AES key in textBox5
            textBox5.Text = TripledesKeyString;   //----------------------------- Printing the key to textbox5 on GUI.

            // Convert the decrypted message back to a string
            string decryptedMessage = Encoding.UTF8.GetString(decrypted);

            // Display the decrypted message
            textBox3.Text = decryptedMessage;

        }

        //------------------------------------------------------------TRIPLE DES-------------->>>>>>>>>>>>>>>
        static byte[] TripleDESEncrypt(byte[] data, byte[] key)   //-------Triple D encrypt method
        {
            using (TripleDES tripleDES = TripleDES.Create())
            {
                tripleDES.Key = key;
                tripleDES.Mode = CipherMode.CBC;
                tripleDES.Padding = PaddingMode.PKCS7;
                tripleDES.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(tripleDES.IV, 0, tripleDES.IV.Length);
                    using (CryptoStream cs = new CryptoStream(ms, tripleDES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }


        static byte[] TripleDESDecrypt(byte[] data, byte[] key)
        {
            using (TripleDES tripleDES = TripleDES.Create())
            {
                tripleDES.Key = key;
                tripleDES.Mode = CipherMode.CBC;
                tripleDES.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[tripleDES.IV.Length];
                Array.Copy(data, iv, iv.Length);

                byte[] encryptedData = new byte[data.Length - iv.Length];
                Array.Copy(data, iv.Length, encryptedData, 0, encryptedData.Length);

                tripleDES.IV = iv;

                using (MemoryStream ms = new MemoryStream(encryptedData))
                {
                    using (CryptoStream cs = new CryptoStream(ms, tripleDES.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream decryptedMs = new MemoryStream())
                        {
                            cs.CopyTo(decryptedMs);
                            return decryptedMs.ToArray();
                        }
                    }
                }
            }
        }






        // Generate a random 192-bit Triple DES key
        static byte[] TripleDESGenerateRandomKey()
        {
            using (TripleDES tripleDES = TripleDES.Create())
            {
                tripleDES.KeySize = 192;    //-----------------------Keysize for triple DES - 192
                tripleDES.GenerateKey();
                return tripleDES.Key;
            }
        }

        private void button10_Click(object sender, EventArgs e)
        {
            textBox5.Clear();
            textBox2.Clear();
            textBox3.Clear();
            textBox4.Clear();
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {

        }
    }
}